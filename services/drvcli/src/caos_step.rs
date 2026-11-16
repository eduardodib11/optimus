//! Queda do `storaged` no meio de uma escrita (T-541): numa partição `caos`
//! o `drvcli` grava commits sem parar; o `svcmgr` mata o `storaged` num
//! ponto do boot (`svcmgr.mata`). O cliente vê o `BlockStore` morto
//! (`PeerClosed`), reconecta ao `storaged` que o `svcmgr` reiniciou, reabre a
//! fila, remonta o volume e confere que nenhum commit confirmado se perdeu.
//!
//! Dois outros cenários usam a mesma partição (ADR 0072): o `svcmgr` mata o
//! driver de bloco (o `storaged` conclui com `Reset`, reconecta ao driver
//! novo e o cliente remonta e confere o mesmo) ou mata o próprio `drvcli`
//! (o `storaged` tem de soltar as filas do cliente morto assim que o novo
//! abre uma sessão; ver [`morto`]).

use super::crash_step::{FILE_LEN, KEY, UUID, pattern};
use super::optfs_step::{QueueIo, Sha};
use super::{BlockStoreCliente, Fila, Session, StorageCliente, connect, open_fila};
use optfs::{Allocator, BlockIo, Fs, IoError, Tx, mount};
use optfs_format::{BlockPtr, Integrity, SUPERBLOCKS, Superblock};
use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::ring::Consumer;

/// Commits depois da recuperação que encerram o cenário.
const AFTER: u32 = 1;
/// Sem queda nenhuma até aqui, o cenário encerra: o `svcmgr` mata o alvo até
/// 9 s depois de pôr os serviços em `Running` e o driver volta em ~100 ms. O
/// driver morto só dá `Reset` a quem tem pedido em voo; quem estava
/// calculando não vê nada, e o `xtask` confere o disco do mesmo jeito.
const QUIET_NS: u64 = 16_000_000_000;

/// Fim de uma tentativa que não foi um erro do cenário.
enum Fim {
    /// O dispositivo falhou: o `storaged` morreu.
    Queda,
    /// Recuperou e gravou o que devia.
    Pronto,
}

/// Monta (ou formata) e commita até a primeira falha de E/S. `check` é
/// verdadeiro depois de uma queda: o volume tem de montar com um txg que não
/// seja menor que o último confirmado, com o conteúdo desse txg.
#[inline(never)]
fn attempt(
    f: &mut Fila,
    blocks: u64,
    confirmed: &mut u64,
    check: bool,
    deadline: u64,
) -> Option<Fim> {
    let h = Sha;
    let mut io = QueueIo::new(f, blocks);
    let mounted = mount(&mut io, &h);
    // Erro de E/S na montagem é a queda; só um volume em branco se formata.
    if matches!(mounted, Err(IoError::Io)) {
        return Some(Fim::Queda);
    }
    let (mut prev, mut root) = if let Ok(m) = mounted {
        (m.sb, m.sb.root)
    } else if check && *confirmed > 0 {
        // Com commit confirmado, montar tem de funcionar depois de uma queda.
        return None;
    } else {
        let s1 = Superblock {
            uuid: UUID,
            txg: 1,
            integrity: Integrity::Hash,
            root: BlockPtr::null(),
            volume_blocks: blocks,
            epochs: 0,
            free_blocks: blocks,
        };
        if io.write(SUPERBLOCKS[1], &s1.encode(&h)).is_err() || io.flush().is_err() {
            return Some(Fim::Queda);
        }
        (s1, s1.root)
    };
    let mut al = Allocator::new(blocks);
    if !root.is_null() {
        let mut tx = Tx::new(&mut io, &h, &mut al, prev.txg + 1, 1);
        tx.mark_reachable(&[root]).ok()?;
        if check {
            let fs = Fs::from_root(root, KEY);
            let (file, _) = fs.lookup(&mut tx, 1, "f").ok()??;
            let got = fs.read(&mut tx, file, 0, FILE_LEN).ok()?;
            if prev.txg < *confirmed || got != pattern(prev.txg) {
                ostd::debug::print_fmt(format_args!(
                    "fsstress: perdeu commit: montou txg {} e confirmado {}",
                    prev.txg, *confirmed
                ));
                return None;
            }
            ostd::debug::print_fmt(format_args!(
                "fsstress: recuperado: montou txg {} e confirmado {}",
                prev.txg, *confirmed
            ));
        }
    }
    let mut k = 0u32;
    loop {
        let txg = prev.txg + 1;
        let mut tx = Tx::new(&mut io, &h, &mut al, txg, 1);
        // Erro de E/S aqui é a queda do `storaged` no meio do commit.
        let opened = if root.is_null() {
            Fs::create(&mut tx, KEY)
                .and_then(|mut fs| {
                    let file = fs.create_file(&mut tx, 1, "f")?;
                    Ok((fs, file))
                })
                .ok()
        } else {
            let fs = Fs::from_root(root, KEY);
            match fs.lookup(&mut tx, 1, "f") {
                Ok(Some((file, _))) => Some((fs, file)),
                Ok(None) => return None,
                Err(_) => None,
            }
        };
        let Some((mut fs, file)) = opened else {
            return Some(Fim::Queda);
        };
        if fs.write(&mut tx, file, 0, &pattern(txg)).is_err() {
            return Some(Fim::Queda);
        }
        let mut new = prev;
        new.root = fs.root;
        new.free_blocks = tx.free_blocks();
        let Ok(sb) = tx.commit(&prev, new) else {
            return Some(Fim::Queda);
        };
        prev = sb;
        root = fs.root;
        *confirmed = txg;
        k += 1;
        ostd::debug::print_fmt(format_args!("fsstress: commit {k} txg {txg}"));
        if (check && k >= AFTER) || (!check && ostd::time::now_ns() >= deadline) {
            return Some(Fim::Pronto);
        }
    }
}

/// Abre a partição `caos` no `Storage` de `ep`.
fn open_caos(s: &mut Session, ep: Handle, quota: Handle) -> Option<(Fila, u64)> {
    let part = StorageCliente::new(ep)
        .open(&mut s.buffer, "caos")
        .ok()?
        .ok()?;
    let info = BlockStoreCliente::new(part)
        .info(&mut s.buffer)
        .ok()?
        .ok()?;
    Some((open_fila(&mut s.buffer, quota, part)?, info.blocks))
}

/// Filas que o `storaged` aceita ao todo (`MAX_QUEUES`).
const FILAS: u32 = 8;
/// Filas por sessão (`QUEUES_PER_SESSION`).
const POR_SESSAO: u32 = 4;
/// Onde a área de cada fila de teste é mapeada, só para criar o anel.
const MORTO_VA: u64 = 0x50_0000_0000;

/// Abre uma fila no `BlockStore` `part` sem usá-la (só o contrato `open_queue`).
fn fila_vazia(s: &mut Session, quota: Handle, part: Handle, i: u32) -> Option<()> {
    let bytes = ostd::ring::object_bytes(super::RING_BYTES) + 4096;
    let area = ostd::cap::create(quota, ObjectType::MemoryObject, bytes).ok()?;
    let ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).ok()?;
    // O anel de conclusões precisa de cabeçalho; o mapeamento some no fim.
    let _ring = Consumer::create(
        area,
        MORTO_VA + u64::from(i) * 0x20_0000,
        super::RING_BYTES,
        0x0B02,
        ntfy,
    )
    .ok()?;
    let rw = ostd::cap::mint(area, Rights::MAP | Rights::READ | Rights::WRITE, 0, None).ok()?;
    let sig = ostd::cap::mint(ntfy, Rights::SIGNAL, 0, None).ok()?;
    BlockStoreCliente::new(part)
        .open_queue(&mut s.buffer, rw, sig, 4, 1, 1)
        .ok()?
        .ok()
        .map(drop)
}

/// A segunda encarnação do `drvcli` (depois de o `svcmgr` matar a primeira,
/// que deixou uma sessão e uma fila abertas no `storaged`): sem soltar as
/// filas do cliente morto não cabem as 8 filas do `storaged`. O `open` já
/// liberou a sessão velha pela geração do cliente (ADR 0072).
fn morto(s: &mut Session, ep: Handle, quota: Handle) -> Option<()> {
    let storage = StorageCliente::new(ep);
    let mut abertas = 0;
    for _ in 0..FILAS / POR_SESSAO {
        let part = storage.open(&mut s.buffer, "caos").ok()?.ok()?;
        for _ in 0..POR_SESSAO {
            fila_vazia(s, quota, part, abertas)?;
            abertas += 1;
        }
    }
    ostd::debug::print_fmt(format_args!(
        "fsstress: cliente morto: {abertas} filas abertas"
    ));
    Some(())
}

/// O cenário inteiro. `None` num erro; só volta com `Some` depois de
/// recuperar da queda e gravar mais commits.
pub fn run(s: &mut Session, ep: Handle, quota: Handle) -> Option<()> {
    // Encarnação nova do `drvcli`: a anterior morreu (ADR 0072).
    if s.boot.generation > 1 {
        return morto(s, ep, quota);
    }
    let mut confirmed = 0u64;
    let mut ep = ep;
    let mut dead = false;
    let mut retries = 0u32;
    let mut resets = 0u32;
    let deadline = ostd::time::now_ns().saturating_add(QUIET_NS);
    'outer: loop {
        // Uma queda no meio de `open` ou da abertura da fila também vale.
        let Some((mut q, blocks)) = open_caos(s, ep, quota) else {
            retries += 1;
            if retries > 5 {
                return None;
            }
            ep = connect(s, b"optimus.storage.Storage")?;
            dead = true;
            continue;
        };
        loop {
            match attempt(&mut q, blocks, &mut confirmed, dead, deadline)? {
                Fim::Pronto => return Some(()),
                Fim::Queda => {
                    // O `BlockStore` morreu e o `svcmgr` revogou a instância:
                    // quem estava numa chamada recebe `PeerClosed`; uma chamada
                    // nova numa cópia revogada, `InvalidHandle` (ADR 0067,
                    // item 4).
                    let r = q.store.info(&mut s.buffer);
                    if r.is_ok() {
                        // O `storaged` segue vivo: o driver de bloco morreu e
                        // os pedidos concluíram com `Reset` (ADR 0072). O
                        // `storaged` reconecta; o cliente espera e remonta.
                        resets += 1;
                        if resets > 120 {
                            ostd::debug::print("fsstress: Reset sem fim");
                            return None;
                        }
                        if resets == 1 {
                            ostd::debug::print_fmt(format_args!(
                                "fsstress: Reset visto depois do commit txg {confirmed}"
                            ));
                        }
                        super::pause();
                        dead = true;
                        continue;
                    }
                    if !matches!(r, Err(Error::PeerClosed | Error::InvalidHandle)) {
                        ostd::debug::print("fsstress: E/S falhou mas o BlockStore segue vivo");
                        return None;
                    }
                    ostd::debug::print_fmt(format_args!(
                        "fsstress: queda vista ({:?}) depois do commit txg {confirmed}",
                        r.err()
                    ));
                    // Solta os mapeamentos: a fila nova usa os mesmos endereços.
                    drop(q);
                    ep = connect(s, b"optimus.storage.Storage")?;
                    dead = true;
                    continue 'outer;
                }
            }
        }
    }
}
