//! Queda do `storaged` no meio de uma escrita (T-541): numa partição `caos`
//! o `drvcli` grava commits sem parar; o `svcmgr` mata o `storaged` num
//! ponto do boot (`svcmgr.mata`). O cliente vê o `BlockStore` morto
//! (`PeerClosed`), reconecta ao `storaged` que o `svcmgr` reiniciou, reabre a
//! fila, remonta o volume e confere que nenhum commit confirmado se perdeu.

use super::crash_step::{FILE_LEN, KEY, UUID, pattern};
use super::optfs_step::{QueueIo, Sha};
use super::{BlockStoreCliente, Fila, Session, StorageCliente, connect, open_fila};
use optfs::{Allocator, BlockIo, Fs, Tx, mount};
use optfs_format::{BlockPtr, Integrity, SUPERBLOCKS, Superblock};
use ostd::kabi::{Error, Handle};

/// Commits depois da recuperação que encerram o cenário.
const AFTER: u32 = 2;

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
fn attempt(f: &mut Fila, blocks: u64, confirmed: &mut u64, check: bool) -> Option<Fim> {
    let h = Sha;
    let mut io = QueueIo::new(f, blocks);
    let (mut prev, mut root) = if let Ok(m) = mount(&mut io, &h) {
        (m.sb, m.sb.root)
    } else if check {
        // Montar tem de funcionar depois de uma queda.
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
        let (mut fs, file) = if root.is_null() {
            let mut fs = Fs::create(&mut tx, KEY).ok()?;
            let file = fs.create_file(&mut tx, 1, "f").ok()?;
            (fs, file)
        } else {
            let fs = Fs::from_root(root, KEY);
            let (file, _) = fs.lookup(&mut tx, 1, "f").ok()??;
            (fs, file)
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
        if check && k >= AFTER {
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

/// O cenário inteiro. `None` num erro; só volta com `Some` depois de
/// recuperar da queda e gravar mais commits.
pub fn run(s: &mut Session, ep: Handle, quota: Handle) -> Option<()> {
    let mut confirmed = 0u64;
    let mut ep = ep;
    let mut dead = false;
    loop {
        let (mut q, blocks) = open_caos(s, ep, quota)?;
        match attempt(&mut q, blocks, &mut confirmed, dead)? {
            Fim::Pronto => return Some(()),
            Fim::Queda => {
                // O `BlockStore` morreu e o `svcmgr` revogou a instância: quem
                // estava numa chamada recebe `PeerClosed`; uma chamada nova
                // numa cópia revogada, `InvalidHandle` (ADR 0067, item 4).
                let r = q.store.info(&mut s.buffer);
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
            }
        }
    }
}
