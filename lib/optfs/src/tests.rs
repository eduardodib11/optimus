#![allow(clippy::cast_possible_truncation)]

use crate::sim::Sim;
use crate::{Allocator, BlockIo, IoError, commit, mount};
use optfs_format::{BLOCK_SIZE, BlockPtr, Integrity, SUPERBLOCKS, Sha256, Superblock};

struct Fake;
impl Sha256 for Fake {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in data.iter().enumerate() {
            let s = &mut out[i % 32];
            *s = s
                .wrapping_mul(31)
                .wrapping_add(*b)
                .wrapping_add(i.to_le_bytes()[0]);
        }
        out
    }
}

const N: usize = 256;

fn sb(txg: u64, marker: u64) -> Superblock {
    let mut root = BlockPtr::null();
    root.addr = marker;
    Superblock {
        uuid: [1; 16],
        txg,
        integrity: Integrity::Hash,
        root,
        volume_blocks: N as u64,
        epochs: 0,
        free_blocks: 100,
    }
}

/// Disco formatado com o txg 1 gravado em A/B e durável.
fn formatted() -> (Sim, Superblock) {
    let mut d = Sim::new(N);
    let s = sb(1, 1);
    d.write(SUPERBLOCKS[1], &s.encode(&Fake)).unwrap();
    d.flush().unwrap();
    (d, s)
}

#[test]
fn monta_o_de_maior_txg() {
    let (mut d, s1) = formatted();
    let s2 = commit(&mut d, &Fake, &s1, sb(0, 2), []).unwrap();
    assert_eq!(s2.txg, 2);
    let m = mount(&mut d, &Fake).unwrap();
    assert_eq!((m.sb.txg, m.sb.root.addr, m.other_invalid), (2, 2, false));
    // O txg 1 continua no outro slot, como superbloco de reserva.
    d.crash();
    assert_eq!(mount(&mut d, &Fake).unwrap().sb.txg, 2);
}

#[test]
fn ordem_do_commit_e_dois_flushes() {
    let (mut d, s1) = formatted();
    d.log.clear();
    let blk = [9u8; BLOCK_SIZE];
    commit(&mut d, &Fake, &s1, sb(0, 2), [(20, &blk), (21, &blk)]).unwrap();
    assert_eq!(d.log, ["write", "write", "flush", "write", "flush"]);
}

#[test]
fn queda_em_qualquer_ponto_monta_um_commit_confirmado() {
    // Para cada ponto de falha do commit, depois da queda monta-se o txg
    // antigo ou o novo, nunca outra coisa; se o commit retornou Ok, o
    // novo.
    for budget in 0..8 {
        let (mut d, s1) = formatted();
        let blk = [7u8; BLOCK_SIZE];
        d.budget = Some(budget);
        let r = commit(&mut d, &Fake, &s1, sb(0, 2), [(20, &blk)]);
        d.crash();
        let m = mount(&mut d, &Fake).unwrap();
        if r.is_ok() {
            assert_eq!(m.sb.txg, 2, "budget {budget}");
        } else {
            assert_eq!(m.sb.txg, 1, "budget {budget}");
        }
        let mut b = [0u8; BLOCK_SIZE];
        d.read(20, &mut b).unwrap();
    }
}

#[test]
fn superbloco_rasgado_cai_para_o_anterior() {
    let (mut d, s1) = formatted();
    commit(&mut d, &Fake, &s1, sb(0, 2), []).unwrap();
    d.durable[SUPERBLOCKS[0] as usize][100] ^= 0xff; // txg 2 vai no slot 0
    let m = mount(&mut d, &Fake).unwrap();
    assert_eq!((m.sb.txg, m.other_invalid), (1, true));
    d.durable[SUPERBLOCKS[1] as usize][100] ^= 0xff;
    assert_eq!(mount(&mut d, &Fake).unwrap_err(), IoError::Integrity);
}

#[test]
fn txg_no_limite_do_u64_nao_causa_overflow() {
    let (mut d, _) = formatted();
    let last = sb(u64::MAX, 1);
    assert_eq!(
        commit(&mut d, &Fake, &last, sb(0, 2), []).unwrap_err(),
        IoError::Full
    );
}

#[test]
fn recusa_escrever_em_regiao_reservada() {
    let (mut d, s1) = formatted();
    let blk = [0u8; BLOCK_SIZE];
    for b in [0u64, 2, 3, 15, N as u64 - 1, N as u64 + 5] {
        assert_eq!(
            commit(&mut d, &Fake, &s1, sb(0, 2), [(b, &blk)]).unwrap_err(),
            IoError::BadRequest,
            "bloco {b}"
        );
    }
    assert_eq!(mount(&mut d, &Fake).unwrap().sb.txg, 1);
}

#[test]
fn liberado_so_volta_dois_commits_depois() {
    let mut a = Allocator::new(N as u64);
    let x = a.alloc().unwrap();
    assert!(x >= 16);
    a.free(5, x); // liberado no txg 5
    // Enquanto o txg 5 não foi confirmado, o bloco não volta.
    assert!(a.is_used(x));
    a.confirmed(5);
    assert!(a.is_used(x), "o txg 4 (reserva) ainda o referencia");
    a.confirmed(6);
    assert!(!a.is_used(x));
}

#[test]
fn aloca_ate_encher() {
    let mut a = Allocator::new(32);
    let mut got = Vec::new();
    while let Ok(b) = a.alloc() {
        assert!((16..31).contains(&b));
        got.push(b);
    }
    assert_eq!(got.len(), 15);
    assert_eq!(a.alloc(), Err(IoError::Full));
    got.sort_unstable();
    got.dedup();
    assert_eq!(got.len(), 15);
}

mod arvore {
    use super::*;
    use crate::Tx;
    use optfs_format::{Key, KeyKind};

    fn k(n: u64) -> Key {
        Key {
            object: n,
            kind: KeyKind::Extent,
            offset: 0,
        }
    }
    fn val(n: u64, len: usize) -> Vec<u8> {
        (0..len).map(|i| (n as usize + i) as u8).collect()
    }
    fn perm(n: u64) -> Vec<u64> {
        // Permutação determinística (multiplicador coprimo com n primo).
        (0..n).map(|i| (i * 7919) % n).collect()
    }

    #[test]
    fn insere_busca_remove_e_remonta_depois_de_queda() {
        let (mut d, s1) = formatted_big();
        let mut al = Allocator::new(d.blocks());
        let mut root = BlockPtr::null();
        let n = 3001; // primo
        {
            let mut tx = Tx::new(&mut d, &Fake, &mut al, 2, 1);
            for i in perm(n) {
                root = tx
                    .insert(&root, k(i), &val(i, 100 + (i % 200) as usize))
                    .unwrap();
            }
            for i in 0..n {
                assert_eq!(
                    tx.get(&root, &k(i)).unwrap(),
                    Some(val(i, 100 + (i % 200) as usize))
                );
            }
            assert_eq!(tx.get(&root, &k(n + 5)).unwrap(), None);
            // Remove os pares e troca um valor.
            for i in (0..n).step_by(2) {
                root = tx.remove(&root, &k(i)).unwrap();
            }
            root = tx.insert(&root, k(1), b"novo").unwrap();
            for i in 0..n {
                let want = if i % 2 == 0 {
                    None
                } else if i == 1 {
                    Some(b"novo".to_vec())
                } else {
                    Some(val(i, 100 + (i % 200) as usize))
                };
                assert_eq!(tx.get(&root, &k(i)).unwrap(), want, "chave {i}");
            }
            // Varredura em ordem.
            let mut at = k(0);
            let mut seen = 0u64;
            while let Some((key, _)) = tx.first_ge(&root, &at).unwrap() {
                assert_eq!(key.object % 2, 1);
                seen += 1;
                at = Key { offset: 1, ..key };
            }
            assert_eq!(seen, n / 2);
            let mut new = sb(0, 0);
            new.root = root;
            tx.commit(&s1, new).unwrap();
        }
        d.crash();
        let m = mount(&mut d, &Fake).unwrap();
        assert_eq!(m.sb.txg, 2);
        let mut al2 = Allocator::new(d.blocks());
        let mut tx = Tx::new(&mut d, &Fake, &mut al2, 3, 1);
        assert_eq!(tx.get(&m.sb.root, &k(1)).unwrap(), Some(b"novo".to_vec()));
        assert_eq!(tx.get(&m.sb.root, &k(2)).unwrap(), None);
        assert_eq!(
            tx.get(&m.sb.root, &k(2999)).unwrap(),
            Some(val(2999, 100 + (2999 % 200) as usize))
        );
    }

    #[test]
    fn adulteracao_de_no_e_detectada_na_leitura() {
        let (mut d, s1) = formatted_big();
        let mut al = Allocator::new(d.blocks());
        let mut tx = Tx::new(&mut d, &Fake, &mut al, 2, 1);
        let mut root = BlockPtr::null();
        for i in 0..200 {
            root = tx.insert(&root, k(i), &val(i, 300)).unwrap();
        }
        let mut new = sb(0, 0);
        new.root = root;
        tx.commit(&s1, new).unwrap();
        let addr = root.addr as usize;
        let mut al2 = Allocator::new(d.blocks());
        d.durable[addr][500] ^= 1;
        let mut tx = Tx::new(&mut d, &Fake, &mut al2, 3, 1);
        assert_eq!(tx.get(&root, &k(1)).unwrap_err(), IoError::Integrity);
        // Árvore de outro dono: o cabeçalho não confere.
        d.durable[addr][500] ^= 1;
        let mut tx = Tx::new(&mut d, &Fake, &mut al2, 3, 99);
        assert_eq!(tx.get(&root, &k(1)).unwrap_err(), IoError::Integrity);
    }

    #[test]
    fn valor_grande_demais_e_recusado() {
        let mut d = Sim::new(N);
        let mut al = Allocator::new(N as u64);
        let mut tx = Tx::new(&mut d, &Fake, &mut al, 2, 1);
        assert_eq!(
            tx.insert(&BlockPtr::null(), k(1), &[0; 1025]).unwrap_err(),
            IoError::BadRequest
        );
    }

    fn formatted_big() -> (Sim, Superblock) {
        let mut d = Sim::new(4096);
        let mut s = sb(1, 1);
        s.volume_blocks = 4096;
        d.write(SUPERBLOCKS[1], &s.encode(&Fake)).unwrap();
        d.flush().unwrap();
        (d, s)
    }
}

mod arquivos {
    use super::*;
    use crate::{Fs, FsError, ObjKind, Tx};

    fn big() -> (Sim, Superblock) {
        let mut d = Sim::new(4096);
        let mut s = sb(1, 1);
        s.volume_blocks = 4096;
        d.write(SUPERBLOCKS[1], &s.encode(&Fake)).unwrap();
        d.flush().unwrap();
        (d, s)
    }

    fn pat(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn diretorios_arquivos_e_conteudo_sobrevivem_a_queda() {
        let (mut d, s1) = big();
        let mut al = Allocator::new(4096);
        let mut tx = Tx::new(&mut d, &Fake, &mut al, 2, 1);
        let mut fs = Fs::create(&mut tx, [5; 32]).unwrap();
        let docs = fs.mkdir(&mut tx, 1, "docs").unwrap();
        let small = fs.create_file(&mut tx, docs, "nota.txt").unwrap();
        let large = fs.create_file(&mut tx, docs, "grande.bin").unwrap();
        fs.write(&mut tx, small, 0, b"ola, optfs").unwrap();
        let big_data = pat(70_000, 3);
        fs.write(&mut tx, large, 0, &big_data).unwrap();
        // Sobrescreve o meio, atravessando blocos, e escreve com buraco.
        let mid = pat(9_000, 99);
        fs.write(&mut tx, large, 5_000, &mid).unwrap();
        let mut want = big_data.clone();
        want[5_000..14_000].copy_from_slice(&mid);
        fs.write(&mut tx, large, 100_000, b"fim").unwrap();
        want.resize(100_000, 0);
        want.extend_from_slice(b"fim");
        assert_eq!(fs.read(&mut tx, large, 0, 200_000).unwrap(), want);
        assert_eq!(
            fs.read(&mut tx, large, 69_990, 20).unwrap(),
            want[69_990..70_010]
        );
        assert_eq!(fs.read(&mut tx, small, 0, 100).unwrap(), b"ola, optfs");
        // Pequeno que cresce além de 1 KiB vira bloco de dados.
        fs.write(&mut tx, small, 10, &pat(3000, 1)).unwrap();
        let mut sw = b"ola, optfs".to_vec();
        sw.extend(pat(3000, 1));
        assert_eq!(fs.read(&mut tx, small, 0, 5000).unwrap(), sw);
        let mut new = sb(0, 0);
        new.root = fs.root;
        tx.commit(&s1, new).unwrap();
        let (root, name_key) = (fs.root, fs.name_key);
        d.crash();
        let m = mount(&mut d, &Fake).unwrap();
        assert_eq!(m.sb.root, root);
        let mut al = Allocator::new(4096);
        let mut tx = Tx::new(&mut d, &Fake, &mut al, 3, 1);
        let fs = Fs::from_root(m.sb.root, name_key);
        // O alocador remontado reconhece os blocos em uso: 19 de dados do
        // arquivo grande, 1 do pequeno e os nós.
        let before = tx.free_blocks();
        tx.mark_reachable(&[fs.root]).unwrap();
        assert!(before - tx.free_blocks() >= 20);
        assert_eq!(
            fs.lookup(&mut tx, 1, "docs").unwrap(),
            Some((docs, ObjKind::Dir))
        );
        assert_eq!(
            fs.lookup(&mut tx, docs, "grande.bin").unwrap(),
            Some((large, ObjKind::File))
        );
        assert_eq!(fs.read(&mut tx, large, 0, 200_000).unwrap(), want);
        let mut names: Vec<String> = fs
            .readdir(&mut tx, docs)
            .unwrap()
            .into_iter()
            .map(|e| e.0)
            .collect();
        names.sort();
        assert_eq!(names, ["grande.bin", "nota.txt"]);
        assert_eq!(fs.stat(&mut tx, large).unwrap().size, 100_003);
    }

    #[test]
    fn erros_de_nome_e_tipo() {
        let (mut d, _) = big();
        let mut al = Allocator::new(4096);
        let mut tx = Tx::new(&mut d, &Fake, &mut al, 2, 1);
        let mut fs = Fs::create(&mut tx, [5; 32]).unwrap();
        let dir = fs.mkdir(&mut tx, 1, "d").unwrap();
        let f = fs.create_file(&mut tx, dir, "f").unwrap();
        assert_eq!(fs.create_file(&mut tx, dir, "f"), Err(FsError::Exists));
        for bad in ["", "a/b", "a\0b", &"x".repeat(256)] {
            assert_eq!(fs.create_file(&mut tx, dir, bad), Err(FsError::BadName));
        }
        assert_eq!(fs.create_file(&mut tx, f, "x"), Err(FsError::NotDir));
        assert_eq!(fs.read(&mut tx, dir, 0, 1), Err(FsError::IsDir));
        assert_eq!(fs.write(&mut tx, dir, 0, b"x"), Err(FsError::IsDir));
        assert_eq!(fs.unlink(&mut tx, 1, "d"), Err(FsError::NotEmpty));
        assert_eq!(fs.unlink(&mut tx, 1, "nada"), Err(FsError::NotFound));
        fs.unlink(&mut tx, dir, "f").unwrap();
        fs.unlink(&mut tx, 1, "d").unwrap();
        assert!(fs.readdir(&mut tx, 1).unwrap().is_empty());
        assert_eq!(fs.stat(&mut tx, f), Err(FsError::NotFound));
    }

    #[test]
    fn apagar_devolve_o_espaco_depois_de_dois_commits() {
        let (mut d, mut prev) = big();
        let mut al = Allocator::new(4096);
        let mut root;
        {
            let mut tx = Tx::new(&mut d, &Fake, &mut al, 2, 1);
            let mut fs = Fs::create(&mut tx, [5; 32]).unwrap();
            let f = fs.create_file(&mut tx, 1, "f").unwrap();
            fs.write(&mut tx, f, 0, &pat(200_000, 1)).unwrap();
            let mut new = sb(0, 0);
            new.root = fs.root;
            prev = tx.commit(&prev, new).unwrap();
            root = fs.root;
        }
        let free0 = al.free_blocks();
        for txg in [3, 4, 5] {
            let mut tx = Tx::new(&mut d, &Fake, &mut al, txg, 1);
            let mut fs = Fs::from_root(root, [5; 32]);
            if txg == 3 {
                fs.unlink(&mut tx, 1, "f").unwrap();
            }
            let mut new = sb(0, 0);
            new.root = fs.root;
            prev = tx.commit(&prev, new).unwrap();
            root = fs.root;
            if txg == 3 {
                assert!(al.free_blocks() < free0 + 5, "volta antes da hora");
            }
        }
        // 200 000 bytes são 49 blocos de dados mais nós; tudo volta.
        assert!(
            al.free_blocks() >= free0 + 49,
            "{} {}",
            al.free_blocks(),
            free0
        );
    }
}

mod snapshots {
    use super::*;
    use crate::{Fs, FsError, Tx};

    fn big() -> (Sim, Superblock) {
        let mut d = Sim::new(4096);
        let mut s = sb(1, 1);
        s.volume_blocks = 4096;
        s.root = BlockPtr::null();
        d.write(SUPERBLOCKS[1], &s.encode(&Fake)).unwrap();
        d.flush().unwrap();
        (d, s)
    }

    fn pat(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed))
            .collect()
    }

    /// Um txg: abre, roda `f`, confirma. Devolve o novo superbloco.
    fn txg(
        d: &mut Sim,
        al: &mut Allocator,
        prev: &Superblock,
        f: impl FnOnce(&mut Tx<'_, Sim, Fake>, &mut Fs),
    ) -> Superblock {
        let t = prev.txg + 1;
        let mut tx = Tx::new(d, &Fake, al, t, 1);
        let mut fs = if prev.root.is_null() {
            Fs::create(&mut tx, [5; 32]).unwrap()
        } else {
            Fs::open(&mut tx, prev.root, [5; 32]).unwrap()
        };
        f(&mut tx, &mut fs);
        let mut new = sb(0, 0);
        new.root = fs.root;
        tx.commit(prev, new).unwrap()
    }

    #[test]
    fn snapshot_guarda_o_passado_apesar_de_escritas_e_remontagem() {
        let (mut d, s1) = big();
        let mut al = Allocator::new(4096);
        let v1 = pat(20_000, 1);
        let s2 = txg(&mut d, &mut al, &s1, |tx, fs| {
            let f = fs.create_file(tx, 1, "a").unwrap();
            fs.write(tx, f, 0, &v1).unwrap();
            fs.snapshot(tx, "s1").unwrap();
        });
        // Muda tudo depois do snapshot, em vários txgs (o alocador reusa
        // blocos liberados: se o snapshot os perdesse, a leitura falharia).
        let v2 = pat(20_000, 77);
        let mut prev = s2;
        for i in 0..4 {
            prev = txg(&mut d, &mut al, &prev, |tx, fs| {
                fs.write(tx, 2, 0, &v2).unwrap();
                fs.create_file(tx, 1, &format!("b{i}")).unwrap();
            });
        }
        d.crash();
        let m = mount(&mut d, &Fake).unwrap();
        let mut al = Allocator::new(4096);
        let mut tx = Tx::new(&mut d, &Fake, &mut al, m.sb.txg + 1, 1);
        let fs = Fs::open(&mut tx, m.sb.root, [5; 32]).unwrap();
        let snaps = fs.snapshots(&mut tx).unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].name, "s1");
        let mut roots = vec![fs.root];
        roots.extend(snaps.iter().map(|s| s.root));
        tx.mark_reachable(&roots).unwrap();
        assert_eq!(fs.read(&mut tx, 2, 0, 30_000).unwrap(), v2);
        let old = fs.view(&mut tx, "s1").unwrap();
        assert_eq!(old.read(&mut tx, 2, 0, 30_000).unwrap(), v1);
        assert!(old.lookup(&mut tx, 1, "b0").unwrap().is_none());
        assert!(fs.lookup(&mut tx, 1, "b0").unwrap().is_some());
        let mut ro = old;
        assert_eq!(ro.write(&mut tx, 2, 0, b"x"), Err(FsError::ReadOnly));
        assert_eq!(ro.create_file(&mut tx, 1, "z"), Err(FsError::ReadOnly));
    }

    #[test]
    fn rollback_restaura_o_snapshot_e_devolve_o_espaco() {
        let (mut d, s1) = big();
        let mut al = Allocator::new(4096);
        let v1 = pat(30_000, 1);
        let mut prev = txg(&mut d, &mut al, &s1, |tx, fs| {
            let f = fs.create_file(tx, 1, "a").unwrap();
            fs.write(tx, f, 0, &v1).unwrap();
            fs.snapshot(tx, "s1").unwrap();
        });
        let base_free = al.free_blocks();
        prev = txg(&mut d, &mut al, &prev, |tx, fs| {
            fs.write(tx, 2, 0, &pat(30_000, 50)).unwrap();
            fs.create_file(tx, 1, "b").unwrap();
            fs.snapshot(tx, "s2").unwrap();
        });
        prev = txg(&mut d, &mut al, &prev, |tx, fs| {
            fs.write(tx, 2, 100, &pat(5_000, 9)).unwrap();
        });
        assert!(al.free_blocks() < base_free - 10);
        prev = txg(&mut d, &mut al, &prev, |tx, fs| {
            fs.rollback(tx, "s1").unwrap();
            assert_eq!(fs.read(tx, 2, 0, 40_000).unwrap(), v1);
            assert!(fs.lookup(tx, 1, "b").unwrap().is_none());
            let names: Vec<String> = fs
                .snapshots(tx)
                .unwrap()
                .into_iter()
                .map(|s| s.name)
                .collect();
            assert_eq!(names, ["s1"]);
        });
        // Dois commits vazios e o espaço do futuro descartado volta.
        for _ in 0..2 {
            prev = txg(&mut d, &mut al, &prev, |_, _| {});
        }
        assert!(
            al.free_blocks() + 3 >= base_free,
            "livres {} contra {base_free} antes da mudança",
            al.free_blocks()
        );
        // Depois de uma queda a raiz montada é a do rollback, e o snapshot
        // s1 ainda lê o conteúdo original.
        d.crash();
        let m = mount(&mut d, &Fake).unwrap();
        let mut al2 = Allocator::new(4096);
        let mut tx = Tx::new(&mut d, &Fake, &mut al2, m.sb.txg + 1, 1);
        let fs = Fs::open(&mut tx, m.sb.root, [5; 32]).unwrap();
        assert_eq!(fs.read(&mut tx, 2, 0, 40_000).unwrap(), v1);
        assert_eq!(
            fs.view(&mut tx, "s1")
                .unwrap()
                .read(&mut tx, 2, 0, 40_000)
                .unwrap(),
            v1
        );
        assert_eq!(fs.view(&mut tx, "s2").err(), Some(FsError::NotFound));
    }

    #[test]
    fn apagar_snapshot_devolve_so_o_que_ele_usava() {
        let (mut d, s1) = big();
        let mut al = Allocator::new(4096);
        let mut prev = txg(&mut d, &mut al, &s1, |tx, fs| {
            let f = fs.create_file(tx, 1, "a").unwrap();
            fs.write(tx, f, 0, &pat(40_000, 1)).unwrap();
            fs.snapshot(tx, "velho").unwrap();
        });
        prev = txg(&mut d, &mut al, &prev, |tx, fs| {
            fs.write(tx, 2, 0, &pat(40_000, 2)).unwrap();
        });
        let with_snap = al.free_blocks();
        prev = txg(&mut d, &mut al, &prev, |tx, fs| {
            fs.delete_snapshot(tx, "velho").unwrap();
            assert_eq!(fs.delete_snapshot(tx, "velho"), Err(FsError::NotFound));
            assert!(fs.snapshots(tx).unwrap().is_empty());
        });
        for _ in 0..2 {
            prev = txg(&mut d, &mut al, &prev, |_, _| {});
        }
        // Os 10 blocos de dados do conteúdo antigo voltam.
        assert!(
            al.free_blocks() >= with_snap + 10,
            "{} contra {with_snap}",
            al.free_blocks()
        );
        // O conteúdo vivo continua íntegro.
        let mut tx = Tx::new(&mut d, &Fake, &mut al, prev.txg + 1, 1);
        let fs = Fs::open(&mut tx, prev.root, [5; 32]).unwrap();
        assert_eq!(fs.read(&mut tx, 2, 0, 50_000).unwrap(), pat(40_000, 2));
    }
}

/// T-533 (versão de host): 200 quedas em pontos aleatórios de um trabalho
/// de escrita; depois de cada uma, o que se monta é exatamente o último
/// estado confirmado.
mod queda_de_energia {
    use super::*;
    use crate::{Fs, Tx};
    use std::collections::BTreeMap;

    fn next(r: &mut u64) -> u64 {
        *r = r
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *r >> 33
    }

    fn content(seed: u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (seed as u8).wrapping_add((i as u8).wrapping_mul(31)))
            .collect()
    }

    type Model = BTreeMap<String, Vec<u8>>;

    /// O que está montado, lido por inteiro.
    fn state(d: &mut Sim, m: &crate::Mounted) -> Model {
        let mut out = Model::new();
        if m.sb.root.is_null() {
            return out;
        }
        let mut al = Allocator::new(4096);
        let mut tx = Tx::new(d, &Fake, &mut al, m.sb.txg + 1, 1);
        let fs = Fs::open(&mut tx, m.sb.root, [5; 32]).unwrap();
        for (name, obj, _) in fs.readdir(&mut tx, 1).unwrap() {
            out.insert(name, fs.read(&mut tx, obj, 0, 100_000).unwrap());
        }
        out
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::many_single_char_names)]
    fn duzentas_quedas_nunca_perdem_commit_confirmado() {
        let mut rng = 0x00c0_ffee_u64;
        let mut d = Sim::new(4096);
        let mut s = sb(1, 1);
        s.volume_blocks = 4096;
        s.root = BlockPtr::null();
        d.write(SUPERBLOCKS[1], &s.encode(&Fake)).unwrap();
        d.flush().unwrap();
        let mut prev;
        let mut model = Model::new();
        // Um commit que falhou pode ter chegado ao disco mesmo assim (a
        // queda veio depois do superbloco e antes do `flush` voltar).
        let mut maybe: Option<Model> = None;
        let (mut confirmed, mut adopted) = (0u32, 0u32);
        let mut crashes = 0;
        while crashes < 200 {
            // Monta e reconstrói o alocador, como depois de uma queda real.
            let m = mount(&mut d, &Fake).unwrap();
            prev = m.sb;
            let got = state(&mut d, &m);
            if got != model {
                assert_eq!(
                    Some(&got),
                    maybe.as_ref(),
                    "montou algo que nunca foi confirmado nem tentado"
                );
                model = got;
                adopted += 1;
            }
            maybe = None;
            let mut al = Allocator::new(4096);
            {
                let mut tx = Tx::new(&mut d, &Fake, &mut al, prev.txg + 1, 1);
                let mut roots = Vec::new();
                if !prev.root.is_null() {
                    roots.push(prev.root);
                }
                tx.mark_reachable(&roots).unwrap();
            }
            // Trabalha até o disco cair num ponto aleatório.
            d.budget = Some(next(&mut rng) as usize % 400);
            loop {
                let t = prev.txg + 1;
                let mut tx = Tx::new(&mut d, &Fake, &mut al, t, 1);
                let mut fs = if prev.root.is_null() {
                    Fs::create(&mut tx, [5; 32]).unwrap()
                } else {
                    Fs::open(&mut tx, prev.root, [5; 32]).unwrap()
                };
                let mut next_model = model.clone();
                let mut failed = false;
                for _ in 0..=(next(&mut rng) % 4) {
                    let name = format!("f{}", next(&mut rng) % 6);
                    let r = match next(&mut rng) % 3 {
                        0 if next_model.contains_key(&name) => {
                            next_model.remove(&name);
                            fs.unlink(&mut tx, 1, &name)
                        }
                        _ => {
                            let len = (next(&mut rng) % 9000) as usize;
                            let data = content(next(&mut rng), len);
                            let mut res = Ok(());
                            // Reescreve o arquivo inteiro: sem restos antigos.
                            if next_model.contains_key(&name) {
                                res = fs.unlink(&mut tx, 1, &name);
                            }
                            if res.is_ok() {
                                res = fs
                                    .create_file(&mut tx, 1, &name)
                                    .and_then(|o| fs.write(&mut tx, o, 0, &data));
                                next_model.insert(name.clone(), data);
                            }
                            res
                        }
                    };
                    if r.is_err() {
                        failed = true;
                        break;
                    }
                }
                if failed {
                    break;
                }
                let mut new = sb(0, 0);
                new.root = fs.root;
                if let Ok(sb) = tx.commit(&prev, new) {
                    prev = sb;
                    confirmed += 1;
                    model = next_model;
                } else {
                    maybe = Some(next_model);
                    break;
                }
            }
            // O disco caiu: parte do cache chegou ao disco, o resto some.
            d.crash_partial(&mut rng);
            crashes += 1;
        }
        let m = mount(&mut d, &Fake).unwrap();
        let got = state(&mut d, &m);
        assert!(got == model || Some(&got) == maybe.as_ref());
        // A carga de fato confirma commits e cai em vários pontos.
        assert!(confirmed > 200, "{confirmed} commits confirmados");
        eprintln!(
            "quedas: {crashes}, commits confirmados: {confirmed}, tentados que sobreviveram: {adopted}"
        );
    }
}
