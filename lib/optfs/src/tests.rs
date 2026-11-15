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
        let fs = Fs {
            root: m.sb.root,
            name_key,
        };
        // O alocador remontado reconhece os blocos em uso: 19 de dados do
        // arquivo grande, 1 do pequeno e os nós.
        let before = tx.free_blocks();
        tx.mark_reachable(&fs.root).unwrap();
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
            let mut fs = Fs {
                root,
                name_key: [5; 32],
            };
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
