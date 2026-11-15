//! Carga do teste de queda de energia (T-533): numa partição `crash` o
//! `drvcli` monta (ou formata) o `OptFS` e grava commits sem parar, cada um
//! com o arquivo `f` cheio do padrão do txg. O `xtask` derruba o QEMU num
//! ponto aleatório e confere no host que o volume monta e que o último
//! commit confirmado (a linha `fsstress: commit`) está íntegro.

use super::Fila;
use super::optfs_step::{QueueIo, Sha};
use optfs::{Allocator, BlockIo, Fs, Tx, mount};
use optfs_format::{BlockPtr, Integrity, SUPERBLOCKS, Superblock};
use ostd::vec::Vec;

/// Chave de nomes, UUID e arquivo do teste (o `xtask` usa os mesmos).
pub(super) const KEY: [u8; 32] = [7; 32];
pub(super) const UUID: [u8; 16] = [1; 16];
pub(super) const FILE_LEN: usize = 6000;

/// Conteúdo do arquivo no txg `txg`.
pub(super) fn pattern(txg: u64) -> Vec<u8> {
    let seed = txg.to_le_bytes()[0];
    (0..FILE_LEN)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
        .collect()
}

/// Monta o volume (formata se está zerado) e commita para sempre. Só volta
/// com `None`, num erro.
#[inline(never)]
pub fn run(f: &mut Fila, blocks: u64) -> Option<()> {
    let h = Sha;
    let mut io = QueueIo::new(f, blocks);
    let (mut prev, mut root) = if let Ok(m) = mount(&mut io, &h) {
        (m.sb, m.sb.root)
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
        io.write(SUPERBLOCKS[1], &s1.encode(&h)).ok()?;
        io.flush().ok()?;
        (s1, s1.root)
    };
    let mut al = Allocator::new(blocks);
    if !root.is_null() {
        Tx::new(&mut io, &h, &mut al, prev.txg + 1, 1)
            .mark_reachable(&[root])
            .ok()?;
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
        fs.write(&mut tx, file, 0, &pattern(txg)).ok()?;
        let mut new = prev;
        new.root = fs.root;
        new.free_blocks = tx.free_blocks();
        prev = tx.commit(&prev, new).ok()?;
        root = fs.root;
        k += 1;
        ostd::debug::print_fmt(format_args!("fsstress: commit {k} txg {txg}"));
    }
}
