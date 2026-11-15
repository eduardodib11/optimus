//! O `OptFS` sobre o `BlockStore` no QEMU (T-522): formata a partição
//! `data`, grava um commit, remonta e confere o conteúdo, e confere a ordem
//! que a ADR 0052 exige no dispositivo (superbloco só depois do `flush` dos
//! blocos novos; nenhum pedido pendente depois do commit).

use super::{Fila, PAGE, completion, submit};
use optfs::{Allocator, BlockIo, Fs, IoError, Tx, mount};
use optfs_format::{BLOCK_SIZE, BlockPtr, Integrity, SUPERBLOCKS, Sha256, Superblock};
use ostd::vec::Vec;

struct Sha;

impl Sha256 for Sha {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        optcrypt::sha256::hash(data)
    }
}

/// `BlockIo` sobre uma fila do `BlockStore`, um bloco por pedido, com a
/// conferência da ordem de escrita.
struct QueueIo<'a> {
    f: &'a mut Fila,
    blocks: u64,
    id: u64,
    /// Escritas feitas desde o último `flush`.
    dirty: u32,
    /// Falso se um superbloco foi escrito com escritas ainda sem `flush`.
    ordem_ok: bool,
}

impl QueueIo<'_> {
    fn run(&mut self, op: u8, flags: u8, block: u64) -> Result<(), IoError> {
        self.id += 1;
        let count = u16::from(op != 2);
        if !submit(&mut self.f.ring, self.id, op, flags, count, 0, block) {
            return Err(IoError::Io);
        }
        match completion(&mut self.f.done, self.id) {
            Some(0) => Ok(()),
            _ => Err(IoError::Io),
        }
    }
}

impl BlockIo for QueueIo<'_> {
    fn blocks(&self) -> u64 {
        self.blocks
    }

    fn read(&mut self, block: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), IoError> {
        self.run(0, 0, block)?;
        buf.copy_from_slice(&self.f.data.bytes()[..PAGE]);
        Ok(())
    }

    fn write(&mut self, block: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), IoError> {
        if SUPERBLOCKS.contains(&block) && self.dirty > 0 {
            self.ordem_ok = false;
        }
        self.f.data.bytes_mut().ok_or(IoError::Io)?[..PAGE].copy_from_slice(buf);
        self.run(1, 0, block)?;
        self.dirty += 1;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.run(2, 0, 0)?;
        self.dirty = 0;
        Ok(())
    }
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
        .collect()
}

/// Formata, grava dois commits, remonta e confere. Devolve `None` em
/// qualquer divergência.
#[inline(never)]
pub fn run(f: &mut Fila, blocks: u64) -> Option<()> {
    let h = Sha;
    let mut io = QueueIo {
        f,
        blocks,
        id: 100,
        dirty: 0,
        ordem_ok: true,
    };
    let s1 = Superblock {
        uuid: [1; 16],
        txg: 1,
        integrity: Integrity::Hash,
        root: BlockPtr::null(),
        volume_blocks: blocks,
        epochs: 0,
        free_blocks: blocks,
    };
    io.write(SUPERBLOCKS[1], &s1.encode(&h)).ok()?;
    io.flush().ok()?;
    let want = pattern(6000, 3);
    let key = [7u8; 32];
    let mut al = Allocator::new(blocks);
    let (root2, sb2) = {
        let mut tx = Tx::new(&mut io, &h, &mut al, 2, 1);
        let mut fs = Fs::create(&mut tx, key).ok()?;
        let docs = fs.mkdir(&mut tx, 1, "docs").ok()?;
        let file = fs.create_file(&mut tx, docs, "nota.txt").ok()?;
        fs.write(&mut tx, file, 0, &want).ok()?;
        let mut new = s1;
        new.root = fs.root;
        new.free_blocks = tx.free_blocks();
        (fs.root, tx.commit(&s1, new).ok()?)
    };
    if !io.ordem_ok || io.dirty != 0 || sb2.txg != 2 {
        return None;
    }
    // Remonta: o superbloco de maior txg tem a raiz gravada, e o conteúdo
    // volta igual do disco.
    let m = mount(&mut io, &h).ok()?;
    if m.sb.txg != 2 || m.sb.root != root2 {
        return None;
    }
    let mut al = Allocator::new(blocks);
    let sb3 = {
        let mut tx = Tx::new(&mut io, &h, &mut al, 3, 1);
        let mut fs = Fs::from_root(m.sb.root, key);
        tx.mark_reachable(&[fs.root]).ok()?;
        let docs = fs.lookup(&mut tx, 1, "docs").ok()??.0;
        let file = fs.lookup(&mut tx, docs, "nota.txt").ok()??.0;
        if fs.read(&mut tx, file, 0, 6000).ok()? != want {
            return None;
        }
        // Segundo commit: sobrescreve o meio (copy-on-write).
        fs.write(&mut tx, file, 100, b"segundo txg").ok()?;
        let mut new = m.sb;
        new.root = fs.root;
        new.free_blocks = tx.free_blocks();
        tx.commit(&m.sb, new).ok()?
    };
    if !io.ordem_ok || io.dirty != 0 || sb3.txg != 3 {
        return None;
    }
    let m = mount(&mut io, &h).ok()?;
    let mut al = Allocator::new(blocks);
    let mut tx = Tx::new(&mut io, &h, &mut al, 4, 1);
    let fs = Fs::from_root(m.sb.root, key);
    let docs = fs.lookup(&mut tx, 1, "docs").ok()??.0;
    let file = fs.lookup(&mut tx, docs, "nota.txt").ok()??.0;
    let got = fs.read(&mut tx, file, 0, 6000).ok()?;
    let mut exp = want.clone();
    exp[100..111].copy_from_slice(b"segundo txg");
    (m.sb.txg == 3 && got == exp).then_some(())
}
