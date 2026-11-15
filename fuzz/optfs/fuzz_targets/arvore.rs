#![no_main]

use libfuzzer_sys::fuzz_target;
use optfs::{Allocator, BlockIo, Fs, IoError, Tx};
use optfs_format::{BLOCK_SIZE, BlockPtr, Compression, Integrity, Key, KeyKind, NodeHeader, PtrKind, Sha256};

/// Resumo fraco (ver o alvo `superbloco`): com `auth` zerado todo bloco confere
/// e o fuzzer chega ao código que lê nós, itens e snapshots.
struct Weak;
impl Sha256 for Weak {
    fn sha256(&self, _: &[u8]) -> [u8; 32] {
        [0; 32]
    }
}

/// Disco de 64 blocos feito da entrada, em ciclo; só leitura.
struct Fuzzed<'a> {
    data: &'a [u8],
}

impl BlockIo for Fuzzed<'_> {
    fn blocks(&self) -> u64 {
        64
    }
    fn read(&mut self, b: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), IoError> {
        if b >= 64 || self.data.is_empty() {
            return Err(IoError::Io);
        }
        let start = usize::try_from(b).unwrap_or(0) * BLOCK_SIZE;
        for (i, x) in buf.iter_mut().enumerate() {
            *x = self.data[(start + i) % self.data.len()];
        }
        Ok(())
    }
    fn write(&mut self, _: u64, _: &[u8; BLOCK_SIZE]) -> Result<(), IoError> {
        Ok(())
    }
    fn flush(&mut self) -> Result<(), IoError> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut io = Fuzzed { data };
    let mut blk = [0u8; BLOCK_SIZE];
    if io.read(16, &mut blk).is_err() {
        return;
    }
    // A raiz é o bloco 16 e o ponteiro vem do cabeçalho dele: nível, txg e
    // árvore combinam, então a leitura vai além da conferência do pai.
    let Ok(hd) = NodeHeader::decode(&blk) else { return };
    let root = BlockPtr {
        addr: 16,
        birth: hd.txg,
        logical: 4096,
        physical: 4096,
        level: hd.level,
        kind: PtrKind::Node,
        compression: Compression::None,
        integrity: Integrity::Hash,
        nonce: [0; 12],
        auth: [0; 32],
    };
    let mut al = Allocator::new(64);
    let mut tx = Tx::new(&mut io, &Weak, &mut al, hd.txg.saturating_add(1), hd.tree);
    let fs = Fs::from_root(root, [0; 32]);
    let _ = fs.snapshots(&mut tx);
    let _ = fs.readdir(&mut tx, 1);
    let _ = fs.stat(&mut tx, 1);
    let _ = fs.lookup(&mut tx, 1, "a");
    let _ = fs.read(&mut tx, 2, 0, 10_000);
    let mut at = Key { object: 0, kind: KeyKind::Inode, offset: 0 };
    for _ in 0..64 {
        match tx.first_ge(&root, &at) {
            Ok(Some((k, _))) if k.offset < u64::MAX => at = Key { offset: k.offset + 1, ..k },
            _ => break,
        }
    }
    let _ = tx.mark_reachable(&[root]);
});
