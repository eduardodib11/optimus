#![no_main]

use libfuzzer_sys::fuzz_target;
use optfs_format::{BlockPtr, Key, NodeHeader, Sha256, Superblock};

/// Resumo fraco de propósito: sem ele o fuzzer nunca passaria da conferência
/// do SHA-256 e os campos do superbloco ficariam sem teste.
struct Weak;
impl Sha256 for Weak {
    fn sha256(&self, _: &[u8]) -> [u8; 32] {
        [0; 32]
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = Superblock::decode(data, &Weak);
    let _ = BlockPtr::decode(data);
    let _ = NodeHeader::decode(data);
    let _ = Key::decode(data);
    // Um bloco inteiro com o fim zerado deixa o resumo fraco valer.
    let mut b = [0u8; 4096];
    let n = data.len().min(4096 - 64);
    b[..n].copy_from_slice(&data[..n]);
    if let Ok(sb) = Superblock::decode(&b, &Weak) {
        // O que se decodifica volta idêntico.
        let again = sb.encode(&Weak);
        assert_eq!(Superblock::decode(&again, &Weak), Ok(sb));
    }
});
