//! `optfs-format`: o formato em disco do `OptFS` (ADR 0052, T-523).
//!
//! Só estruturas e constantes, sem E/S e sem alocação: ponteiro de bloco
//! de 72 bytes, superbloco, cabeçalho de nó e chave das árvores. Todo
//! decodificador trata o disco como não confiável e devolve um erro, nunca
//! entra em pânico. O layout em bytes está em `docs/spec/optfs.md`.
//!
//! O SHA-256 do superbloco vem de fora, pelo trait [`Sha256`], para esta
//! crate não depender do `optcrypt` (que ganha o SHA-256 na T-526).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod node;
mod ptr;
mod sb;

pub use node::{Key, KeyKind, NodeHeader};
pub use ptr::{BlockPtr, Compression, Integrity, PtrKind};
pub use sb::{SB_HMAC_OFFSET, SB_SHA_OFFSET, Superblock};

/// Bytes de um bloco.
pub const BLOCK_SIZE: usize = 4096;
/// Bytes de um ponteiro de bloco.
pub const PTR_LEN: usize = 72;
/// Bytes do cabeçalho de um nó.
pub const NODE_HEADER_LEN: usize = 64;
/// Maior extent lógico (128 KiB).
pub const MAX_EXTENT: u32 = 128 * 1024;
/// Bloco do cabeçalho do volume; a cópia fica no último bloco.
pub const HEADER_BLOCK: u64 = 0;
/// Blocos dos superblocos A e B (o txg `t` vai em `SUPERBLOCKS[t % 2]`).
pub const SUPERBLOCKS: [u64; 2] = [2, 3];
/// Primeiro bloco alocável (1 e 4 a 15 são reservados).
pub const FIRST_ALLOC: u64 = 16;
/// Blocos de um grupo de alocação (128 MiB).
pub const GROUP_BLOCKS: u64 = 32_768;

/// Motivo de um bloco ou campo ser recusado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Tamanho de buffer errado.
    BadLen,
    /// `magic` diferente do esperado.
    BadMagic,
    /// Versão do formato desconhecida.
    BadVersion,
    /// Campo reservado diferente de zero.
    Reserved,
    /// Valor fora do domínio (tipo, compressão, tamanhos, contagens).
    BadField,
    /// O SHA-256 gravado não confere.
    BadChecksum,
}

/// SHA-256, fornecido por quem usa a crate (`optcrypt`, a partir da T-526).
pub trait Sha256 {
    /// Resumo SHA-256 de `data`.
    fn sha256(&self, data: &[u8]) -> [u8; 32];
}

pub(crate) fn rd_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
pub(crate) fn rd_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]))
}
pub(crate) fn rd_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}
pub(crate) fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}

#[cfg(test)]
mod tests;
