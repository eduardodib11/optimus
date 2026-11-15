//! `optfs`: núcleo do sistema de arquivos `OptFS` (ADR 0052; T-522 a T-524).
//!
//! Esta etapa traz as três peças em que a integridade se apoia, todas
//! genéricas sobre um [`BlockIo`] (o `BlockStore` do `storaged` entra pelo
//! mesmo trait) e testáveis no host com um disco que perde a escrita não
//! descarregada na queda:
//!
//! - [`commit`]: a ordem do commit (escritas, `flush`, superbloco, `flush`);
//! - [`mount`]: a escolha do superbloco válido de maior txg;
//! - [`Allocator`]: o alocador, que só reusa um bloco liberado no txg `N`
//!   depois que o `N + 1` foi confirmado.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod alloc_map;
mod crypt;
mod fs;
mod io;
mod tree;
mod txg;

pub use alloc_map::Allocator;
pub use crypt::{BlockCipher, VolumeCipher};
pub use fs::{Fs, FsError, Inode, ObjKind, Snap};
pub use io::{BlockIo, IoError};
pub use tree::{MAX_VALUE, Tx};
pub use txg::{Mounted, commit, mount};

#[cfg(test)]
mod sim;
#[cfg(test)]
mod tests;
