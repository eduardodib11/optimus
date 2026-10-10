//! Gerência de memória (SDD v1.0, seção 6.3).

#![forbid(unsafe_code)]

pub mod buddy;
pub mod frames;
pub mod paging;

/// Tamanho de um frame de memória física: 4 KiB.
pub const FRAME_SIZE: u64 = 4096;

/// Endereço físico. Tipo próprio para não misturar com endereços virtuais (seção 17.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysAddr(pub u64);

impl PhysAddr {
    /// O endereço como inteiro.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}
