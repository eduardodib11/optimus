//! `virtio-core`: transporte virtio moderno (1.0+) sobre PCI (ADR 0046).
//!
//! A crate é `no_std`, sem alocação e sem `unsafe`. Quem mapeia o BAR e a
//! memória de DMA (o processo do driver) implementa [`Mmio`] e [`DmaBuf`];
//! aqui ficam a leitura das capabilities PCI ([`cap`]), a negociação de
//! features ([`Transport`]) e a fila split ([`Queue`]). O dispositivo não é
//! confiável: todo índice e tamanho que ele escreve é validado.

#![cfg_attr(not(any(test, feature = "fuzz")), no_std)]
#![forbid(unsafe_code)]
// Os casts truncam de propósito: N ≤ 32768 e as metades de endereços de 64 bits.
#![allow(clippy::cast_possible_truncation)]

pub mod cap;
mod queue;
mod transport;

pub use queue::{Chain, Queue, Seg};
pub use transport::{F_ACCESS_PLATFORM, F_VERSION_1, NO_VECTOR, Transport, status};

/// Acesso a registradores mapeados (BAR). Os `off` são relativos à região.
pub trait Mmio {
    /// Lê 8 bits.
    fn read8(&self, off: usize) -> u8;
    /// Lê 16 bits.
    fn read16(&self, off: usize) -> u16;
    /// Lê 32 bits.
    fn read32(&self, off: usize) -> u32;
    /// Escreve 8 bits.
    fn write8(&self, off: usize, v: u8);
    /// Escreve 16 bits.
    fn write16(&self, off: usize, v: u16);
    /// Escreve 32 bits.
    fn write32(&self, off: usize, v: u32);
}

/// Região de memória compartilhada com o dispositivo (um `DmaDomain`).
///
/// Os acessos são little-endian e alinhados; o chamador de `Queue` garante
/// que `off` está dentro de `len()`. `barrier` é uma barreira de memória
/// completa entre a escrita dos dados e a publicação do índice, e entre a
/// leitura do índice e a leitura dos dados.
#[allow(clippy::len_without_is_empty)]
pub trait DmaBuf {
    /// Tamanho da região, em bytes.
    fn len(&self) -> usize;
    /// Endereço que o dispositivo usa para o byte 0.
    fn device_addr(&self) -> u64;
    /// Lê 16 bits em `off`.
    fn read16(&self, off: usize) -> u16;
    /// Lê 32 bits em `off`.
    fn read32(&self, off: usize) -> u32;
    /// Escreve 16 bits em `off`.
    fn write16(&self, off: usize, v: u16);
    /// Escreve 32 bits em `off`.
    fn write32(&self, off: usize, v: u32);
    /// Escreve 64 bits em `off`.
    fn write64(&self, off: usize, v: u64);
    /// Barreira de memória completa.
    fn barrier(&self);
}

/// Erros do transporte e das filas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// O dispositivo não oferece `VIRTIO_F_VERSION_1` (só legacy).
    NoVersion1,
    /// O dispositivo recusou o conjunto de features (`FEATURES_OK` caiu).
    FeaturesRejected,
    /// O dispositivo não zerou o status no reset a tempo.
    ResetTimeout,
    /// A fila não existe (tamanho máximo zero) ou o tamanho não serve.
    BadQueue,
    /// A região de DMA é pequena demais para a fila.
    DmaTooSmall,
    /// Não há descritores livres.
    Full,
    /// Cadeia vazia ou maior que a fila.
    BadChain,
    /// O dispositivo devolveu um id inválido, repetido ou um `len` impossível.
    DeviceMisbehaved,
    /// O dispositivo não aceitou o vetor MSI-X.
    NoVector,
    /// Capability PCI malformada.
    BadCap,
}

#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz;

#[cfg(test)]
mod tests;
