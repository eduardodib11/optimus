//! Afinidade de CPU e `sys_info` (ADR 0032, item 4; T-325).
//!
//! A máscara de afinidade é do `SchedContext`: `sched_configure` a recebe
//! em `r8`, como o endereço de usuário de uma [`CpuMask`] (alinhada a 8),
//! ou 0 para manter a atual. Com a doação de IPC, a máscara anda junto com
//! o tempo e a prioridade.

use crate::MAX_CPUS;

/// Palavras de 64 bits de uma [`CpuMask`].
pub const CPU_MASK_WORDS: usize = MAX_CPUS / 64;

/// Bytes de uma [`CpuMask`] na memória do usuário.
pub const CPU_MASK_BYTES: usize = CPU_MASK_WORDS * 8;

/// Conjunto de CPUs: bit `i` (palavra `i / 64`, bit `i % 64`) é a CPU de id
/// lógico `i` (ADR 0030).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CpuMask(pub [u64; CPU_MASK_WORDS]);

impl Default for CpuMask {
    fn default() -> Self {
        Self::ALL
    }
}

impl CpuMask {
    /// Todas as CPUs (a máscara de um `SchedContext` novo).
    pub const ALL: Self = Self([u64::MAX; CPU_MASK_WORDS]);
    /// Nenhuma CPU.
    pub const NONE: Self = Self([0; CPU_MASK_WORDS]);

    /// Só a CPU `cpu` (vazia se `cpu` passa de [`MAX_CPUS`]).
    #[must_use]
    pub const fn only(cpu: usize) -> Self {
        Self::NONE.with(cpu)
    }

    /// Esta máscara mais a CPU `cpu` (igual se `cpu` passa de [`MAX_CPUS`]).
    #[must_use]
    pub const fn with(mut self, cpu: usize) -> Self {
        if cpu < MAX_CPUS {
            self.0[cpu / 64] |= 1 << (cpu % 64);
        }
        self
    }

    /// A CPU `cpu` está na máscara.
    #[must_use]
    pub const fn contains(&self, cpu: usize) -> bool {
        cpu < MAX_CPUS && self.0[cpu / 64] & (1 << (cpu % 64)) != 0
    }

    /// Nenhuma CPU na máscara.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
    }

    /// CPUs nas duas máscaras.
    #[must_use]
    pub fn and(&self, other: &Self) -> Self {
        let mut out = *self;
        for (w, o) in out.0.iter_mut().zip(other.0) {
            *w &= o;
        }
        out
    }

    /// Lê a máscara dos [`CPU_MASK_BYTES`] bytes do usuário (little-endian).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; CPU_MASK_BYTES]) -> Self {
        let mut out = Self::NONE;
        for (w, chunk) in out.0.iter_mut().zip(bytes.chunks_exact(8)) {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            *w = u64::from_le_bytes(word);
        }
        out
    }
}

/// Seletor de `sys_info(seletor)` (em `rdi`): CPUs. Devolve as ligadas
/// (`rdx`), o total de ids lógicos da topologia (`r10`) e zero (`r8`).
/// Seletor desconhecido dá `NotSupported`.
pub const SYS_INFO_CPUS: u64 = 1;

/// Seletor de `sys_info(seletor, handle)`: registro de morte (ADR 0035,
/// item 2) da `Thread` (com `READ_STATE`) ou do processo do `CapSpace` (com
/// `MANAGE`) de `handle` (`rsi`): causa (`rdx`, zero se vivo), código (`r10`)
/// e auxiliar (`r8`); ver [`crate::exit`].
pub const SYS_INFO_EXIT: u64 = 2;

/// Seletor de `sys_info(seletor, 0)`: entropia (ADR 0039, item 4). Devolve
/// [`SYS_INFO_ENTROPY_BYTES`] bytes aleatórios criptográficos em `rdx`,
/// `r10` e `r8` (little-endian, nessa ordem), sem capability. O argumento
/// (`rsi`) tem de ser zero (senão `InvalidArgument`); sem semente de
/// entropia no boot, `NotSupported`.
pub const SYS_INFO_ENTROPY: u64 = 5;

/// Bytes de entropia por chamada de [`SYS_INFO_ENTROPY`] (três palavras).
pub const SYS_INFO_ENTROPY_BYTES: usize = 24;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mascara_por_cpu() {
        let m = CpuMask::only(3).with(64).with(255);
        assert!(m.contains(3) && m.contains(64) && m.contains(255));
        assert!(!m.contains(0) && !m.contains(65) && !m.contains(256));
        assert_eq!(m.0, [1 << 3, 1, 0, 1 << 63]);
        assert!(CpuMask::NONE.is_empty() && !m.is_empty());
        assert_eq!(CpuMask::only(MAX_CPUS), CpuMask::NONE);
        assert_eq!(CpuMask::default(), CpuMask::ALL);
        assert_eq!(m.and(&CpuMask::only(64)), CpuMask::only(64));
    }

    #[test]
    fn mascara_dos_bytes_do_usuario() {
        let mut bytes = [0u8; CPU_MASK_BYTES];
        bytes[0] = 0b101;
        bytes[8] = 1;
        bytes[31] = 0x80;
        assert_eq!(
            CpuMask::from_bytes(&bytes),
            CpuMask::only(0).with(2).with(64).with(255)
        );
    }
}
