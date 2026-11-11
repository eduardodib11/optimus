//! `IoPortRange` (tipo 10; ADR 0049): uma faixa de portas de E/S do x86
//! que a thread liga com `thread_configure(CONFIGURE_IO_PORTS)` e usa
//! direto com `in`/`out`, pelo mapa de E/S da TSS.

#![forbid(unsafe_code)]

use alloc::sync::Arc;

use kabi::Error;

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota};

/// Portas que o kernel usa (ADR 0049, item 1): PIC, PIT, COM1 do registro
/// do kernel, reset e a saída do QEMU. Faixas `(base, quantidade)`.
pub const RESERVED: [(u16, u16); 6] = [
    (0x20, 2),
    (0xa0, 2),
    (0x40, 4),
    (0x3f8, 8),
    (0xcf9, 1),
    (0xf4, 1),
];

/// Faixa de portas `base..base + count`.
pub struct IoPortRange {
    _charge: Charge,
    base: u16,
    count: u16,
}

impl core::fmt::Debug for IoPortRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IoPortRange({:#x}+{})", self.base, self.count)
    }
}

/// A faixa cabe no espaço de E/S e não toca as portas do kernel.
#[must_use]
pub fn range_ok(base: u64, count: u64) -> bool {
    let end = base.saturating_add(count);
    count != 0
        && end <= 0x1_0000
        && RESERVED.iter().all(|&(b, n)| {
            let (b, e) = (u64::from(b), u64::from(b) + u64::from(n));
            end <= b || base >= e
        })
}

impl IoPortRange {
    /// Cria a faixa, cobrada de `quota`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] fora de [`range_ok`] (ou com mais de
    /// 65535 portas); [`Error::QuotaExceeded`] sem cota.
    pub fn new(quota: &Arc<MemoryQuota>, base: u64, count: u64) -> Result<Self, Error> {
        if !range_ok(base, count) {
            return Err(Error::InvalidArgument);
        }
        let base = u16::try_from(base).map_err(|_| Error::InvalidArgument)?;
        let count = u16::try_from(count).map_err(|_| Error::InvalidArgument)?;
        Ok(Self {
            _charge: quota.charge(object_bytes::<Self>())?,
            base,
            count,
        })
    }

    /// Primeira porta.
    #[must_use]
    pub const fn base(&self) -> u16 {
        self.base
    }

    /// Quantidade de portas.
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// `base << 16 | count`, como a troca de contexto a guarda.
    #[must_use]
    pub const fn packed(&self) -> u32 {
        (self.base as u32) << 16 | self.count as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faixas_do_kernel_sao_recusadas() {
        assert!(range_ok(0x60, 1) && range_ok(0x64, 1) && range_ok(0x70, 2));
        assert!(range_ok(0xcf8, 1) && range_ok(0xcfc, 4) && range_ok(0xffff, 1));
        for (b, n) in [(0x20, 1), (0x1f, 2), (0x43, 1), (0x3f0, 9), (0xcf8, 8)] {
            assert!(!range_ok(b, n), "{b:#x}+{n}");
        }
        assert!(!range_ok(0x70, 0) && !range_ok(0xffff, 2) && !range_ok(u64::MAX, 2));
        assert!(range_ok(0x1000, 0xffff - 0x1000));
    }
}
