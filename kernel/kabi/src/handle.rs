//! Handles de capability: índice de 24 bits + geração de 8 bits (seção 6.2).

use crate::UnknownValue;

/// Referência a um slot do `CapSpace` do processo.
///
/// Layout em `u32`: índice nos 24 bits baixos e geração nos 8 bits altos
/// (definido aqui, o SDD não fixa a posição dos campos). A geração evita que um
/// handle antigo acerte um slot reutilizado.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Handle(u32);

impl Handle {
    /// Bits do índice do slot.
    pub const INDEX_BITS: u32 = 24;
    /// Bits da geração.
    pub const GENERATION_BITS: u32 = 8;
    /// Maior índice representável.
    pub const MAX_INDEX: u32 = (1 << Self::INDEX_BITS) - 1;

    /// Monta um handle; `None` se `index` não couber em 24 bits.
    #[must_use]
    pub const fn new(index: u32, generation: u8) -> Option<Self> {
        if index > Self::MAX_INDEX {
            return None;
        }
        Some(Self(index | ((generation as u32) << Self::INDEX_BITS)))
    }

    /// Reinterpreta os 32 bits crus; todo `u32` é um handle bem formado.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Os 32 bits crus.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Índice do slot no `CapSpace`.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0 & Self::MAX_INDEX
    }

    /// Geração do slot.
    #[must_use]
    pub const fn generation(self) -> u8 {
        (self.0 >> Self::INDEX_BITS) as u8
    }
}

/// Dois handles num registrador: `low` nos 32 bits baixos e `high` nos
/// altos (a entrada do `root`, ADR 0029; o alvo de `ipc_recv` usa o mesmo
/// arranjo).
#[must_use]
pub const fn handle_pair(low: Handle, high: Handle) -> u64 {
    low.0 as u64 | ((high.0 as u64) << 32)
}

/// Desfaz [`handle_pair`]: `(low, high)`.
#[must_use]
pub const fn split_handle_pair(raw: u64) -> (Handle, Handle) {
    #[allow(clippy::cast_possible_truncation, reason = "metades de 32 bits")]
    (Handle(raw as u32), Handle((raw >> 32) as u32))
}

impl TryFrom<u64> for Handle {
    type Error = UnknownValue;

    /// Recusa valores de registrador com bits acima dos 32 baixos.
    fn try_from(raw: u64) -> Result<Self, UnknownValue> {
        u32::try_from(raw).map(Self).map_err(|_| UnknownValue(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn campos_e_layout() {
        let h = Handle::new(0x12_3456, 0xAB).unwrap();
        assert_eq!((h.index(), h.generation()), (0x12_3456, 0xAB));
        assert_eq!(h.raw(), 0xAB12_3456);
        assert_eq!(Handle::from_raw(h.raw()), h);
        let max = Handle::new(Handle::MAX_INDEX, u8::MAX).unwrap();
        assert_eq!(max.raw(), u32::MAX);
        assert_eq!(Handle::new(1 << 24, 0), None);
    }

    #[test]
    fn conversao_de_registrador() {
        assert_eq!(
            Handle::try_from(0xAB12_3456),
            Ok(Handle::from_raw(0xAB12_3456))
        );
        assert_eq!(Handle::try_from(1 << 32), Err(UnknownValue(1 << 32)));
        assert!(Handle::try_from(u64::MAX).is_err());
    }

    #[test]
    fn par_de_handles() {
        let (a, b) = (Handle::new(5, 1).unwrap(), Handle::new(9, 2).unwrap());
        assert_eq!(handle_pair(a, b), 0x0200_0009_0100_0005);
        assert_eq!(split_handle_pair(handle_pair(a, b)), (a, b));
    }
}
