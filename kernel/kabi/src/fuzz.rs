//! Convenção do `test=fuzz` entre o kernel e o `okfuzz` (T-214), fora da
//! ABI v1, como [`DEBUG_PRINT`](crate::DEBUG_PRINT): só vale para o fuzzer de
//! syscalls que o kernel inicia no lugar do `root`.
//!
//! O kernel cria o processo com duas threads: a principal recebe a cota
//! raiz em `rdi`, o próprio `AddressSpace` em `rsi` e a [`Config`] em
//! `rdx`; a auxiliar recebe zero em `rdi` e `rsi` e a mesma configuração.
//! O buffer de IPC de cada thread é uma página que o próprio kernel mapeia
//! no espaço do processo ([`BUFFER_MAIN`] e [`BUFFER_WORKER`]); o `okfuzz`
//! nem precisa tocá-lo.

/// Endereço do buffer de IPC da thread principal (mapeado pelo kernel).
pub const BUFFER_MAIN: u64 = 0x5000_0000;
/// Endereço do buffer de IPC da thread auxiliar.
pub const BUFFER_WORKER: u64 = 0x5000_1000;

/// Bits da semente em [`Config`].
pub const SEED_BITS: u32 = 48;

/// Semente e duração da rodada, num registrador.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Semente do gerador (só os [`SEED_BITS`] baixos).
    pub seed: u64,
    /// Duração em segundos.
    pub seconds: u16,
}

impl Config {
    /// Valor de `rdx`: a semente nos 48 bits baixos, os segundos nos altos.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        (self.seed & ((1 << SEED_BITS) - 1)) | ((self.seconds as u64) << SEED_BITS)
    }

    /// Desfaz [`to_raw`](Self::to_raw).
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        #[allow(clippy::cast_possible_truncation, reason = "16 bits altos")]
        let seconds = (raw >> SEED_BITS) as u16;
        Self {
            seed: raw & ((1 << SEED_BITS) - 1),
            seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_ida_e_volta() {
        let c = Config {
            seed: 0x1234_5678_9abc,
            seconds: 14_400,
        };
        assert_eq!(Config::from_raw(c.to_raw()), c);
        let cut = Config {
            seed: u64::MAX,
            seconds: 1,
        };
        assert_eq!(Config::from_raw(cut.to_raw()).seed, (1 << SEED_BITS) - 1);
        assert!(BUFFER_MAIN.is_multiple_of(4096) && BUFFER_WORKER == BUFFER_MAIN + 4096);
    }
}
