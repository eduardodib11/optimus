//! Aleatoriedade (ADR 0039, item 4).
//!
//! Por ora só a entropia do kernel: [`secure_fill`] pede à `sys_info` de
//! entropia (classe 5, [`kabi::sched::SYS_INFO_ENTROPY`]) pedaços de
//! [`kabi::sched::SYS_INFO_ENTROPY_BYTES`] bytes, para chaves e nonces. Não
//! é gerador de volume: o consumo grande usa um DRBG de usuário semeado por
//! ele. O PRNG rápido por thread (`fast`) e a mistura de reserva com
//! `is_degraded` quando o kernel recusa ficam para depois (T-337, parte do
//! `ostd`).

use kabi::Error;
use kabi::Syscall;
use kabi::sched::{SYS_INFO_ENTROPY, SYS_INFO_ENTROPY_BYTES};

use crate::sys::syscall;

/// Enche `buf` com bytes aleatórios criptográficos do kernel.
///
/// # Errors
///
/// `NotSupported` se o kernel não tem entropia (o `optboot` não achou
/// fonte); `buf` pode ter sido preenchido em parte.
pub fn secure_fill(buf: &mut [u8]) -> Result<(), Error> {
    for chunk in buf.chunks_mut(SYS_INFO_ENTROPY_BYTES) {
        let words = syscall(Syscall::SysInfo, [SYS_INFO_ENTROPY, 0, 0, 0, 0, 0])?;
        let mut bytes = [0u8; SYS_INFO_ENTROPY_BYTES];
        for (dst, w) in bytes.chunks_exact_mut(8).zip(words) {
            dst.copy_from_slice(&w.to_le_bytes());
        }
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    Ok(())
}
