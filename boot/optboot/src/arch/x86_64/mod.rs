//! Instruções x86-64 que o `optboot` usa: entropia por hardware e TSC.

use core::arch::asm;
use core::arch::x86_64::{__cpuid, __cpuid_count};

/// Tentativas antes de desistir do RDRAND/RDSEED (a Intel recomenda 10).
const RETRIES: u32 = 10;

/// A CPU tem RDSEED (CPUID.07H:EBX\[18\]).
fn has_rdseed() -> bool {
    __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0
}

/// A CPU tem RDRAND (CPUID.01H:ECX\[30\]).
fn has_rdrand() -> bool {
    __cpuid(1).ecx & (1 << 30) != 0
}

/// Uma palavra de RDSEED, se a instrução existir e entregar.
fn rdseed() -> Option<u64> {
    for _ in 0..RETRIES {
        let (value, ok): (u64, u8);
        // SAFETY: só chamada depois de `has_rdseed`; RDSEED escreve um
        // registrador e o CF, sem acessar memória.
        unsafe {
            asm!("rdseed {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok,
                 options(nomem, nostack));
        }
        if ok == 1 {
            return Some(value);
        }
    }
    None
}

/// Uma palavra de RDRAND, se a instrução existir e entregar.
fn rdrand() -> Option<u64> {
    for _ in 0..RETRIES {
        let (value, ok): (u64, u8);
        // SAFETY: só chamada depois de `has_rdrand`; RDRAND escreve um
        // registrador e o CF, sem acessar memória.
        unsafe {
            asm!("rdrand {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok,
                 options(nomem, nostack));
        }
        if ok == 1 {
            return Some(value);
        }
    }
    None
}

/// Fonte de entropia por hardware usada.
#[derive(Clone, Copy, Debug)]
pub enum HwRng {
    /// RDSEED: saída direta do condicionador de entropia.
    Rdseed,
    /// RDRAND: saída do DRBG da CPU.
    Rdrand,
}

/// Preenche `buf` com RDSEED ou, na falta dele, RDRAND.
pub fn hw_random(buf: &mut [u8]) -> Option<HwRng> {
    let (source, next): (HwRng, fn() -> Option<u64>) = if has_rdseed() && rdseed().is_some() {
        (HwRng::Rdseed, rdseed)
    } else if has_rdrand() {
        (HwRng::Rdrand, rdrand)
    } else {
        return None;
    };
    for chunk in buf.chunks_mut(8) {
        let word = next()?.to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    Some(source)
}

/// Contador de ciclos do processador.
pub fn rdtsc() -> u64 {
    // SAFETY: RDTSC só lê o contador de tempo, sem efeito colateral; o
    // optboot roda no anel 0, onde CR4.TSD não bloqueia a instrução.
    unsafe { core::arch::x86_64::_rdtsc() }
}
