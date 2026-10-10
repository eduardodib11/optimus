//! Optimus Kernel (`okernel`).
//!
//! Esqueleto do M1: ligado na metade alta por `linker.ld` e carregado pelo
//! `optboot` (T-101). O salto para cá, com `BootInfo`, chega em T-102 e T-103.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

/// Número de entradas no kernel; fica no BSS e serve para o `optboot` exercitar
/// um segmento RW- com memória zerada além do arquivo.
static ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Ponto de entrada provisório do kernel, chamado pelo `optboot` a partir de T-103.
#[unsafe(no_mangle)]
pub extern "sysv64" fn kernel_entry() -> ! {
    ENTRIES.fetch_add(1, Ordering::Relaxed);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
