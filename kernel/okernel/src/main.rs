//! Optimus Kernel (`okernel`).
//!
//! Esqueleto do M0: só garante que a crate compila para o alvo do kernel.
//! A entrada real, vinda do `optboot` com `BootInfo`, chega no M1 (T-101 a T-104).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use kabi::{SYSCALL_COUNT, Syscall};

// Prova que a ABI compartilhada compila no kernel: a tabela de syscalls fecha.
const _: () = assert!(SYSCALL_COUNT == Syscall::ThreadExit as usize + 1);

/// Ponto de entrada provisório do kernel.
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
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
