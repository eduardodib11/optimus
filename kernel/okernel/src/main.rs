//! Optimus Kernel (`okernel`).
//!
//! Esqueleto do M1: PIE ligado na metade alta por `linker.ld`, carregado pelo
//! `optboot` com KASLR e chamado em `kernel_entry(&BootInfo)` (T-103).

#![no_std]
#![no_main]

mod arch;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

use kabi::boot::BootInfo;
use kabi::{SYSCALL_COUNT, Syscall};

use arch::x86_64::{QemuExit, halt, qemu_exit};

// Prova que a ABI compartilhada compila no kernel: a tabela de syscalls fecha.
const _: () = assert!(SYSCALL_COUNT == Syscall::ThreadExit as usize + 1);

/// Número de entradas no kernel; fica no BSS e serve para o `optboot` exercitar
/// um segmento RW- com memória zerada além do arquivo.
static ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Ponto de entrada do kernel, chamado pelo `optboot` com interrupções
/// desligadas e `info` no mapa direto.
///
/// Por ora só confere a `BootInfo` e desliga o QEMU com sucesso ou falha.
#[unsafe(no_mangle)]
pub extern "sysv64" fn kernel_entry(info: &'static BootInfo) -> ! {
    ENTRIES.fetch_add(1, Ordering::Relaxed);
    if info.is_valid() && ENTRIES.load(Ordering::Relaxed) == 1 {
        qemu_exit(QemuExit::Success)
    }
    qemu_exit(QemuExit::Failure)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt()
}
