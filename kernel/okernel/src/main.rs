//! Optimus Kernel (`okernel`).
//!
//! Esqueleto do M1: PIE ligado na metade alta por `linker.ld` e carregado pelo
//! `optboot` com KASLR (T-103). A entrada em assembly (`arch/x86_64/entry.S`)
//! troca de pilha e chama [`kernel_main`] (T-104).

#![no_std]
#![no_main]

#[macro_use]
mod klog;
mod arch;

use core::panic::PanicInfo;

use kabi::boot::{BootInfo, MemKind, MemRegion};
use kabi::{SYSCALL_COUNT, Syscall};
use okernel::log::{Level, level_from_cmdline};

use arch::x86_64::{QemuExit, qemu_exit};

// Prova que a ABI compartilhada compila no kernel: a tabela de syscalls fecha.
const _: () = assert!(SYSCALL_COUNT == Syscall::ThreadExit as usize + 1);

/// Teto de faixas aceitas no mapa de memória, contra um `BootInfo` corrompido.
const MAX_REGIONS: u64 = 4096;

/// Mapa de memória da `BootInfo`, se o ponteiro e o tamanho forem plausíveis.
fn memory_map(info: &BootInfo) -> Option<&'static [MemRegion]> {
    let ptr = info.memory_map;
    let len = usize::try_from(info.memory_map_len).ok()?;
    if ptr.is_null() || !ptr.is_aligned() || info.memory_map_len > MAX_REGIONS {
        return None;
    }
    // SAFETY: o optboot (T-103) grava `memory_map_len` faixas num vetor
    // próprio, de tipo Kernel no mapa, apontado pelo mapa direto; nada mais
    // escreve nessa memória.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Imprime o mapa de memória recebido (aceite do T-102).
fn log_memory_map(map: &[MemRegion]) {
    info!("okernel: mapa de memória com {} faixas", map.len());
    for r in map {
        info!(
            "okernel:   {:#014x}-{:#014x} {:?} ({} KiB)",
            r.base,
            r.end(),
            r.kind(),
            r.len >> 10
        );
    }
    let usable: u64 = map
        .iter()
        .filter(|r| r.kind() == MemKind::Usable)
        .map(|r| r.len)
        .sum();
    info!("okernel: {} KiB usáveis", usable >> 10);
}

/// Primeira função em Rust, chamada por `kernel_entry` já na pilha do kernel.
#[unsafe(no_mangle)]
extern "sysv64" fn kernel_main(info: &'static BootInfo) -> ! {
    let cmdline = info.cmdline().unwrap_or("");
    klog::init(level_from_cmdline(cmdline, Level::Info));
    info!("okernel: hello");
    if !info.is_valid() {
        error!("okernel: BootInfo inválida (magic {:#x})", info.magic);
        qemu_exit(QemuExit::Failure);
    }
    info!(
        "okernel: kaslr_slide {:#x}, kernel_main em {:p}",
        info.kaslr_slide, kernel_main as *const ()
    );
    debug!(
        "okernel: cmdline \"{cmdline}\", boot em {} ns",
        info.boot_time_ns
    );
    trace!("okernel: BootInfo em {:p}", info);
    match memory_map(info) {
        Some(map) => log_memory_map(map),
        None => warn!("okernel: mapa de memória ausente ou inválido"),
    }
    info!("okernel: desligando");
    qemu_exit(QemuExit::Success)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    klog::emergency(format_args!("okernel: PÂNICO: {info}"));
    qemu_exit(QemuExit::Failure)
}
