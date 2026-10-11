//! Optimus Kernel (`okernel`).
//!
//! Esqueleto do M1: PIE ligado na metade alta por `linker.ld` e carregado pelo
//! `optboot` com KASLR (T-103). A entrada em assembly (`arch/x86_64/entry.S`)
//! troca de pilha e chama [`kernel_main`] (T-104), que carrega GDT, TSS e IDT
//! (T-105). Com `test=fault` na linha de comando, provoca um #UD de propósito;
//! com `test=kernel`, roda os testes de kernel ([`ktest`], T-111).

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod klog;
#[macro_use]
mod ktest;
mod arch;
mod bootinfo;
mod kcap;
mod kheap;
mod kmem;
mod kpanic;
mod kthread;
mod ktime;
mod kvm;

use kabi::boot::BootInfo;
use kabi::{SYSCALL_COUNT, Syscall};
use okernel::log::{Level, level_from_cmdline, option};

use arch::x86_64::{QemuExit, qemu_exit};

// Prova que a ABI compartilhada compila no kernel: a tabela de syscalls fecha.
const _: () = assert!(SYSCALL_COUNT == Syscall::ThreadExit as usize + 1);

/// Primeira função em Rust, chamada por `kernel_entry` já na pilha do kernel.
#[unsafe(no_mangle)]
extern "sysv64" fn kernel_main(info: &'static BootInfo) -> ! {
    let cmdline = info.cmdline().unwrap_or("");
    klog::init(level_from_cmdline(cmdline, Level::Info));
    info!("okernel: hello");
    // SAFETY: primeira e única chamada, no boot, com interrupções desligadas
    // (o optboot entrega assim e nada as ligou).
    unsafe { arch::x86_64::init() };
    info!("okernel: GDT, TSS e IDT carregadas");
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
    bootinfo::set(info);
    match bootinfo::memory_map(info) {
        Some(map) => {
            bootinfo::log_memory_map(map);
            kmem::init(map);
            kvm::init();
            kheap::init(cmdline);
            kcap::init();
            ktime::init(info);
        }
        None => warn!("okernel: mapa de memória ausente ou inválido"),
    }
    match option(cmdline, "test") {
        Some("fault") => {
            warn!("okernel: test=fault, provocando #UD");
            arch::x86_64::trigger_invalid_opcode();
        }
        Some("kernel") => ktest::run(option(cmdline, "ktest")),
        Some("panic") => panic!("pânico de teste proposital (test=panic)"),
        _ => {}
    }
    kheap::log_stats();
    info!("okernel: desligando");
    qemu_exit(QemuExit::Success)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    kpanic::handle(info)
}
