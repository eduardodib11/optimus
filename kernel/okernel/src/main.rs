//! Optimus Kernel (`okernel`).
//!
//! Esqueleto do M1: PIE ligado na metade alta por `linker.ld` e carregado pelo
//! `optboot` com KASLR (T-103). A entrada em assembly (`arch/x86_64/entry.S`)
//! troca de pilha e chama [`kernel_main`] (T-104), que carrega GDT, TSS e IDT
//! (T-105). Com `test=fault` na linha de comando, provoca um #UD de propósito;
//! com `test=kernel`, roda os testes de kernel ([`ktest`], T-111); com
//! `test=bench`, os benchmarks ([`kbench`], T-213); com `test=perfil`, os
//! de IPC e de troca em laço, para o `cargo xtask perfil` (T-331).

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod klog;
#[macro_use]
mod ktest;
mod arch;
mod bootinfo;
mod kbench;
mod kcap;
mod kfault;
mod kfuzz;
mod kheap;
mod kipc;
mod kirq;
mod kmem;
mod kpanic;
mod kroot;
mod ksmp;
mod ksync;
mod kthread;
mod ktime;
mod kvm;

use kabi::boot::{BootInfo, direct_map_base_valid};
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
    ksync::init();
    info!("okernel: GDT, TSS e IDT carregadas");
    if !info.is_valid() {
        error!("okernel: BootInfo inválida (magic {:#x})", info.magic);
        qemu_exit(QemuExit::Failure);
    }
    info!(
        "okernel: kaslr_slide {:#x}, kernel_main em {:p}",
        info.kaslr_slide, kernel_main as *const ()
    );
    let limit = bootinfo::memory_map(info).map_or(0, bootinfo::direct_map_limit);
    if !direct_map_base_valid(info.direct_map_base, limit) {
        error!(
            "okernel: base do mapa direto inválida: {:#x}",
            info.direct_map_base
        );
        qemu_exit(QemuExit::Failure);
    }
    kmem::set_direct_base(info.direct_map_base);
    info!("okernel: mapa direto em {:#x}", info.direct_map_base);
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
            ksmp::init(info, cmdline);
            ksmp::start::start_aps();
        }
        None => warn!("okernel: mapa de memória ausente ou inválido"),
    }
    match option(cmdline, "test") {
        Some("fault") => {
            warn!("okernel: test=fault, provocando #UD");
            arch::x86_64::trigger_invalid_opcode();
        }
        Some("kernel") => ktest::run(option(cmdline, "ktest")),
        Some("bench") => kbench::run(),
        Some("perfil") => kbench::profile(),
        Some("panic") => {
            // Com `smp.panic_cpu=N`, o pânico vem da CPU N (função remota),
            // e as outras, inclusive o BSP que espera, congelam pelo NMI.
            if let Some(cpu) = option(cmdline, "smp.panic_cpu").and_then(|c| c.parse().ok()) {
                ksmp::ipi::call_on(
                    cpu,
                    |_| panic!("pânico de teste proposital (test=panic)"),
                    0,
                );
            }
            panic!("pânico de teste proposital (test=panic)")
        }
        Some("fuzz") => kfuzz::run(cmdline),
        // Testes de usuário (T-332): o `utest` no lugar do `root`.
        Some("user") => kroot::run_named("utest"),
        _ => kroot::run(),
    }
    kheap::log_stats();
    info!("okernel: desligando");
    qemu_exit(QemuExit::Success)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    kpanic::handle(info)
}
