//! SYSCALL/SYSRET, área por CPU (GS) e troca de contexto (T-206).
//!
//! O asm fica em `syscall.S`; aqui ficam os MSRs, a `PerCpu` e as
//! declarações que o resto do kernel usa.

use core::sync::atomic::{AtomicU64, Ordering};

use super::cpu::{self, rdmsr, wrmsr};
use super::gdt::{self, KERNEL_CODE, SYSRET_BASE};

const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_FMASK: u32 = 0xc000_0084;
const MSR_GS_BASE: u32 = 0xc000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;
const EFER_SCE: u64 = 1;

/// RFLAGS limpos na entrada: TF, IF, DF, IOPL, NT e AC (o kernel roda sem
/// interrupções e sem acesso implícito ao usuário).
const FMASK: u64 = 0x4_7700;

/// RFLAGS.IF.
pub const RFLAGS_IF: u64 = 1 << 9;
/// Bits de RFLAGS que o usuário controla (CF, PF, AF, ZF, SF, DF, OF, AC);
/// o resto (IOPL, NT, RF, VM, TF...) volta sempre limpo.
const RFLAGS_USER: u64 = 0x4_0cd5;
/// Bit 1 de RFLAGS, sempre um.
const RFLAGS_FIXED: u64 = 1 << 1;

/// Área por CPU apontada por GS no kernel; os deslocamentos são os de
/// `syscall.S`.
#[repr(C)]
struct PerCpu {
    this: AtomicU64,
    /// Topo da pilha de kernel da thread atual (gs:[8]).
    kernel_rsp: AtomicU64,
    /// Rascunho do rsp do usuário na entrada (gs:[16]).
    user_rsp: AtomicU64,
}

static PERCPU: PerCpu = PerCpu {
    this: AtomicU64::new(0),
    kernel_rsp: AtomicU64::new(0),
    user_rsp: AtomicU64::new(0),
};

unsafe extern "C" {
    fn syscall_entry();
    /// Troca de pilha de kernel (ver `syscall.S`).
    pub fn switch_context(save_rsp: *mut u64, next_rsp: u64);
    /// Retorno da primeira troca para uma thread nova.
    pub fn thread_trampoline();
}

/// Liga SYSCALL/SYSRET e a área por CPU.
///
/// # Safety
///
/// Uma vez, no boot, depois de [`gdt::init`] e com interrupções desligadas.
pub unsafe fn init() {
    let percpu = (&raw const PERCPU).addr() as u64;
    PERCPU.this.store(percpu, Ordering::Relaxed);
    let star = (u64::from(SYSRET_BASE) << 48) | (u64::from(KERNEL_CODE) << 32);
    // SAFETY: MSRs arquiteturais de toda CPU x86-64; STAR casa com a GDT
    // (kernel em 0x08/0x10, usuário em 0x23/0x2b), LSTAR é a entrada em
    // `syscall.S` e GS passa a apontar a área por CPU, como o asm espera.
    unsafe {
        wrmsr(cpu::MSR_EFER, rdmsr(cpu::MSR_EFER) | EFER_SCE);
        wrmsr(MSR_STAR, star);
        wrmsr(MSR_LSTAR, (syscall_entry as *const ()).addr() as u64);
        wrmsr(MSR_FMASK, FMASK);
        wrmsr(MSR_GS_BASE, percpu);
        wrmsr(MSR_KERNEL_GS_BASE, 0);
    }
}

/// Pilha de kernel para entradas vindas do anel 3 (SYSCALL e interrupções).
///
/// # Safety
///
/// Com interrupções desligadas; `top` é o topo da pilha de kernel mapeada
/// da thread que vai rodar.
pub unsafe fn set_kernel_stack(top: u64) {
    PERCPU.kernel_rsp.store(top, Ordering::Relaxed);
    // SAFETY: contrato acima.
    unsafe { gdt::set_kernel_stack(top) };
}

/// RFLAGS que pode voltar ao usuário: só os bits dele, com IF ligado.
#[must_use]
pub const fn user_rflags(rflags: u64) -> u64 {
    (rflags & RFLAGS_USER) | RFLAGS_IF | RFLAGS_FIXED
}

/// Pode voltar por SYSRET: RIP canônico na metade de usuário e seletores
/// de usuário. Senão, volta por IRETQ (que dá #GP no anel 3, não no 0).
#[must_use]
pub fn sysret_ok(rip: u64, cs: u64, ss: u64) -> bool {
    rip < kabi::vm::USER_END && cs == u64::from(gdt::USER_CODE) && ss == u64::from(gdt::USER_DATA)
}
