//! Registradores de controle que todas as CPUs têm iguais (ADR 0030, item
//! 4, passo 2; T-319).
//!
//! O BSP grava, antes de ligar os APs, os valores finais de CR0, CR4, EFER,
//! XCR0, PAT e `TSC_ADJUST` ([`capture`]); cada AP confere que tem todos os
//! recursos que esses valores ligam e os copia ([`apply`]). A CPU que não tiver um
//! recurso que o BSP ligou, ou que pedir área de XSAVE de outro tamanho,
//! fica fora em vez de rodar com proteção menor.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::cpu::{self, rdmsr, wrmsr};
use super::fpu;

const MSR_PAT: u32 = 0x277;
const MSR_TSC_AUX: u32 = 0xc000_0103;
const MSR_TSC_ADJUST: u32 = 0x3b;

const EFER_SCE: u64 = 1;
const CR4_PGE: u64 = 1 << 7;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXSAVE: u64 = 1 << 18;

/// CR0, CR4, EFER, XCR0 e PAT do BSP.
static STATE: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
/// `IA32_TSC_ADJUST` do BSP, se ele o tiver.
static TSC_ADJUST: AtomicU64 = AtomicU64::new(0);
static BSP_HAS_TSC_ADJUST: AtomicBool = AtomicBool::new(false);

/// Bits de CR4 que dependem de um recurso anunciado: bit, folha, registrador
/// (0 = EBX, 1 = ECX, 2 = EDX) e bit do CPUID.
const CR4_FEATURES: [(u64, u32, u8, u32, &str); 6] = [
    (CR4_PGE, 1, 2, 13, "PGE"),
    (CR4_OSFXSR, 1, 2, 24, "FXSR"),
    (CR4_OSXSAVE, 1, 1, 26, "XSAVE"),
    (cpu::CR4_UMIP, 7, 1, 2, "UMIP"),
    (cpu::CR4_SMEP, 7, 0, 7, "SMEP"),
    (cpu::CR4_SMAP, 7, 0, 20, "SMAP"),
];

/// Grava o estado do BSP para os APs (depois de `kmem::init` e
/// `fpu::init`, que ligam as proteções e a FPU).
pub fn capture() {
    // SAFETY: EFER e PAT existem em toda CPU x86-64.
    let (efer, pat) = unsafe { (rdmsr(cpu::MSR_EFER), rdmsr(MSR_PAT)) };
    let xcr0 = if cpu::read_cr4() & CR4_OSXSAVE != 0 {
        fpu::xcr0()
    } else {
        0
    };
    for (slot, v) in STATE
        .iter()
        .zip([cpu::read_cr0(), cpu::read_cr4(), efer, xcr0, pat])
    {
        slot.store(v, Ordering::Relaxed);
    }
    if has_tsc_adjust() {
        // SAFETY: a CPU anuncia `IA32_TSC_ADJUST`.
        TSC_ADJUST.store(unsafe { rdmsr(MSR_TSC_ADJUST) }, Ordering::Relaxed);
        BSP_HAS_TSC_ADJUST.store(true, Ordering::Relaxed);
    }
}

/// Esta CPU tem `IA32_TSC_ADJUST` (CPUID 7, `EBX[1]`).
pub fn has_tsc_adjust() -> bool {
    has(7, 0, 1)
}

/// Soma `delta` ao `IA32_TSC_ADJUST` desta CPU, o que soma o mesmo ao TSC
/// (correção do teste de salto, ADR 0030, item 5).
///
/// # Safety
///
/// A CPU tem `IA32_TSC_ADJUST` e ninguém nela depende ainda do relógio
/// (é um AP antes de entrar na máscara de ligadas).
pub unsafe fn add_tsc_adjust(delta: i64) {
    // SAFETY: contrato do chamador.
    unsafe {
        let now = rdmsr(MSR_TSC_ADJUST);
        wrmsr(MSR_TSC_ADJUST, now.wrapping_add_signed(delta));
    }
}

fn has(leaf: u32, reg: u8, bit: u32) -> bool {
    if cpu::max_leaf(false) < leaf {
        return false;
    }
    let r = cpu::cpuid(leaf, 0);
    let word = match reg {
        0 => r.ebx,
        1 => r.ecx,
        _ => r.edx,
    };
    word & (1 << bit) != 0
}

/// Copia o estado do BSP para esta CPU; `cpu_id` vai para o `TSC_AUX`.
///
/// # Errors
///
/// O nome do recurso que falta, ou `"tamanho da área de XSAVE"`.
///
/// # Safety
///
/// Num AP, com interrupções desligadas, depois de [`capture`] no BSP e
/// antes de qualquer acesso à FPU ou à memória de usuário.
pub unsafe fn apply(cpu_id: u32) -> Result<(), &'static str> {
    let [cr0, cr4, efer, xcr0, pat] = [0, 1, 2, 3, 4].map(|i| STATE[i].load(Ordering::Relaxed));
    for (bit, leaf, reg, cpuid_bit, name) in CR4_FEATURES {
        if cr4 & bit != 0 && !has(leaf, reg, cpuid_bit) {
            return Err(name);
        }
    }
    if cr4 & CR4_OSXSAVE != 0 {
        let leaf = cpu::cpuid(0xd, 0);
        let supported = u64::from(leaf.eax) | (u64::from(leaf.edx) << 32);
        if xcr0 & !supported != 0 {
            return Err("componentes de XSAVE");
        }
    }
    // SAFETY: os bits de CR4 ligados foram conferidos acima (os demais,
    // como PAE, existem em toda CPU x86-64); CR0 e EFER só repetem o modo
    // em que esta CPU já está, mais WP, NE, MP e NXE/SCE, que toda CPU
    // x86-64 tem; XCR0 só com componentes anunciados; o PAT é o do BSP.
    unsafe {
        cpu::write_cr0(cr0);
        cpu::write_cr4(cr4);
        wrmsr(
            cpu::MSR_EFER,
            rdmsr(cpu::MSR_EFER) | (efer & (cpu::EFER_NXE | EFER_SCE)),
        );
        wrmsr(MSR_PAT, pat);
        if cr4 & CR4_OSXSAVE != 0 {
            fpu::set_xcr0(xcr0);
        }
        // O mesmo `TSC_ADJUST` do BSP antes de qualquer leitura do TSC.
        if BSP_HAS_TSC_ADJUST.load(Ordering::Relaxed) && has_tsc_adjust() {
            wrmsr(MSR_TSC_ADJUST, TSC_ADJUST.load(Ordering::Relaxed));
        }
        if cpu::max_leaf(true) >= 0x8000_0001 && cpu::cpuid(0x8000_0001, 0).edx & (1 << 27) != 0 {
            wrmsr(MSR_TSC_AUX, u64::from(cpu_id));
        }
    }
    if cr4 & CR4_OSXSAVE != 0 && cpu::cpuid(0xd, 0).ebx as usize > fpu::area_bytes() {
        return Err("tamanho da área de XSAVE");
    }
    Ok(())
}
