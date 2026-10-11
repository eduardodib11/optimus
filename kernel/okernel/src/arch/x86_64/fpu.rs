//! Estado de FPU/SIMD das threads de usuário: XSAVE quando a CPU tem,
//! FXSAVE como reserva (T-206).
//!
//! O kernel é compilado sem SSE (alvo `x86_64-unknown-none`), então o
//! estado de FPU é todo do usuário e só precisa ser salvo e restaurado na
//! troca de thread. Com XSAVE, o XCR0 liga os componentes de usuário que a
//! CPU anuncia (x87, SSE, AVX e AVX-512), e o tamanho da área vem de
//! CPUID.(0xD, 0).EBX depois disso.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::cpu;

/// Componentes de XCR0 que o kernel aceita ligar: x87, SSE, AVX, opmask,
/// `ZMM_Hi256` e `Hi16_ZMM` (estado de usuário, sem MPX nem PKRU).
const XCR0_USER: u64 = 0b1110_0111;
/// Área do FXSAVE.
const FXSAVE_BYTES: usize = 512;

const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR0_NE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;

static XSAVE: AtomicBool = AtomicBool::new(false);
static XSAVEOPT: AtomicBool = AtomicBool::new(false);
static AREA_BYTES: AtomicUsize = AtomicUsize::new(FXSAVE_BYTES);

/// Liga SSE para o anel 3 e, se houver, XSAVE; mede a área.
pub fn init() {
    // SAFETY: liga a FPU sem emulação nem troca preguiçosa (TS); o kernel
    // não usa FPU, então nada muda para ele.
    unsafe { cpu::write_cr0((cpu::read_cr0() | CR0_MP | CR0_NE) & !(CR0_EM | CR0_TS)) };
    let mut cr4 = cpu::read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT;
    let xsave = cpu::cpuid(1, 0).ecx & (1 << 26) != 0 && cpu::max_leaf(false) >= 0xd;
    if xsave {
        cr4 |= CR4_OSXSAVE;
    }
    // SAFETY: os bits ligados existem em toda CPU x86-64 (SSE) ou foram
    // anunciados por CPUID (XSAVE).
    unsafe { cpu::write_cr4(cr4) };
    let bytes = if xsave {
        let leaf = cpu::cpuid(0xd, 0);
        let supported = u64::from(leaf.eax) | (u64::from(leaf.edx) << 32);
        let xcr0 = supported & XCR0_USER;
        // SAFETY: OSXSAVE ligado; XCR0 só com componentes anunciados, x87
        // sempre, e AVX só com SSE (garantido pela própria CPU).
        unsafe { xsetbv(xcr0) };
        info!("okernel: FPU com XSAVE, XCR0 {xcr0:#x}");
        cpu::cpuid(0xd, 0).ebx as usize
    } else {
        warn!("okernel: CPU sem XSAVE; FPU com FXSAVE");
        FXSAVE_BYTES
    };
    XSAVE.store(xsave, Ordering::Relaxed);
    XSAVEOPT.store(xsave && cpu::cpuid(0xd, 1).eax & 1 != 0, Ordering::Relaxed);
    AREA_BYTES.store(bytes.max(FXSAVE_BYTES), Ordering::Relaxed);
}

/// Bytes da área de estado de uma thread.
pub fn area_bytes() -> usize {
    AREA_BYTES.load(Ordering::Relaxed)
}

/// Grava XCR0.
///
/// # Safety
///
/// CR4.OSXSAVE ligado e `value` válido para a CPU.
unsafe fn xsetbv(value: u64) {
    #[allow(clippy::cast_possible_truncation, reason = "XSETBV divide em EDX:EAX")]
    let (low, high) = (value as u32, (value >> 32) as u32);
    // SAFETY: contrato do chamador.
    unsafe { asm!("xsetbv", in("ecx") 0, in("eax") low, in("edx") high, options(nomem, nostack)) };
}
/// A CPU salva com XSAVE.
pub fn uses_xsave() -> bool {
    XSAVE.load(Ordering::Relaxed)
}

/// Salva o estado de FPU/SIMD da CPU em `area`.
///
/// # Safety
///
/// `area` aponta [`area_bytes`] bytes graváveis, alinhados a 64, só desta
/// thread.
pub unsafe fn save(area: *mut u8) {
    if XSAVEOPT.load(Ordering::Relaxed) {
        // SAFETY: como abaixo. XSAVEOPT deixa de gravar componentes no
        // estado inicial ou não modificados desde o último XRSTOR, se foi
        // desta mesma área; ela só é salva para a thread que sai da CPU,
        // cujo XRSTOR foi o último (na troca para ela), e ninguém grava a
        // área enquanto a thread roda.
        unsafe {
            asm!("xsaveopt64 [{}]", in(reg) area, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack));
        }
    } else if uses_xsave() {
        // SAFETY: contrato do chamador; EDX:EAX todo um salva tudo o que o
        // XCR0 liga.
        unsafe {
            asm!("xsave64 [{}]", in(reg) area, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack));
        }
    } else {
        // SAFETY: contrato do chamador (512 bytes alinhados a 16).
        unsafe { asm!("fxsave64 [{}]", in(reg) area, options(nostack)) };
    }
}

/// Carrega o estado de FPU/SIMD de `area`.
///
/// # Safety
///
/// `area` aponta uma área válida de [`area_bytes`] bytes, alinhada a 64,
/// gravada por [`save`] ou iniciada como a de uma thread nova (cabeçalho
/// XSAVE zerado, FCW e MXCSR válidos).
pub unsafe fn restore(area: *const u8) {
    if uses_xsave() {
        // SAFETY: contrato do chamador.
        unsafe {
            asm!("xrstor64 [{}]", in(reg) area, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack));
        }
    } else {
        // SAFETY: contrato do chamador.
        unsafe { asm!("fxrstor64 [{}]", in(reg) area, options(nostack)) };
    }
}
