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
/// `XGETBV` com ECX = 1 (XINUSE) existe (CPUID.(0xD, 1).EAX\[2\]).
static XINUSE: AtomicBool = AtomicBool::new(false);

/// MXCSR do estado inicial (todas as exceções mascaradas).
const MXCSR_INIT: u32 = 0x1f80;
/// Deslocamento do MXCSR na área legada do XSAVE.
const MXCSR_AT: usize = 24;
/// Deslocamento do `XSTATE_BV` (cabeçalho do XSAVE).
const XSTATE_BV_AT: usize = 512;
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
    let sub1 = if xsave { cpu::cpuid(0xd, 1).eax } else { 0 };
    XSAVEOPT.store(sub1 & 1 != 0, Ordering::Relaxed);
    XINUSE.store(sub1 & (1 << 2) != 0, Ordering::Relaxed);
    AREA_BYTES.store(bytes.max(FXSAVE_BYTES), Ordering::Relaxed);
}

/// Bytes da área de estado de uma thread.
pub fn area_bytes() -> usize {
    AREA_BYTES.load(Ordering::Relaxed)
}

/// XCR0 desta CPU (só com CR4.OSXSAVE ligado).
pub fn xcr0() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: quem chama confere CR4.OSXSAVE; XGETBV só lê.
    unsafe {
        asm!("xgetbv", in("ecx") 0, out("eax") low, out("edx") high, options(nomem, nostack));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Grava o XCR0 desta CPU (os APs copiam o do BSP).
///
/// # Safety
///
/// CR4.OSXSAVE ligado e `value` válido para a CPU.
pub unsafe fn set_xcr0(value: u64) {
    // SAFETY: contrato do chamador.
    unsafe { xsetbv(value) };
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

/// Troca o estado de FPU/SIMD da CPU: salva o de quem sai em `prev` e
/// carrega o de quem entra de `next` (T-519, ADR 0058, item 1).
///
/// A política continua ansiosa: ao voltar, os registradores têm o estado
/// de quem entra. O que muda é pular o trabalho que não muda nada quando os
/// registradores estão no estado inicial (XINUSE zero e MXCSR padrão), o
/// caso de todo programa do sistema, que é compilado sem SSE:
///
/// - a área de quem sai só ganha o cabeçalho do estado inicial
///   (`XSTATE_BV` zero e MXCSR padrão), em vez do `XSAVEOPT`;
/// - a área de quem entra, se também está no estado inicial, não é
///   carregada: o `XRSTOR` deixaria os registradores como já estão.
///
/// # Safety
///
/// Cada área aponta [`area_bytes`] bytes alinhados a 64, só da thread
/// dela, que ninguém mais acessa durante a troca; `next` foi gravada por
/// esta função, por [`save`] ou iniciada como a de uma thread nova
/// (cabeçalho zerado, FCW e MXCSR do estado inicial).
#[allow(
    clippy::cast_ptr_alignment,
    reason = "a área é alinhada a 64 e os campos a 4 e 8 dentro dela"
)]
pub unsafe fn switch(prev: Option<*mut u8>, next: Option<*const u8>) {
    let init = regs_init();
    if let Some(area) = prev {
        if init {
            // SAFETY: contrato acima; MXCSR e `XSTATE_BV` ficam dentro da
            // área e alinhados. Com `XSTATE_BV` zero, o `XRSTOR` põe cada
            // componente no estado inicial e só lê o MXCSR da área, que
            // fica o padrão: é o estado que a CPU tem agora.
            unsafe {
                area.add(MXCSR_AT).cast::<u32>().write(MXCSR_INIT);
                area.add(XSTATE_BV_AT).cast::<u64>().write(0);
            }
        } else {
            // SAFETY: contrato acima.
            unsafe { save(area) };
        }
    }
    if let Some(area) = next {
        // SAFETY: contrato acima.
        if !(init && unsafe { area_init(area) }) {
            // SAFETY: contrato acima.
            unsafe { restore(area) };
        }
    }
}

/// A troca pula o trabalho redundante ([`switch`]): a CPU tem XINUSE.
pub fn skips_redundant() -> bool {
    XINUSE.load(Ordering::Relaxed)
}

/// Os registradores de FPU/SIMD desta CPU estão no estado inicial: todo
/// componente do XCR0 com XINUSE zero (o que garante a configuração
/// inicial, com FCW e o resto do x87 inclusos) e MXCSR padrão, que o
/// XINUSE do SSE não cobre em todas as CPUs. Falso sem XINUSE.
fn regs_init() -> bool {
    if !XINUSE.load(Ordering::Relaxed) {
        return false;
    }
    let (low, high): (u32, u32);
    let mut mxcsr: u32 = 0;
    // SAFETY: XGETBV com ECX = 1 existe (CPUID acima) e só lê; STMXCSR
    // grava 4 bytes em `mxcsr` (CR4.OSFXSR ligado no `init`).
    unsafe {
        asm!("xgetbv", in("ecx") 1, out("eax") low, out("edx") high, options(nomem, nostack));
        asm!("stmxcsr [{}]", in(reg) &raw mut mxcsr, options(nostack));
    }
    low == 0 && high == 0 && mxcsr == MXCSR_INIT
}

/// A área guarda o estado inicial: o `XRSTOR` dela põe todo componente no
/// estado inicial e o MXCSR no padrão.
///
/// # Safety
///
/// `area` aponta uma área de [`area_bytes`] bytes, alinhada a 64, com
/// cabeçalho XSAVE (só chamada com XINUSE, que implica XSAVE).
#[allow(
    clippy::cast_ptr_alignment,
    reason = "a área é alinhada a 64 e os campos a 4 e 8 dentro dela"
)]
unsafe fn area_init(area: *const u8) -> bool {
    // SAFETY: contrato acima; os campos ficam dentro da área, alinhados.
    let (bv, mxcsr) = unsafe {
        (
            area.add(XSTATE_BV_AT).cast::<u64>().read(),
            area.add(MXCSR_AT).cast::<u32>().read(),
        )
    };
    bv == 0 && mxcsr == MXCSR_INIT
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
        // desta mesma área; se não foi (a troca para ela pulou o XRSTOR,
        // ver `switch`), grava tudo. Ninguém grava a área enquanto a
        // thread roda, e o cabeçalho que `switch` grava só substitui um
        // estado que os registradores já deixaram por escrita (todo
        // componente que o XRSTOR deixou fora do inicial foi escrito para
        // voltar a ele, o que marca a modificação).
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
