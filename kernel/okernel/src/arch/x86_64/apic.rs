//! APIC local em modo x2APIC (MSRs), com xAPIC (MMIO) como reserva, e o
//! timer do APIC em modo TSC-deadline ou, sem ele, one-shot (T-109; SDD v1.0,
//! seção 6.8).
//!
//! O 8259 legado fica todo mascarado. Interrupções de vetor 32 a 255 chegam a
//! [`dispatch`]: o timer registra o disparo e, depois do EOI, chama o
//! escalonador (T-207; as interrupções só chegam no anel 3 ou no ocioso,
//! nunca com trava do kernel na mão), o vetor espúrio é ignorado e os
//! demais contam como inesperados.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use super::cpu::{self, rdmsr, wrmsr};
use super::outb;

/// Vetor do timer do APIC.
pub const TIMER_VECTOR: u8 = 0x20;
/// Vetor de interrupções espúrias.
pub const SPURIOUS_VECTOR: u8 = 0xff;

const MSR_APIC_BASE: u32 = 0x1b;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2: u64 = 1 << 10;
const MSR_TSC_DEADLINE: u32 = 0x6e0;

const REG_ID: u32 = 0x20;
const REG_VERSION: u32 = 0x30;
const REG_EOI: u32 = 0xb0;
const REG_SVR: u32 = 0xf0;
const REG_ICR: u32 = 0x300;
const REG_ICR_HIGH: u32 = 0x310;
const REG_LVT_TIMER: u32 = 0x320;
const REG_TIMER_INITIAL: u32 = 0x380;
const REG_TIMER_CURRENT: u32 = 0x390;
const REG_TIMER_DIVIDE: u32 = 0x3e0;

const LVT_MASKED: u32 = 1 << 16;
const LVT_TSC_DEADLINE: u32 = 0b10 << 17;

/// Como o APIC é acessado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// Ainda não inicializado.
    Off = 0,
    /// MMIO no endereço do `IA32_APIC_BASE`.
    XApic = 1,
    /// MSRs 0x800 em diante.
    X2Apic = 2,
}

static MODE: AtomicU8 = AtomicU8::new(Mode::Off as u8);
static MMIO: AtomicU64 = AtomicU64::new(0);
static DEADLINE: AtomicBool = AtomicBool::new(false);
static TIMER_FIRES: AtomicU64 = AtomicU64::new(0);
static TIMER_LAST_TSC: AtomicU64 = AtomicU64::new(0);
static UNEXPECTED: AtomicU64 = AtomicU64::new(0);
static FROZEN: AtomicBool = AtomicBool::new(false);

/// Modo atual.
pub fn mode() -> Mode {
    match MODE.load(Ordering::Acquire) {
        1 => Mode::XApic,
        2 => Mode::X2Apic,
        _ => Mode::Off,
    }
}

/// O timer usa TSC-deadline.
pub fn tsc_deadline() -> bool {
    DEADLINE.load(Ordering::Relaxed)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "registradores do APIC têm 32 bits (o ICR do x2APIC não passa por aqui)"
)]
fn read(reg: u32) -> u32 {
    match mode() {
        // SAFETY: MSR x2APIC de um registrador legível; o modo foi ligado.
        Mode::X2Apic => unsafe { rdmsr(0x800 + (reg >> 4)) as u32 },
        // SAFETY: página do APIC no mapa direto; registradores de 32 bits
        // alinhados a 16 bytes.
        Mode::XApic => unsafe {
            ((MMIO.load(Ordering::Relaxed) + u64::from(reg)) as *const u32).read_volatile()
        },
        Mode::Off => 0,
    }
}

fn write(reg: u32, value: u32) {
    match mode() {
        // SAFETY: MSR x2APIC de um registrador gravável.
        Mode::X2Apic => unsafe { wrmsr(0x800 + (reg >> 4), u64::from(value)) },
        // SAFETY: idem a `read`.
        Mode::XApic => unsafe {
            ((MMIO.load(Ordering::Relaxed) + u64::from(reg)) as *mut u32).write_volatile(value);
        },
        Mode::Off => {}
    }
}

/// Liga o APIC local (x2APIC se houver), mascara o 8259 e o timer.
/// `direct_map` converte o endereço físico do xAPIC em virtual.
pub fn init(direct_map: u64) -> Mode {
    let leaf1 = cpu::cpuid(1, 0);
    // SAFETY: os 8259 ficam nas portas 0x21 e 0xa1; mascarar todas as linhas
    // impede IRQs legadas nos vetores que o kernel usa.
    unsafe {
        outb(0x21, 0xff);
        outb(0xa1, 0xff);
    }
    // SAFETY: `IA32_APIC_BASE` existe em toda CPU x86-64 com APIC.
    let base = unsafe { rdmsr(MSR_APIC_BASE) };
    let mode = if leaf1.ecx & (1 << 21) != 0 {
        // SAFETY: a CPU anuncia x2APIC; ligar EN e depois EXTD é a sequência
        // do manual (de xAPIC para x2APIC).
        unsafe {
            wrmsr(MSR_APIC_BASE, base | APIC_BASE_ENABLE);
            wrmsr(MSR_APIC_BASE, base | APIC_BASE_ENABLE | APIC_BASE_X2);
        }
        Mode::X2Apic
    } else {
        // SAFETY: liga o APIC global sem mudar o endereço.
        unsafe { wrmsr(MSR_APIC_BASE, base | APIC_BASE_ENABLE) };
        MMIO.store(
            direct_map + (base & 0x000f_ffff_ffff_f000),
            Ordering::Relaxed,
        );
        Mode::XApic
    };
    MODE.store(mode as u8, Ordering::Release);
    write(REG_SVR, 0x100 | u32::from(SPURIOUS_VECTOR));
    write(REG_LVT_TIMER, LVT_MASKED | u32::from(TIMER_VECTOR));
    DEADLINE.store(leaf1.ecx & (1 << 24) != 0, Ordering::Relaxed);
    mode
}

/// Endereço físico dos registradores do xAPIC (`IA32_APIC_BASE`).
pub fn xapic_phys() -> u64 {
    // SAFETY: `IA32_APIC_BASE` existe em toda CPU x86-64 com APIC.
    unsafe { rdmsr(MSR_APIC_BASE) & 0x000f_ffff_ffff_f000 }
}

/// ID e versão do APIC local.
pub fn id_and_version() -> (u32, u32) {
    let id = read(REG_ID);
    let id = if mode() == Mode::X2Apic { id } else { id >> 24 };
    (id, read(REG_VERSION))
}

/// Disparos do timer e o TSC do último.
pub fn timer_fires() -> (u64, u64) {
    (
        TIMER_FIRES.load(Ordering::Acquire),
        TIMER_LAST_TSC.load(Ordering::Relaxed),
    )
}

/// Interrupções sem dono recebidas.
pub fn unexpected() -> u64 {
    UNEXPECTED.load(Ordering::Relaxed)
}

/// Conta regressiva do timer one-shot com divisor 1, a partir de `u32::MAX`
/// (para calibrar a frequência do timer contra o HPET).
pub fn start_countdown() {
    write(REG_TIMER_DIVIDE, 0b1011);
    write(REG_LVT_TIMER, LVT_MASKED | u32::from(TIMER_VECTOR));
    write(REG_TIMER_INITIAL, u32::MAX);
}

/// Contagem atual do timer one-shot.
pub fn countdown() -> u32 {
    read(REG_TIMER_CURRENT)
}

/// Arma o timer: no TSC `deadline_tsc` (modo deadline) ou depois de `ticks`
/// contagens do timer (one-shot).
pub fn arm_timer(deadline_tsc: u64, ticks: u32) {
    if tsc_deadline() {
        write(REG_LVT_TIMER, LVT_TSC_DEADLINE | u32::from(TIMER_VECTOR));
        // SAFETY: a CPU anuncia TSC-deadline; o MSR só arma o timer.
        unsafe { wrmsr(MSR_TSC_DEADLINE, deadline_tsc) };
    } else {
        write(REG_TIMER_DIVIDE, 0b1011);
        write(REG_LVT_TIMER, u32::from(TIMER_VECTOR));
        write(REG_TIMER_INITIAL, ticks.max(1));
    }
}

/// Fim de interrupção (EOI) de um vetor tratado fora de [`dispatch`].
pub fn eoi() {
    write(REG_EOI, 0);
}

/// Manda a esta CPU uma interrupção fixa no vetor `vector` (self-IPI),
/// entregue quando as interrupções forem ligadas.
pub fn self_ipi(vector: u8) {
    // Entrega fixa (000b), nível de asserção, destino "esta CPU" (01b).
    let icr: u32 = u32::from(vector) | (1 << 14) | (0b01 << 18);
    match mode() {
        // SAFETY: ICR do x2APIC; uma interrupção comum só para esta CPU.
        Mode::X2Apic => unsafe { wrmsr(0x800 + (REG_ICR >> 4), u64::from(icr)) },
        Mode::XApic => {
            write(REG_ICR_HIGH, 0);
            write(REG_ICR, icr);
        }
        Mode::Off => {}
    }
}

/// Manda NMI a todas as outras CPUs (para congelá-las no pânico).
fn nmi_others() {
    // Entrega NMI (100b), nível de asserção, destino "todas menos esta".
    let icr: u32 = (0b100 << 8) | (1 << 14) | (0b11 << 18);
    match mode() {
        // SAFETY: ICR do x2APIC; um NMI só para as outras CPUs.
        Mode::X2Apic => unsafe { wrmsr(0x800 + (REG_ICR >> 4), u64::from(icr)) },
        Mode::XApic => {
            write(REG_ICR_HIGH, 0);
            write(REG_ICR, icr);
        }
        Mode::Off => {}
    }
}

/// Congela o resto da máquina para o pânico: mascara o timer desta CPU e
/// manda NMI às outras, que param ao ver [`frozen`].
pub fn freeze_others() {
    FROZEN.store(true, Ordering::SeqCst);
    write(REG_LVT_TIMER, LVT_MASKED | u32::from(TIMER_VECTOR));
    nmi_others();
}

/// Um pânico pediu que as CPUs parem.
pub fn frozen() -> bool {
    FROZEN.load(Ordering::SeqCst)
}

/// Tratador das interrupções de vetor 32 a 255, chamado com IF desligado.
/// Devolve se foi o timer, já com o EOI feito (o escalonador pode trocar de
/// thread em seguida).
pub fn dispatch(vector: u64) -> bool {
    let timer = match u8::try_from(vector) {
        Ok(SPURIOUS_VECTOR) => return false,
        Ok(TIMER_VECTOR) => {
            TIMER_LAST_TSC.store(cpu::rdtsc(), Ordering::Relaxed);
            TIMER_FIRES.fetch_add(1, Ordering::Release);
            true
        }
        _ => {
            UNEXPECTED.fetch_add(1, Ordering::Relaxed);
            false
        }
    };
    write(REG_EOI, 0);
    timer
}
