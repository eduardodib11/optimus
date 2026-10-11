//! Relógio monotônico em ns e timer do APIC (T-109; SDD v1.0, seção 6.8).
//!
//! O TSC é calibrado contra o HPET, achado pela tabela ACPI a partir do RSDP
//! da `BootInfo`: conta-se o TSC (e o timer do APIC, para o modo one-shot)
//! durante [`CALIBRATION_MS`] ms do HPET. O relógio conta ns desde o reset da
//! CPU (TSC zero), como o `boot_time_ns` da `BootInfo`. Sem HPET o relógio
//! fica parado em zero e o kernel avisa; PIT e ACPI PM como reserva ficam
//! para quando houver hardware sem HPET no CI.
//!
//! O timer usa TSC-deadline quando a CPU o anuncia (KVM e hardware real);
//! senão (o TCG do QEMU), one-shot do APIC com a frequência calibrada.

use core::sync::atomic::{AtomicU64, Ordering};

use kabi::boot::BootInfo;
use okernel::acpi::{self, PhysRead};
use okernel::time::{Clock, Scale, hpet_ticks_to_ns, hz_from};

use crate::arch::x86_64::{apic, cpu, hpet};
use crate::kmem;

mod tests;
pub use tests::TESTS;

/// Janela de calibragem do TSC contra o HPET.
pub const CALIBRATION_MS: u64 = 50;

static TSC_HZ: AtomicU64 = AtomicU64::new(0);
/// Multiplicador do relógio (`Scale::mult`), zero sem calibragem.
static TSC_MULT: AtomicU64 = AtomicU64::new(0);
static APIC_HZ: AtomicU64 = AtomicU64::new(0);

/// Memória física lida pelo mapa direto, só onde houver mapeamento.
struct DirectRead;

impl PhysRead for DirectRead {
    fn read(&mut self, phys: u64, buf: &mut [u8]) -> bool {
        let Some(end) = phys.checked_add(buf.len() as u64) else {
            return false;
        };
        let mapped = (phys & !0xfff..end)
            .step_by(4096)
            .all(|p| kmem::translate(kmem::direct_base() + p).is_some());
        if mapped {
            // SAFETY: todas as páginas da faixa estão no mapa direto (só
            // leitura ou mais), e `buf` não as sobrepõe (está na pilha ou no
            // kernel, fora das tabelas ACPI).
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (kmem::direct_base() + phys) as *const u8,
                    buf.as_mut_ptr(),
                    buf.len(),
                );
            }
        }
        mapped
    }
}

/// Frequência calibrada do TSC (zero se não houver relógio).
pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

fn clock() -> Option<Clock> {
    Some(Clock {
        base: 0,
        scale: Scale::from_mult(TSC_MULT.load(Ordering::Relaxed))?,
    })
}

/// Nanossegundos desde o reset da CPU (zero sem relógio calibrado).
pub fn now_ns() -> u64 {
    clock().map_or(0, |c| c.ns(cpu::rdtsc()))
}

/// Ns do HPET desde a contagem `start`.
pub fn hpet_ns_since(start: u64) -> u64 {
    hpet_ticks_to_ns(hpet::counter().wrapping_sub(start), hpet::period_fs())
}

/// Arma o timer para disparar no instante `ns` do relógio.
pub fn set_timer_at(ns: u64) {
    let Some(clock) = clock() else { return };
    let ahead = ns.saturating_sub(now_ns());
    let ticks = Scale::from_hz(APIC_HZ.load(Ordering::Relaxed)).map_or(u32::MAX, |s| {
        u32::try_from(s.ns_to_ticks(ahead)).unwrap_or(u32::MAX)
    });
    apic::arm_timer(clock.ticks_at(ns), ticks);
}

/// Acha o HPET, liga o APIC e calibra o TSC e o timer.
pub fn init(info: &BootInfo) {
    if let Err(e) = kmem::mmio(apic::xapic_phys()) {
        warn!("okernel: APIC sem mapeamento sem cache: {e:?}");
    }
    let mode = apic::init(kmem::direct_base());
    let period = info
        .acpi_rsdp()
        .ok_or(acpi::AcpiError::NotFound)
        .and_then(|rsdp| acpi::hpet_base(&mut DirectRead, rsdp))
        .and_then(|base| {
            let virt = kmem::mmio(base).map_err(|_| acpi::AcpiError::Unreadable)?;
            hpet::init(virt).ok_or(acpi::AcpiError::Unreadable)
        });
    let period = match period {
        Ok(p) => p,
        Err(e) => {
            error!("okernel: sem HPET ({e:?}); relógio parado");
            return;
        }
    };
    apic::start_countdown();
    let (h0, t0, c0) = (hpet::counter(), cpu::rdtsc(), apic::countdown());
    while hpet_ns_since(h0) < CALIBRATION_MS * 1_000_000 {
        core::hint::spin_loop();
    }
    let (h1, t1, c1) = (hpet::counter(), cpu::rdtsc(), apic::countdown());
    let ns = hpet_ticks_to_ns(h1 - h0, period);
    let tsc = hz_from(t1 - t0, ns).unwrap_or(0);
    let timer = hz_from(u64::from(c0 - c1), ns).unwrap_or(0);
    TSC_HZ.store(tsc, Ordering::Relaxed);
    TSC_MULT.store(
        Scale::from_hz(tsc).map_or(0, Scale::mult),
        Ordering::Relaxed,
    );
    APIC_HZ.store(timer, Ordering::Relaxed);
    let invariant =
        cpu::max_leaf(true) >= 0x8000_0007 && cpu::cpuid(0x8000_0007, 0).edx & (1 << 8) != 0;
    info!(
        "okernel: relógio: TSC de {} kHz (invariante: {invariant}) calibrado contra o HPET ({period} fs) em {CALIBRATION_MS} ms",
        tsc / 1000
    );
    info!(
        "okernel: APIC {mode:?}, timer {} ({} kHz)",
        if apic::tsc_deadline() {
            "TSC-deadline"
        } else {
            "one-shot"
        },
        timer / 1000
    );
}
