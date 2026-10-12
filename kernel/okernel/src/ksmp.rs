//! Topologia de CPUs (ADR 0030, item 1; T-316).
//!
//! No boot, depois do APIC e do relógio, o kernel lê a MADT e guarda o id
//! de APIC de cada CPU pelo id lógico (0 é o BSP). A opção `smp=N` da
//! linha de comando limita quantas sobem; `smp=1` deixa o kernel como no
//! M2. A partida dos APs fica em [`start`].

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use kabi::MAX_CPUS;
use kabi::boot::BootInfo;
use okernel::acpi::madt::{self, Options, Topology};
use okernel::log::option;

use crate::arch::x86_64::{apic, percpu};
use crate::ktime::DirectRead;

pub mod ipi;
pub mod start;
pub mod tests;
pub mod tlb;
pub mod tsc;
pub use tests::TESTS;

/// Id de APIC de cada CPU, pelo id lógico.
static APIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// CPUs da topologia (1 até a MADT ser lida).
static COUNT: AtomicUsize = AtomicUsize::new(1);

/// CPUs da topologia (as que o kernel vai tentar ligar).
pub fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}

/// Id de APIC da CPU de id lógico `cpu`.
pub fn apic_id(cpu: usize) -> Option<u32> {
    (cpu < count()).then(|| APIC_IDS[cpu].load(Ordering::Relaxed))
}

/// Lê a MADT e guarda a topologia; sem MADT, só o BSP.
pub fn init(info: &BootInfo, cmdline: &str) {
    let (bsp, _) = apic::id_and_version();
    APIC_IDS[0].store(bsp, Ordering::Relaxed);
    percpu::with(|p| p.set_apic_id(bsp));
    let limit = option(cmdline, "smp")
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(MAX_CPUS);
    let opts = Options {
        bsp_apic_id: bsp,
        xapic: apic::mode() != apic::Mode::X2Apic,
        limit,
    };
    let topo = info
        .acpi_rsdp()
        .ok_or(okernel::acpi::AcpiError::NotFound)
        .and_then(|rsdp| madt::read(&mut DirectRead, rsdp, opts));
    match topo {
        Ok(t) => publish(&t),
        Err(e) => warn!("okernel: sem MADT ({e:?}); só o BSP"),
    }
}

fn publish(t: &Topology) {
    for (cpu, &id) in t.apic_ids().iter().enumerate() {
        APIC_IDS[cpu].store(id, Ordering::Relaxed);
    }
    COUNT.store(t.count(), Ordering::Release);
    info!(
        "okernel: topologia: {} CPU(s), APIC local em {:#x}, ids de APIC {:?}",
        t.count(),
        t.local_apic,
        t.apic_ids()
    );
    if !t.bsp_listed {
        warn!("okernel: o BSP não está na MADT");
    }
    if t.disabled + t.duplicates + t.over_limit + t.unaddressable > 0 {
        warn!(
            "okernel: CPUs fora: {} desligadas ({} hotplug), {} repetidas, {} além do limite, {} sem endereço em xAPIC",
            t.disabled, t.online_capable, t.duplicates, t.over_limit, t.unaddressable
        );
    }
    debug!(
        "okernel: MADT: {} IOAPIC(s) {:?}, {} override(s), {} NMI(s)",
        t.ioapics().len(),
        t.ioapics(),
        t.overrides,
        t.nmis
    );
}
