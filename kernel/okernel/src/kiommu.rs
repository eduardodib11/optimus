//! IOMMU no boot (ADR 0044, item 1; T-403): lê a DMAR, mapeia os
//! registradores de cada unidade de VT-d e instala o backend em
//! [`okernel::dma`]. Sem DMAR, nada é instalado e o `kroot` avisa
//! "isolamento de DMA ausente".

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;

use okernel::acpi::dmar;
use okernel::dma::vtd::{Fault, Hw, VtD};
use okernel::mm::PhysAddr;
use okernel::mm::paging::{Table, TableMemory};
use okernel::sync::{LockClass, SpinLock};

use crate::arch::x86_64::cpu;
use crate::kmem::{self, DirectMap};
use crate::{bootinfo, ktime};

mod tests;
pub use tests::TESTS;

/// O backend instalado, para ler as faltas.
static VTD: SpinLock<Option<&'static VtD>> = SpinLock::with_class(LockClass::Diagnostic, None);

/// Registradores das unidades (endereço virtual sem cache de cada uma) e as
/// tabelas, no mapa direto. As tabelas da IOMMU são só do backend, que as
/// toca com a trava dele: nenhuma é tabela de CPU guardada por `KERNEL_PT`.
struct Regs(Vec<u64>, DirectMap);

impl Regs {
    fn at(&self, unit: usize, off: usize) -> u64 {
        assert!(off < 0x2000, "vt-d: registrador fora das duas páginas");
        self.0[unit] + off as u64
    }
}

impl TableMemory for Regs {
    fn table(&mut self, phys: PhysAddr) -> &mut Table {
        self.1.table(phys)
    }

    fn alloc_table(&mut self) -> Option<PhysAddr> {
        self.1.alloc_table()
    }

    fn free_table(&mut self, phys: PhysAddr) {
        self.1.free_table(phys);
    }
}

// SAFETY (os quatro acessos): `at` cai nas duas páginas de registradores da
// unidade, mapeadas sem cache por `kmem::mmio` em `init`; os deslocamentos
// do VT-d são alinhados à largura do acesso.
impl Hw for Regs {
    fn read32(&mut self, unit: usize, off: usize) -> u32 {
        // SAFETY: ver acima.
        unsafe { ptr::read_volatile(self.at(unit, off) as *const u32) }
    }

    fn read64(&mut self, unit: usize, off: usize) -> u64 {
        // SAFETY: ver acima.
        unsafe { ptr::read_volatile(self.at(unit, off) as *const u64) }
    }

    fn write32(&mut self, unit: usize, off: usize, value: u32) {
        // SAFETY: ver acima.
        unsafe { ptr::write_volatile(self.at(unit, off) as *mut u32, value) }
    }

    fn write64(&mut self, unit: usize, off: usize, value: u64) {
        // SAFETY: ver acima.
        unsafe { ptr::write_volatile(self.at(unit, off) as *mut u64, value) }
    }

    fn flush(&mut self, phys: PhysAddr, len: usize) {
        cpu::clflush(kmem::direct(phys), len);
    }
}

/// Liga o VT-d se a DMAR existir. Chamar uma vez, no boot, antes do
/// `kroot`.
pub fn init() {
    let Some(rsdp) = bootinfo::get().and_then(kabi::boot::BootInfo::acpi_rsdp) else {
        return;
    };
    let Ok(table) = dmar::read(&mut ktime::DirectRead, rsdp) else {
        return;
    };
    let mut regs = Regs(Vec::new(), DirectMap);
    for unit in table.units() {
        // Duas páginas: os registradores de IOTLB e de falta podem passar
        // da primeira.
        let mapped = kmem::mmio(unit.base).and_then(|v| kmem::mmio(unit.base + 0x1000).map(|_| v));
        let Ok(virt) = mapped else {
            warn!("okernel: VT-d em {:#x} não mapeou", unit.base);
            return;
        };
        regs.0.push(virt);
    }
    let units = table.units().len();
    let Some(vtd) = VtD::new(Box::new(regs), table) else {
        warn!("okernel: VT-d sem formato de tabela aceito ({units} unidades)");
        return;
    };
    let vtd: &'static VtD = Box::leak(Box::new(vtd));
    *VTD.lock() = Some(vtd);
    okernel::dma::install(vtd);
    let (units, levels) = vtd.shape();
    info!("okernel: VT-d ligado: {units} unidade(s), tabelas de {levels} níveis");
}

/// Lê e limpa as faltas de DMA; cada uma vira um registro no log (ADR
/// 0044, item 4) e é passada a `out`.
pub fn faults(out: &mut dyn FnMut(Fault)) {
    let Some(vtd) = *VTD.lock() else {
        return;
    };
    vtd.faults(&mut |f| {
        warn!(
            "okernel: falta de DMA: dev={:02x}:{:02x}.{} iova={:#x} motivo={:#x} {}",
            f.bdf >> 8,
            (f.bdf >> 3) & 31,
            f.bdf & 7,
            f.iova,
            f.reason,
            if f.write { "escrita" } else { "leitura" }
        );
        out(f);
    });
}
