//! IOMMU no boot (ADR 0044, item 1; T-403): lê a DMAR (VT-d) ou a IVRS
//! (AMD-Vi), mapeia os registradores de cada unidade e instala o backend em
//! [`okernel::dma`]. Sem nenhuma das duas, nada é instalado e o `kroot` avisa
//! "isolamento de DMA ausente".

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;

use okernel::acpi::{dmar, ivrs};
use okernel::dma::amdvi::AmdVi;
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
#[derive(Clone, Copy)]
enum Unit {
    Vtd(&'static VtD),
    Amd(&'static AmdVi),
}

static UNIT: SpinLock<Option<Unit>> = SpinLock::with_class(LockClass::Diagnostic, None);

/// Registradores das unidades (endereço virtual sem cache de cada uma) e as
/// tabelas, no mapa direto. As tabelas da IOMMU são só do backend, que as
/// toca com a trava dele: nenhuma é tabela de CPU guardada por `KERNEL_PT`.
struct Regs(Vec<u64>, DirectMap, usize);

impl Regs {
    fn at(&self, unit: usize, off: usize) -> u64 {
        assert!(off < self.2, "iommu: registrador fora das páginas mapeadas");
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

    fn alloc_contiguous(&mut self, order: u32) -> Option<PhysAddr> {
        let first = kmem::alloc_frames(order as usize)?;
        for p in 0..1u64 << order {
            self.1.table(PhysAddr(first.0 + p * 4096)).fill(0);
        }
        Some(first)
    }
}

/// Mapeia `pages` páginas de registradores de cada unidade em `bases`.
fn map_units(bases: impl Iterator<Item = u64>, pages: u64) -> Option<Regs> {
    let mut regs = Regs(Vec::new(), DirectMap, usize::try_from(pages * 0x1000).ok()?);
    for base in bases {
        let mut virt = None;
        for p in 0..pages {
            let Ok(v) = kmem::mmio(base + p * 0x1000) else {
                warn!("okernel: IOMMU em {base:#x} não mapeou");
                return None;
            };
            virt.get_or_insert(v);
        }
        regs.0.push(virt?);
    }
    Some(regs)
}

/// Liga a IOMMU: VT-d se houver DMAR, senão AMD-Vi se houver IVRS. Chamar
/// uma vez, no boot, antes do `kroot`.
pub fn init() {
    let Some(rsdp) = bootinfo::get().and_then(kabi::boot::BootInfo::acpi_rsdp) else {
        return;
    };
    if let Ok(table) = dmar::read(&mut ktime::DirectRead, rsdp) {
        // Duas páginas: os registradores de IOTLB e de falta podem passar
        // da primeira.
        let Some(regs) = map_units(table.units().iter().map(|u| u.base), 2) else {
            return;
        };
        let units = table.units().len();
        let Some(vtd) = VtD::new(Box::new(regs), table) else {
            warn!("okernel: VT-d sem formato de tabela aceito ({units} unidades)");
            return;
        };
        let vtd: &'static VtD = Box::leak(Box::new(vtd));
        *UNIT.lock() = Some(Unit::Vtd(vtd));
        okernel::dma::install(vtd);
        let (units, levels) = vtd.shape();
        info!("okernel: VT-d ligado: {units} unidade(s), tabelas de {levels} níveis");
    } else if let Ok(table) = ivrs::read(&mut ktime::DirectRead, rsdp) {
        // Três páginas: cabeças e caudas dos anéis ficam em 0x2000.
        let Some(regs) = map_units(table.units().iter().map(|u| u.base), 3) else {
            return;
        };
        let Some(amd) = AmdVi::new(Box::new(regs), table) else {
            warn!("okernel: AMD-Vi sem memória para as tabelas");
            return;
        };
        let amd: &'static AmdVi = Box::leak(Box::new(amd));
        *UNIT.lock() = Some(Unit::Amd(amd));
        okernel::dma::install(amd);
        info!("okernel: AMD-Vi ligado: {} unidade(s)", amd.units());
    }
}

/// A IOMMU ligada: `"VT-d"`, `"AMD-Vi"` ou nenhuma.
pub fn kind() -> Option<&'static str> {
    Some(match (*UNIT.lock())? {
        Unit::Vtd(_) => "VT-d",
        Unit::Amd(_) => "AMD-Vi",
    })
}

/// Lê e limpa as faltas de DMA; cada uma vira um registro no log (ADR
/// 0044, item 4) e é passada a `out`.
pub fn faults(out: &mut dyn FnMut(Fault)) {
    let Some(unit) = *UNIT.lock() else {
        return;
    };
    let mut log = |f: Fault| {
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
    };
    match unit {
        Unit::Vtd(u) => u.faults(&mut log),
        Unit::Amd(u) => u.faults(&mut log),
    }
}
