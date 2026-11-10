//! Backend de VT-d do [`Iommu`] (ADR 0044, item 1; T-403).
//!
//! Modo legado: tabela raiz (uma entrada por barramento) → tabela de
//! contexto (uma por dispositivo e função) → tabelas de segundo nível do
//! domínio, de 3 níveis (IOVA de 39 bits) ou 4, conforme o `SAGAW` que
//! todas as unidades aceitam. Dispositivo sem entrada de contexto tem o DMA
//! bloqueado: ligar a tradução fecha tudo, e só o `dma_attach` abre. As
//! invalidações são pelos registradores (`CCMD` e `IOTLB`), sem fila, e
//! esperam a unidade antes de voltar.
//!
//! O acesso aos registradores e à cache fica atrás de [`Hw`]; a lógica é
//! testável no host. A trava é de nível 5 (a de um espaço de endereços):
//! vem depois da do domínio e antes do heap e do buddy.

#![allow(
    clippy::cast_possible_truncation,
    reason = "campos de registradores e índices de tabela têm largura fixa"
)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use kabi::Error;

use super::Iommu;
use crate::acpi::dmar::Dmar;
use crate::mm::PhysAddr;
use crate::mm::paging::TableMemory;
use crate::sync::{LockClass, SpinLock};

/// Registradores e memória de tabelas das unidades.
pub trait Hw: TableMemory + Send {
    /// Lê o registrador de 32 bits em `off` da unidade `unit`.
    fn read32(&mut self, unit: usize, off: usize) -> u32;
    /// Lê o registrador de 64 bits em `off`.
    fn read64(&mut self, unit: usize, off: usize) -> u64;
    /// Escreve o registrador de 32 bits em `off`.
    fn write32(&mut self, unit: usize, off: usize, value: u32);
    /// Escreve o registrador de 64 bits em `off`.
    fn write64(&mut self, unit: usize, off: usize, value: u64);
    /// Tira da cache as linhas de `len` bytes em `phys`, para unidades que
    /// leem as tabelas sem coerência.
    fn flush(&mut self, phys: PhysAddr, len: usize);
    /// `2^order` frames contíguos e zerados (a tabela de dispositivos do
    /// AMD-Vi); `None` sem memória.
    fn alloc_contiguous(&mut self, order: u32) -> Option<PhysAddr> {
        let _ = order;
        None
    }
}

pub(crate) const CAP: usize = 0x08;
pub(crate) const ECAP: usize = 0x10;
pub(crate) const GCMD: usize = 0x18;
pub(crate) const GSTS: usize = 0x1c;
pub(crate) const RTADDR: usize = 0x20;
pub(crate) const CCMD: usize = 0x28;
const FSTS: usize = 0x34;
const FECTL: usize = 0x38;
const FEDATA: usize = 0x3c;
const FEADDR: usize = 0x40;
const FEUADDR: usize = 0x44;

pub(crate) const TE: u32 = 1 << 31;
pub(crate) const SRTP: u32 = 1 << 30;
const WBF: u32 = 1 << 27;
/// Bits de `GSTS` que voltam ao `GCMD` (os de efeito único ficam de fora).
const PERSISTENT: u32 = 0x96ff_ffff;
const ICC: u64 = 1 << 63;
const IVT: u64 = 1 << 63;
const GLOBAL_CTX: u64 = 1 << 61;
const GLOBAL_IOTLB: u64 = 1 << 60;
const DOMAIN_IOTLB: u64 = 2 << 60;
/// Esvazia leituras e escritas pendentes na invalidação do IOTLB.
const DRAIN: u64 = 3 << 48;
const PRESENT: u64 = 1;
const READ: u64 = 1;
const WRITE: u64 = 2;
const ADDR: u64 = 0x000f_ffff_ffff_f000;
/// Voltas de espera por um bit de registrador antes do pânico.
const SPIN: u32 = 10_000_000;
/// Domínios de hardware aceitos (o id 0 fica reservado).
const MAX_DOMAINS: usize = 1024;

/// Uma falta registrada por uma unidade (ADR 0044, item 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Dispositivo de origem.
    pub bdf: u16,
    /// Página de IOVA da falta.
    pub iova: u64,
    /// Código de motivo do VT-d.
    pub reason: u8,
    /// Escrita (senão, leitura).
    pub write: bool,
}

struct Unit {
    index: usize,
    root: PhysAddr,
    /// Tabela de contexto por barramento (0 = ainda não há). São do kernel:
    /// no máximo 256 por unidade, nunca liberadas.
    contexts: [u64; 256],
    coherent: bool,
    caching_mode: bool,
    write_buffer: bool,
    iotlb: usize,
    /// Primeiro registrador de falta e quantos há.
    faults: (usize, usize),
}

struct Domain {
    root: PhysAddr,
    tables: u64,
    devices: Vec<(usize, u16)>,
}

struct Inner {
    hw: Box<dyn Hw>,
    units: Vec<Unit>,
    domains: Vec<Option<Domain>>,
    dmar: Dmar,
    /// Níveis das tabelas de segundo nível (3 ou 4).
    levels: u32,
}

/// As unidades de VT-d da máquina.
pub struct VtD {
    inner: SpinLock<Inner>,
}

fn spin(hw: &mut dyn Hw, mut done: impl FnMut(&mut dyn Hw) -> bool) {
    for _ in 0..SPIN {
        if done(hw) {
            return;
        }
        core::hint::spin_loop();
    }
    panic!("vt-d: a unidade não confirmou o comando");
}

/// Escreve `cmd` no `GCMD` e espera `GSTS & mask == want`.
fn command(hw: &mut dyn Hw, u: usize, cmd: u32, mask: u32, want: u32) {
    hw.write32(u, GCMD, cmd);
    spin(hw, |hw| hw.read32(u, GSTS) & mask == want);
}

fn flush(hw: &mut dyn Hw, units: &[Unit], phys: u64, len: usize) {
    if units.iter().any(|u| !u.coherent) {
        hw.flush(PhysAddr(phys), len);
    }
}

/// Esvazia o buffer de escrita (se a unidade pede) e invalida o cache de
/// contexto (`ctx` ≠ 0) e o IOTLB (`iotlb`) da unidade.
fn invalidate(hw: &mut dyn Hw, unit: &Unit, ctx: u64, iotlb: u64) {
    let u = unit.index;
    if unit.write_buffer {
        let sts = hw.read32(u, GSTS) & PERSISTENT;
        command(hw, u, sts | WBF, WBF, 0);
    }
    if ctx != 0 {
        hw.write64(u, CCMD, ICC | ctx);
        spin(hw, |hw| hw.read64(u, CCMD) & ICC == 0);
    }
    hw.write64(u, unit.iotlb, IVT | DRAIN | iotlb);
    spin(hw, |hw| hw.read64(u, unit.iotlb) & IVT == 0);
}

fn domain_iotlb(id: u32) -> u64 {
    DOMAIN_IOTLB | u64::from(id) << 32
}

impl VtD {
    /// Liga a tradução em todas as unidades da `dmar`, com o DMA bloqueado
    /// até algum `attach`. `None` sem unidades, sem memória ou se elas não
    /// aceitam tabelas de 3 ou 4 níveis em comum.
    ///
    /// # Panics
    ///
    /// Se uma unidade não confirmar um comando.
    #[must_use]
    pub fn new(mut hw: Box<dyn Hw>, dmar: Dmar) -> Option<Self> {
        let n = dmar.units().len();
        let caps: Vec<_> = (0..n)
            .map(|u| (hw.read64(u, CAP), hw.read64(u, ECAP)))
            .collect();
        let sagaw = caps.iter().fold(0x1f, |a, (c, _)| a & (c >> 8));
        let levels = match sagaw {
            _ if n == 0 => return None,
            s if s & 2 != 0 => 3,
            s if s & 4 != 0 => 4,
            _ => return None,
        };
        let ids = caps
            .iter()
            .map(|(c, _)| 1usize << (4 + 2 * (c & 7)))
            .min()?;
        let mut units = Vec::new();
        for (index, &(cap, ecap)) in caps.iter().enumerate() {
            units.push(Unit {
                index,
                root: hw.alloc_table()?,
                contexts: [0; 256],
                coherent: ecap & 1 != 0,
                caching_mode: cap & (1 << 7) != 0,
                write_buffer: cap & (1 << 4) != 0,
                iotlb: field(ecap, 8, 0x3ff) * 16 + 8,
                faults: (field(cap, 24, 0x3ff) * 16, field(cap, 40, 0xff) + 1),
            });
        }
        for unit in &units {
            let u = unit.index;
            flush(&mut *hw, &units, unit.root.0, 4096);
            let sts = hw.read32(u, GSTS) & PERSISTENT;
            if sts & TE != 0 {
                command(&mut *hw, u, sts & !TE, TE, 0);
            }
            hw.write64(u, RTADDR, unit.root.0);
            command(&mut *hw, u, sts & !TE | SRTP, SRTP, SRTP);
            // Faltas registradas e mascaradas até
            // [`VtD::enable_fault_irq`]; o kernel as lê com [`VtD::faults`].
            hw.write32(u, FECTL, 1 << 31);
            invalidate(&mut *hw, unit, GLOBAL_CTX, GLOBAL_IOTLB);
            command(&mut *hw, u, sts | TE, TE, TE);
        }
        let mut domains = Vec::new();
        domains.resize_with(ids.min(MAX_DOMAINS), || None);
        let inner = Inner {
            hw,
            units,
            domains,
            dmar,
            levels,
        };
        Some(Self {
            inner: SpinLock::with_class(LockClass::AddressSpace, inner),
        })
    }

    /// Unidades e níveis das tabelas de segundo nível.
    #[must_use]
    pub fn shape(&self) -> (usize, u32) {
        let i = self.inner.lock();
        (i.units.len(), i.levels)
    }

    /// Liga a interrupção de falta de todas as unidades: cada falta
    /// registrada manda a MSI `address`/`data`, e o kernel lê as faltas
    /// com [`VtD::faults`] no tratador.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "o endereço vai em duas metades de 32 bits"
    )]
    pub fn enable_fault_irq(&self, address: u64, data: u32) {
        let mut i = self.inner.lock();
        let Inner { hw, units, .. } = &mut *i;
        for unit in units.iter() {
            let u = unit.index;
            hw.write32(u, FEDATA, data);
            hw.write32(u, FEADDR, address as u32);
            hw.write32(u, FEUADDR, (address >> 32) as u32);
            hw.write32(u, FECTL, 0);
        }
    }

    /// Lê e limpa as faltas registradas em todas as unidades.
    pub fn faults(&self, out: &mut dyn FnMut(Fault)) {
        let mut i = self.inner.lock();
        let Inner { hw, units, .. } = &mut *i;
        for unit in units.iter() {
            let (u, (base, count)) = (unit.index, unit.faults);
            for r in 0..count {
                let at = base + r * 16;
                let hi = hw.read64(u, at + 8);
                if hi & (1 << 63) == 0 {
                    continue;
                }
                let lo = hw.read64(u, at);
                hw.write64(u, at + 8, 1 << 63);
                out(Fault {
                    bdf: hi as u16,
                    iova: lo & !0xfff,
                    reason: (hi >> 32) as u8,
                    write: hi & (1 << 62) == 0,
                });
            }
            // Transbordo e pendência são RW1C.
            hw.write32(u, FSTS, 0x7f);
        }
    }
}

fn field(reg: u64, shift: u32, mask: u64) -> usize {
    ((reg >> shift) & mask) as usize
}

impl Inner {
    fn flush(&mut self, phys: u64, len: usize) {
        flush(&mut *self.hw, &self.units, phys, len);
    }

    fn domain(&mut self, id: u32) -> &mut Domain {
        let d = self.domains.get_mut(id as usize).and_then(Option::as_mut);
        d.expect("vt-d: domínio inexistente")
    }

    /// Invalida o IOTLB do domínio `id` em todas as unidades.
    fn flush_domain(&mut self, id: u32) {
        for unit in &self.units {
            invalidate(&mut *self.hw, unit, 0, domain_iotlb(id));
        }
    }

    /// Libera a subárvore em `table` (nível `level`, 1 = folhas).
    fn free_tree(&mut self, table: PhysAddr, level: u32) -> u64 {
        let mut freed = 1;
        if level > 1 {
            for e in 0..512 {
                let entry = self.hw.table(table)[e];
                if entry & PRESENT != 0 {
                    freed += self.free_tree(PhysAddr(entry & ADDR), level - 1);
                }
            }
        }
        self.hw.free_table(table);
        freed
    }

    /// Entrada de contexto de `bdf` na unidade `u`: tabela e índice do
    /// `u64` baixo; com `make`, cria a tabela do barramento.
    fn context(&mut self, u: usize, bdf: u16, make: bool) -> Result<(PhysAddr, usize), Error> {
        let bus = usize::from(bdf >> 8);
        if self.units[u].contexts[bus] == 0 {
            if !make {
                return Err(Error::InvalidArgument);
            }
            let table = self.hw.alloc_table().ok_or(Error::QuotaExceeded)?;
            self.flush(table.0, 4096);
            let root = self.units[u].root;
            self.hw.table(root)[bus * 2] = table.0 | PRESENT;
            self.flush(root.0 + bus as u64 * 16, 16);
            self.units[u].contexts[bus] = table.0;
        }
        let table = PhysAddr(self.units[u].contexts[bus]);
        Ok((table, usize::from(bdf & 0xff) * 2))
    }
}

impl Iommu for VtD {
    fn create(&self, table: &mut dyn FnMut() -> Result<(), Error>) -> Result<u32, Error> {
        let mut i = self.inner.lock();
        let id = (1..i.domains.len())
            .find(|&d| i.domains[d].is_none())
            .ok_or(Error::Busy)?;
        let root = i.hw.alloc_table().ok_or(Error::QuotaExceeded)?;
        if let Err(e) = table() {
            i.hw.free_table(root);
            return Err(e);
        }
        i.flush(root.0, 4096);
        i.domains[id] = Some(Domain {
            root,
            tables: 1,
            devices: Vec::new(),
        });
        Ok(id as u32)
    }

    fn destroy(&self, id: u32) -> u64 {
        let devices = core::mem::take(&mut self.inner.lock().domain(id).devices);
        for (_, bdf) in devices {
            self.detach(id, bdf);
        }
        let mut i = self.inner.lock();
        let d = i.domains[id as usize]
            .take()
            .expect("vt-d: domínio inexistente");
        let levels = i.levels;
        let freed = i.free_tree(d.root, levels);
        debug_assert_eq!(freed, d.tables);
        freed
    }

    fn map(
        &self,
        id: u32,
        iova: u64,
        phys: PhysAddr,
        write: bool,
        table: &mut dyn FnMut() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut i = self.inner.lock();
        let mut t = i.domain(id).root;
        for level in (1..i.levels).rev() {
            let e = ((iova >> (12 + 9 * level)) & 511) as usize;
            let entry = i.hw.table(t)[e];
            t = if entry & PRESENT != 0 {
                PhysAddr(entry & ADDR)
            } else {
                let next = i.hw.alloc_table().ok_or(Error::QuotaExceeded)?;
                if let Err(err) = table() {
                    i.hw.free_table(next);
                    return Err(err);
                }
                i.flush(next.0, 4096);
                i.hw.table(t)[e] = next.0 | READ | WRITE;
                i.flush(t.0 + e as u64 * 8, 8);
                i.domain(id).tables += 1;
                next
            };
        }
        let e = ((iova >> 12) & 511) as usize;
        i.hw.table(t)[e] = phys.0 & ADDR | READ | if write { WRITE } else { 0 };
        i.flush(t.0 + e as u64 * 8, 8);
        // Com `caching mode`, a unidade guarda até entradas ausentes.
        if i.units.iter().any(|u| u.caching_mode) {
            i.flush_domain(id);
        }
        Ok(())
    }

    fn unmap(&self, id: u32, iova: u64, pages: u64) {
        let mut i = self.inner.lock();
        for p in 0..pages {
            let at = iova + p * 4096;
            let mut t = i.domain(id).root;
            for level in (1..i.levels).rev() {
                let entry = i.hw.table(t)[((at >> (12 + 9 * level)) & 511) as usize];
                assert!(entry & PRESENT != 0, "vt-d: unmap fora do mapeado");
                t = PhysAddr(entry & ADDR);
            }
            let e = ((at >> 12) & 511) as usize;
            i.hw.table(t)[e] = 0;
            i.flush(t.0 + e as u64 * 8, 8);
        }
        // Antes de voltar: o objeto pode ser solto logo depois.
        i.flush_domain(id);
    }

    fn attach(&self, id: u32, bdf: u16) -> Result<(), Error> {
        let mut i = self.inner.lock();
        let u = i.dmar.unit_for(bdf).ok_or(Error::InvalidArgument)?;
        let levels = i.levels;
        let root = i.domain(id).root;
        i.domain(id)
            .devices
            .try_reserve(1)
            .map_err(|_| Error::QuotaExceeded)?;
        let (table, e) = i.context(u, bdf, true)?;
        if i.hw.table(table)[e] & PRESENT != 0 {
            return Err(Error::Busy);
        }
        // Largura (1 = 3 níveis, 2 = 4) e domínio na metade alta; o bit de
        // presença por último.
        i.hw.table(table)[e + 1] = u64::from(levels - 2) | u64::from(id) << 8;
        i.hw.table(table)[e] = root.0 | PRESENT;
        i.flush(table.0 + e as u64 * 8, 16);
        let Inner { hw, units, .. } = &mut *i;
        invalidate(&mut **hw, &units[u], GLOBAL_CTX, domain_iotlb(id));
        i.domain(id).devices.push((u, bdf));
        Ok(())
    }

    fn detach(&self, id: u32, bdf: u16) {
        let mut i = self.inner.lock();
        let Some(u) = i.dmar.unit_for(bdf) else {
            return;
        };
        let ours = |hi: u64| (hi >> 8) & 0xffff == u64::from(id);
        if let Ok((table, e)) = i.context(u, bdf, false)
            && ours(i.hw.table(table)[e + 1])
        {
            i.hw.table(table)[e] = 0;
            i.hw.table(table)[e + 1] = 0;
            i.flush(table.0 + e as u64 * 8, 16);
            let Inner { hw, units, .. } = &mut *i;
            invalidate(&mut **hw, &units[u], GLOBAL_CTX, domain_iotlb(id));
        }
        i.domain(id).devices.retain(|&(_, b)| b != bdf);
    }
}

#[cfg(test)]
mod tests;
