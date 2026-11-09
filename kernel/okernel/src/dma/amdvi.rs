//! Backend de AMD-Vi do [`Iommu`] (ADR 0044, item 1; T-403).
//!
//! Cada unidade tem uma tabela de dispositivos (65 536 entradas de 32
//! bytes, 2 MiB contíguos), um buffer de comandos e um log de eventos. Toda
//! entrada nasce apontando para uma tabela vazia (domínio 0): o DMA de todo
//! dispositivo vira falta registrada até o `dma_attach`. As tabelas dos
//! domínios são de 3 níveis (IOVA de 39 bits), no formato da AMD, e
//! compartilhadas entre unidades. Toda mudança é seguida de invalidação e
//! de `COMPLETION_WAIT`, esperado antes de voltar.
//!
//! O acesso aos registradores fica atrás do mesmo [`Hw`] do VT-d. A trava
//! é de nível 5, como a do VT-d.

#![allow(
    clippy::cast_possible_truncation,
    reason = "campos de registradores e índices de tabela têm largura fixa"
)]

use alloc::boxed::Box;
use alloc::vec::Vec;

use kabi::Error;

use super::Iommu;
use super::vtd::{Fault, Hw};
use crate::acpi::ivrs::Ivrs;
use crate::mm::PhysAddr;
use crate::sync::{LockClass, SpinLock};

pub(crate) const DEV_TAB: usize = 0x0000;
pub(crate) const CMD_BUF: usize = 0x0008;
pub(crate) const EVT_LOG: usize = 0x0010;
pub(crate) const CONTROL: usize = 0x0018;
pub(crate) const CMD_HEAD: usize = 0x2000;
pub(crate) const CMD_TAIL: usize = 0x2008;
pub(crate) const EVT_HEAD: usize = 0x2010;
pub(crate) const EVT_TAIL: usize = 0x2018;

const IOMMU_EN: u64 = 1;
const EVENT_LOG_EN: u64 = 1 << 2;
const COHERENT: u64 = 1 << 10;
const CMD_BUF_EN: u64 = 1 << 12;
/// 2 MiB de tabela de dispositivos: 512 páginas (o campo leva páginas − 1).
const DEV_TAB_ORDER: u32 = 9;
/// Buffers de comandos e de eventos: 256 entradas de 16 bytes (4 KiB).
const RING_LEN: u64 = 8 << 56;
const RING_BYTES: u64 = 4096;

const VALID: u64 = 1;
const TRANSLATE: u64 = 1 << 1;
const IR: u64 = 1 << 61;
const IW: u64 = 1 << 62;
const PRESENT: u64 = 1;
const ADDR: u64 = 0x000f_ffff_ffff_f000;
/// Níveis das tabelas de domínio (modo 3: 39 bits).
const LEVELS: u32 = 3;
/// Voltas de espera por um comando antes do pânico.
const SPIN: u32 = 10_000_000;
/// Domínios aceitos (o id 0 fica reservado).
const MAX_DOMAINS: usize = 1024;

const COMPLETION_WAIT: u32 = 1 << 28;
const INVALIDATE_DTE: u32 = 2 << 28;
const INVALIDATE_PAGES: u32 = 3 << 28;
/// Invalidar todas as páginas do domínio: endereço máximo, S e PDE.
const ALL_PAGES: u64 = 0x7fff_ffff_ffff_f000 | 3;
const IO_PAGE_FAULT: u32 = 2;

struct Unit {
    index: usize,
    dev_table: PhysAddr,
    cmd: PhysAddr,
    events: PhysAddr,
    /// Página do semáforo do `COMPLETION_WAIT`.
    sem: PhysAddr,
    /// Tabela de nível 3 vazia, do domínio 0: a dos dispositivos sem
    /// domínio, em que todo acesso é falta registrada.
    empty: PhysAddr,
    tail: u64,
    seq: u64,
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
    ivrs: Ivrs,
}

/// As IOMMUs da AMD da máquina.
pub struct AmdVi {
    inner: SpinLock<Inner>,
}

/// Entrada de dispositivo sem domínio: tradução de 3 níveis pela tabela
/// vazia da unidade (domínio 0). Todo acesso falha na primeira tabela e vira
/// evento de falta de página; só IR e IW zerados bloqueariam sem registro
/// no QEMU.
fn blocked(unit: &Unit) -> u64 {
    unit.empty.0 | u64::from(LEVELS) << 9 | IR | IW | TRANSLATE | VALID
}

/// Página e índice do primeiro `u64` da entrada de `bdf`.
fn dte(unit: &Unit, bdf: u16) -> (PhysAddr, usize) {
    let page = unit.dev_table.0 + u64::from(bdf >> 7) * 4096;
    (PhysAddr(page), usize::from(bdf & 127) * 4)
}

impl Inner {
    fn domain(&mut self, id: u32) -> &mut Domain {
        let d = self.domains.get_mut(id as usize).and_then(Option::as_mut);
        d.expect("amd-vi: domínio inexistente")
    }

    /// Põe um comando no buffer da unidade `u`.
    fn command(&mut self, u: usize, cmd: [u32; 4]) {
        let unit = &mut self.units[u];
        let at = (unit.tail / 8) as usize;
        let t = self.hw.table(unit.cmd);
        t[at] = u64::from(cmd[0]) | u64::from(cmd[1]) << 32;
        t[at + 1] = u64::from(cmd[2]) | u64::from(cmd[3]) << 32;
        unit.tail = (unit.tail + 16) % RING_BYTES;
        self.hw.write64(u, CMD_TAIL, unit.tail);
    }

    /// `COMPLETION_WAIT` com escrita no semáforo, esperado até chegar.
    fn wait(&mut self, u: usize) {
        self.units[u].seq += 1;
        let (seq, sem) = (self.units[u].seq, self.units[u].sem.0);
        let lo = (sem as u32 & !7) | 1;
        let hi = COMPLETION_WAIT | ((sem >> 32) as u32 & 0xf_ffff);
        self.command(u, [lo, hi, seq as u32, (seq >> 32) as u32]);
        let page = self.units[u].sem;
        for _ in 0..SPIN {
            if self.hw.table(page)[0] == seq {
                return;
            }
            core::hint::spin_loop();
        }
        panic!("amd-vi: a unidade não completou os comandos");
    }

    fn invalidate_dte(&mut self, u: usize, bdf: u16) {
        self.command(u, [u32::from(bdf), INVALIDATE_DTE, 0, 0]);
        self.wait(u);
    }

    /// Invalida as páginas do domínio `id` em todas as unidades.
    fn flush_domain(&mut self, id: u32) {
        for u in 0..self.units.len() {
            let cmd = [
                0,
                INVALIDATE_PAGES | id,
                ALL_PAGES as u32,
                (ALL_PAGES >> 32) as u32,
            ];
            self.command(u, cmd);
            self.wait(u);
        }
    }

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
}

impl AmdVi {
    /// Liga cada unidade da `ivrs` com todo DMA bloqueado; `regs` dá o
    /// índice de [`Hw`] de cada uma. `None` sem unidades ou sem memória.
    ///
    /// # Panics
    ///
    /// Se uma unidade não completar os comandos.
    #[must_use]
    pub fn new(mut hw: Box<dyn Hw>, ivrs: Ivrs) -> Option<Self> {
        let n = ivrs.units().len();
        if n == 0 {
            return None;
        }
        let mut units = Vec::new();
        for index in 0..n {
            let dev_table = hw.alloc_contiguous(DEV_TAB_ORDER)?;
            let (cmd, events) = (hw.alloc_table()?, hw.alloc_table()?);
            let (sem, empty) = (hw.alloc_table()?, hw.alloc_table()?);
            units.push(Unit {
                index,
                dev_table,
                cmd,
                events,
                sem,
                empty,
                tail: 0,
                seq: 0,
            });
        }
        let mut inner = Inner {
            hw,
            units,
            domains: Vec::new(),
            ivrs,
        };
        for u in 0..n {
            let (dev_table, cmd, events) = {
                let unit = &inner.units[u];
                (unit.dev_table, unit.cmd, unit.events)
            };
            let blocked = blocked(&inner.units[u]);
            let hw = &mut *inner.hw;
            for page in 0..1u64 << DEV_TAB_ORDER {
                let t = hw.table(PhysAddr(dev_table.0 + page * 4096));
                for e in (0..512).step_by(4) {
                    t[e] = blocked;
                }
            }
            hw.write64(u, CONTROL, 0);
            hw.write64(u, DEV_TAB, dev_table.0 | ((1 << DEV_TAB_ORDER) - 1));
            hw.write64(u, CMD_BUF, cmd.0 | RING_LEN);
            hw.write64(u, EVT_LOG, events.0 | RING_LEN);
            for reg in [CMD_HEAD, CMD_TAIL, EVT_HEAD, EVT_TAIL] {
                hw.write64(u, reg, 0);
            }
            hw.write64(u, CONTROL, IOMMU_EN | EVENT_LOG_EN | COHERENT | CMD_BUF_EN);
            inner.wait(u);
        }
        inner.domains.resize_with(MAX_DOMAINS, || None);
        Some(Self {
            inner: SpinLock::with_class(LockClass::AddressSpace, inner),
        })
    }

    /// Quantas unidades.
    #[must_use]
    pub fn units(&self) -> usize {
        self.inner.lock().units.len()
    }

    /// Lê os eventos de falta de página de todas as unidades e avança o
    /// log; os outros eventos são descartados.
    pub fn faults(&self, out: &mut dyn FnMut(Fault)) {
        let mut i = self.inner.lock();
        let Inner { hw, units, .. } = &mut *i;
        for unit in units.iter() {
            let u = unit.index;
            let (mut head, tail) = (hw.read64(u, EVT_HEAD), hw.read64(u, EVT_TAIL));
            while head != tail {
                let at = (head / 8) as usize;
                let (lo, addr) = {
                    let t = hw.table(unit.events);
                    (t[at], t[at + 1])
                };
                let hi = (lo >> 32) as u32;
                if hi >> 28 == IO_PAGE_FAULT {
                    out(Fault {
                        bdf: lo as u16,
                        iova: addr & !0xfff,
                        reason: IO_PAGE_FAULT as u8,
                        write: hi & (1 << 21) != 0,
                    });
                }
                head = (head + 16) % RING_BYTES;
            }
            hw.write64(u, EVT_HEAD, head);
        }
    }
}

impl Iommu for AmdVi {
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
            .expect("amd-vi: domínio inexistente");
        let freed = i.free_tree(d.root, LEVELS);
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
        for level in (1..LEVELS).rev() {
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
                // Diretório: aponta para o nível de baixo, com IR e IW.
                i.hw.table(t)[e] = next.0 | u64::from(level) << 9 | IR | IW | PRESENT;
                i.domain(id).tables += 1;
                next
            };
        }
        let e = ((iova >> 12) & 511) as usize;
        i.hw.table(t)[e] = phys.0 & ADDR | IR | if write { IW } else { 0 } | PRESENT;
        Ok(())
    }

    fn unmap(&self, id: u32, iova: u64, pages: u64) {
        let mut i = self.inner.lock();
        for p in 0..pages {
            let at = iova + p * 4096;
            let mut t = i.domain(id).root;
            for level in (1..LEVELS).rev() {
                let entry = i.hw.table(t)[((at >> (12 + 9 * level)) & 511) as usize];
                assert!(entry & PRESENT != 0, "amd-vi: unmap fora do mapeado");
                t = PhysAddr(entry & ADDR);
            }
            i.hw.table(t)[((at >> 12) & 511) as usize] = 0;
        }
        // Antes de voltar: o objeto pode ser solto logo depois.
        i.flush_domain(id);
    }

    fn attach(&self, id: u32, bdf: u16) -> Result<(), Error> {
        let mut i = self.inner.lock();
        let u = i.ivrs.unit_for(bdf).ok_or(Error::InvalidArgument)?;
        let root = i.domain(id).root;
        i.domain(id)
            .devices
            .try_reserve(1)
            .map_err(|_| Error::QuotaExceeded)?;
        let (page, e) = dte(&i.units[u], bdf);
        if i.hw.table(page)[e + 1] & 0xffff != 0 {
            return Err(Error::Busy);
        }
        // Domínio primeiro; a entrada com tradução e permissões por último.
        i.hw.table(page)[e + 1] = u64::from(id);
        i.hw.table(page)[e] = root.0 | u64::from(LEVELS) << 9 | IR | IW | TRANSLATE | VALID;
        i.invalidate_dte(u, bdf);
        i.domain(id).devices.push((u, bdf));
        Ok(())
    }

    fn detach(&self, id: u32, bdf: u16) {
        let mut i = self.inner.lock();
        let Some(u) = i.ivrs.unit_for(bdf) else {
            return;
        };
        let (page, e) = dte(&i.units[u], bdf);
        if i.hw.table(page)[e + 1] & 0xffff == u64::from(id) {
            i.hw.table(page)[e] = blocked(&i.units[u]);
            i.hw.table(page)[e + 1] = 0;
            i.invalidate_dte(u, bdf);
            i.flush_domain(id);
        }
        i.domain(id).devices.retain(|&(_, b)| b != bdf);
    }
}

#[cfg(test)]
mod tests;
