//! `DmaDomain` (ADR 0044; T-403): o domínio de DMA de um driver.
//!
//! O domínio guarda os mapeamentos `iova → páginas de um MemoryObject` e os
//! dispositivos ligados a ele. Os mapeamentos seguram o objeto vivo: os
//! frames não voltam ao buddy enquanto o dispositivo puder alcançá-los.
//! Quem programa o hardware é o [`Iommu`] instalado pelo kernel (VT-d ou
//! AMD-Vi). Sem IOMMU (item 5), o domínio é só lógico: `dma_map` confere e
//! devolve o endereço físico, que precisa ser contíguo, e o sistema avisa
//! "isolamento de DMA ausente".
//!
//! Travas: a do domínio e `ATTACHED` são de objeto (nível 3), nunca as
//! duas na mão; o [`Iommu`] toma as dele depois (nível 5), sem voltar a
//! objetos.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use kabi::Error;
use kabi::vm::PAGE_SIZE;

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota};
use crate::mm::PhysAddr;
use crate::sync::{LockClass, SpinLock};
use crate::vm::MemoryObject;

/// Primeiro endereço fora da faixa de IOVA aceita (39 bits: as tabelas de
/// três níveis que toda IOMMU suportada aceita).
pub const IOVA_END: u64 = 1 << 39;

/// Hardware de IOMMU (ADR 0044, item 1): o kernel instala um no boot.
pub trait Iommu: Sync {
    /// Cria a tabela de um domínio novo; devolve o id dele. `table` é
    /// chamado antes de cada frame de tabela, para cobrar a cota do dono.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota ou sem frame; [`Error::Busy`] sem
    /// id livre.
    fn create(&self, table: &mut dyn FnMut() -> Result<(), Error>) -> Result<u32, Error>;
    /// Desliga os dispositivos que sobraram e libera a tabela de `id`;
    /// devolve quantos frames de tabela saíram.
    fn destroy(&self, id: u32) -> u64;
    /// Mapeia `phys` em `iova` no domínio `id` (leitura sempre; escrita com
    /// `write`).
    ///
    /// # Errors
    ///
    /// Os de [`create`](Self::create).
    fn map(
        &self,
        id: u32,
        iova: u64,
        phys: PhysAddr,
        write: bool,
        table: &mut dyn FnMut() -> Result<(), Error>,
    ) -> Result<(), Error>;
    /// Tira `pages` páginas a partir de `iova` e invalida o IOTLB do
    /// domínio antes de voltar.
    fn unmap(&self, id: u32, iova: u64, pages: u64);
    /// Liga o dispositivo `bdf` ao domínio `id`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] se nenhuma unidade cobre `bdf`.
    fn attach(&self, id: u32, bdf: u16) -> Result<(), Error>;
    /// Desliga `bdf`: o DMA dele volta a ser bloqueado.
    fn detach(&self, id: u32, bdf: u16);
}

static IOMMU: SpinLock<Option<&'static dyn Iommu>> =
    SpinLock::with_class(LockClass::Diagnostic, None);

/// Instala o hardware de IOMMU (uma vez, no boot).
pub fn install(iommu: &'static dyn Iommu) {
    *IOMMU.lock() = Some(iommu);
}

/// O hardware instalado; `None` é "isolamento de DMA ausente".
pub fn iommu() -> Option<&'static dyn Iommu> {
    *IOMMU.lock()
}

/// Dispositivos ligados a algum domínio: um `bdf` só pode estar num.
static ATTACHED: SpinLock<Vec<(u16, Weak<DmaDomain>)>> =
    SpinLock::with_class(LockClass::Object, Vec::new());

struct Map {
    iova: u64,
    pages: u64,
    /// Segura os frames enquanto o dispositivo os alcança.
    _object: Arc<MemoryObject>,
}

struct State {
    /// Cota do dono: o objeto, os registros e as tabelas de hardware.
    charge: Charge,
    /// Id no hardware, se houver IOMMU.
    hw: Option<(&'static dyn Iommu, u32)>,
    maps: Vec<Map>,
    devices: Vec<u16>,
}

/// Domínio de DMA (tipo 11; ADR 0044, item 2).
pub struct DmaDomain {
    state: SpinLock<State>,
}

impl core::fmt::Debug for DmaDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DmaDomain")
    }
}

/// Custo de um registro de mapeamento ou de dispositivo.
const RECORD: u64 = size_of::<Map>() as u64;

impl DmaDomain {
    /// Domínio novo, cobrado de `quota`; com IOMMU, já com a tabela.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota; os de [`Iommu::create`].
    pub fn new(quota: &Arc<MemoryQuota>) -> Result<Self, Error> {
        Self::with_unit(quota, iommu())
    }

    /// [`new`](Self::new) com a unidade explícita (os testes usam uma
    /// falsa sem tocar na instalada).
    fn with_unit(
        quota: &Arc<MemoryQuota>,
        unit: Option<&'static dyn Iommu>,
    ) -> Result<Self, Error> {
        let mut charge = quota.charge(object_bytes::<Self>())?;
        let hw = match unit {
            Some(unit) => {
                let mut table = || charge.grow(PAGE_SIZE);
                Some((unit, unit.create(&mut table)?))
            }
            None => None,
        };
        Ok(Self {
            state: SpinLock::with_class(
                LockClass::Object,
                State {
                    charge,
                    hw,
                    maps: Vec::new(),
                    devices: Vec::new(),
                },
            ),
        })
    }

    /// `dma_map`: `len` bytes de `object` a partir de `offset` em `iova`.
    /// Devolve o endereço que o dispositivo usa: `iova` com IOMMU; sem
    /// IOMMU, o físico da primeira página (a faixa tem de ser contígua).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para faixa desalinhada, vazia, fora do
    /// objeto, fora de [`IOVA_END`], sobre outro mapeamento, num objeto de
    /// MMIO ou não contígua sem IOMMU; [`Error::NotSupported`] num objeto
    /// `LAZY` (páginas podem sair); [`Error::QuotaExceeded`] sem cota.
    pub fn map(
        &self,
        object: &Arc<MemoryObject>,
        iova: u64,
        offset: u64,
        len: u64,
        write: bool,
    ) -> Result<u64, Error> {
        if object.is_lazy() {
            return Err(Error::NotSupported);
        }
        let end = iova.checked_add(len).ok_or(Error::InvalidArgument)?;
        let (first, pages) = (offset / PAGE_SIZE, len / PAGE_SIZE);
        let fits = first
            .checked_add(pages)
            .is_some_and(|l| l <= object.pages());
        if object.is_device()
            || len == 0
            || !iova.is_multiple_of(PAGE_SIZE)
            || !offset.is_multiple_of(PAGE_SIZE)
            || !len.is_multiple_of(PAGE_SIZE)
            || end > IOVA_END
            || !fits
        {
            return Err(Error::InvalidArgument);
        }
        let frame = |i: u64| object.frame(first + i).ok_or(Error::InvalidArgument);
        let mut s = self.state.lock();
        if s.maps
            .iter()
            .any(|m| m.iova < end && iova < m.iova + m.pages * PAGE_SIZE)
        {
            return Err(Error::InvalidArgument);
        }
        s.maps.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
        let base = frame(0)?;
        let address = if s.hw.is_some() {
            iova
        } else {
            for i in 1..pages {
                if frame(i)?.0 != base.0 + i * PAGE_SIZE {
                    return Err(Error::InvalidArgument);
                }
            }
            base.0
        };
        s.charge.grow(RECORD)?;
        if let Some((unit, id)) = s.hw {
            let State { charge, .. } = &mut *s;
            let mut table = || charge.grow(PAGE_SIZE);
            for i in 0..pages {
                let done =
                    frame(i).and_then(|f| unit.map(id, iova + i * PAGE_SIZE, f, write, &mut table));
                if let Err(e) = done {
                    unit.unmap(id, iova, i);
                    charge.shrink(RECORD);
                    return Err(e);
                }
            }
        }
        s.maps.push(Map {
            iova,
            pages,
            _object: Arc::clone(object),
        });
        Ok(address)
    }

    /// `dma_unmap` do mapeamento que começa em `iova` com `len` bytes; o
    /// IOTLB é invalidado antes de o objeto ser solto.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] se não houver mapeamento exatamente ali.
    pub fn unmap(&self, iova: u64, len: u64) -> Result<(), Error> {
        let removed = {
            let mut s = self.state.lock();
            let i = s
                .maps
                .iter()
                .position(|m| m.iova == iova && m.pages * PAGE_SIZE == len)
                .ok_or(Error::InvalidArgument)?;
            if let Some((unit, id)) = s.hw {
                unit.unmap(id, iova, len / PAGE_SIZE);
            }
            s.charge.shrink(RECORD);
            s.maps.swap_remove(i)
        };
        // O objeto pode morrer aqui, fora da trava do domínio.
        drop(removed);
        Ok(())
    }

    /// `dma_attach` (ADR 0044, item 3): liga `bdf` a este domínio.
    ///
    /// # Errors
    ///
    /// [`Error::Busy`] se `bdf` já está num domínio vivo;
    /// [`Error::QuotaExceeded`] sem cota; os de [`Iommu::attach`].
    pub fn attach(self: &Arc<Self>, bdf: u16) -> Result<(), Error> {
        // `ATTACHED` e o domínio são da mesma classe: nunca os dois na mão.
        // A vaga em `ATTACHED` vem primeiro e sai se o resto falhar.
        {
            let mut all = ATTACHED.lock();
            all.retain(|(_, w)| w.strong_count() > 0);
            if all.iter().any(|(b, _)| *b == bdf) {
                return Err(Error::Busy);
            }
            all.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
            all.push((bdf, Arc::downgrade(self)));
        }
        let done = self.attach_hw(bdf);
        if done.is_err() {
            self.release(bdf);
        }
        done
    }

    fn attach_hw(&self, bdf: u16) -> Result<(), Error> {
        let mut s = self.state.lock();
        s.devices.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
        s.charge.grow(RECORD)?;
        if let Some((unit, id)) = s.hw
            && let Err(e) = unit.attach(id, bdf)
        {
            s.charge.shrink(RECORD);
            return Err(e);
        }
        s.devices.push(bdf);
        Ok(())
    }

    /// Tira a vaga de `bdf` deste domínio em `ATTACHED`.
    fn release(self: &Arc<Self>, bdf: u16) {
        let me = Arc::as_ptr(self);
        ATTACHED
            .lock()
            .retain(|(b, w)| *b != bdf || !core::ptr::eq(w.as_ptr(), me));
    }

    /// `dma_detach`: desliga `bdf` deste domínio.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] se `bdf` não está ligado aqui.
    pub fn detach(self: &Arc<Self>, bdf: u16) -> Result<(), Error> {
        {
            let mut s = self.state.lock();
            let i = s
                .devices
                .iter()
                .position(|&b| b == bdf)
                .ok_or(Error::InvalidArgument)?;
            if let Some((unit, id)) = s.hw {
                unit.detach(id, bdf);
            }
            s.devices.swap_remove(i);
            s.charge.shrink(RECORD);
        }
        self.release(bdf);
        Ok(())
    }

    /// Mapeamentos e dispositivos (para os testes).
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        let s = self.state.lock();
        (s.maps.len(), s.devices.len())
    }
}

impl Drop for DmaDomain {
    fn drop(&mut self) {
        let s = self.state.get_mut();
        // Desliga e libera a tabela antes de soltar os objetos: nenhum DMA
        // alcança um frame que volta ao buddy.
        if let Some((unit, id)) = s.hw.take() {
            let tables = unit.destroy(id);
            s.charge.shrink(tables * PAGE_SIZE);
        }
        s.maps.clear();
        // As entradas de `ATTACHED` deste domínio ficam com `Weak` morto e
        // saem no próximo `attach`.
    }
}

#[cfg(test)]
mod tests;
