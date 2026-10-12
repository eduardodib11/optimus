//! `AddressSpace` e as syscalls `vm_map`, `vm_unmap` e `vm_protect` (T-205).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::mem::size_of;

use kabi::vm::{PAGE_SIZE, USER_END, USER_START};
use kabi::{Error, Rights};

use super::{MemoryObject, Perms};
use crate::cap::object::object_bytes;
use crate::cap::{Cap, Charge, MemoryQuota};
use crate::mm::PhysAddr;
use crate::mm::paging::{ENTRIES, MapError, PageSize, PageTables, Table, TableMemory};
use crate::platform::Platform;
use crate::sync::SpinLock;

/// `AddressSpace` compartilhado; a trava vem depois da do `CapSpace` e da
/// do objeto na ordem da seção 6.9.
pub type SharedAddressSpace = SpinLock<AddressSpace>;

/// Tabelas de um espaço, contando as vivas para cobrá-las da cota.
struct Counted {
    inner: Box<dyn TableMemory + Send>,
    live: u64,
}

impl TableMemory for Counted {
    fn table(&mut self, phys: PhysAddr) -> &mut Table {
        self.inner.table(phys)
    }

    fn alloc_table(&mut self) -> Option<PhysAddr> {
        let table = self.inner.alloc_table()?;
        self.live += 1;
        Some(table)
    }

    fn free_table(&mut self, phys: PhysAddr) {
        self.live -= 1;
        self.inner.free_table(phys);
    }
}

/// Faixa contínua mapeada de um mesmo objeto.
#[derive(Clone, Debug)]
struct Region {
    start: u64,
    pages: u64,
    object: Arc<MemoryObject>,
    /// Página do objeto mapeada em `start`.
    first: u64,
    perms: Perms,
    /// Permissões máximas, dadas pela capability do objeto no `vm_map`.
    max: Perms,
}

impl Region {
    const BYTES: u64 = size_of::<Self>() as u64;

    const fn end(&self) -> u64 {
        self.start + self.pages * PAGE_SIZE
    }

    /// O pedaço `[start, end)` desta região.
    fn sub(&self, start: u64, end: u64) -> Self {
        Self {
            start,
            pages: (end - start) / PAGE_SIZE,
            object: Arc::clone(&self.object),
            first: self.first + (start - self.start) / PAGE_SIZE,
            perms: self.perms,
            max: self.max,
        }
    }
}

/// Espaço de endereçamento de um processo.
pub struct AddressSpace {
    /// Objeto, tabelas vivas e regiões.
    charge: Charge,
    tables: PageTables<Counted>,
    platform: &'static dyn Platform,
    /// Regiões em ordem de endereço, sem sobreposição.
    regions: Vec<Region>,
}

impl fmt::Debug for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AddressSpace(raiz {:#x}, {} regiões)",
            self.tables.root().0,
            self.regions.len()
        )
    }
}

fn map_error(e: MapError) -> Error {
    match e {
        MapError::OutOfFrames => Error::QuotaExceeded,
        _ => Error::InvalidArgument,
    }
}

/// Endereços das páginas de `[start, end)`.
fn pages_of(start: u64, end: u64) -> impl Iterator<Item = u64> {
    (0..(end - start) / PAGE_SIZE).map(move |i| start + i * PAGE_SIZE)
}

/// Confere uma faixa de usuário alinhada e não vazia; devolve o fim.
fn user_range(start: u64, len: u64) -> Result<u64, Error> {
    let end = start.checked_add(len).ok_or(Error::InvalidArgument)?;
    let aligned = start.is_multiple_of(PAGE_SIZE) && len.is_multiple_of(PAGE_SIZE);
    if !aligned || len == 0 || start < USER_START || end > USER_END {
        return Err(Error::InvalidArgument);
    }
    Ok(end)
}

impl AddressSpace {
    /// Espaço vazio com a metade alta do kernel, cobrado de `quota`.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota ou sem frame para o PML4.
    pub fn new(quota: &Arc<MemoryQuota>, platform: &'static dyn Platform) -> Result<Self, Error> {
        let charge = quota.charge(object_bytes::<SharedAddressSpace>() + PAGE_SIZE)?;
        let mut mem = Counted {
            inner: platform.tables(),
            live: 0,
        };
        let root = mem.alloc_table().ok_or(Error::QuotaExceeded)?;
        // As entradas da metade alta do PML4 do kernel existem todas desde
        // o boot e não mudam: copiá-las compartilha as tabelas de baixo.
        let kernel = platform.kernel_root();
        for i in ENTRIES / 2..ENTRIES {
            let entry = mem.table(kernel)[i];
            mem.table(root)[i] = entry;
        }
        Ok(Self {
            charge,
            tables: PageTables::new(root, mem),
            platform,
            regions: Vec::new(),
        })
    }

    /// Endereço físico do PML4, para o CR3.
    #[must_use]
    pub const fn root(&self) -> PhysAddr {
        self.tables.root()
    }

    /// Bytes cobrados: objeto, tabelas e regiões.
    #[must_use]
    pub const fn charged(&self) -> u64 {
        self.charge.bytes()
    }

    /// Tabelas de página vivas, PML4 incluído.
    #[must_use]
    pub fn live_tables(&mut self) -> u64 {
        self.tables.memory().live
    }

    /// Regiões mapeadas.
    #[must_use]
    pub fn regions(&self) -> usize {
        self.regions.len()
    }

    /// Permissões da página em `virt`, se mapeada.
    #[must_use]
    pub fn query(&mut self, virt: u64) -> Option<(PhysAddr, Perms)> {
        let m = self.tables.translate(virt)?;
        Some((
            m.phys,
            Perms {
                write: m.flags.write,
                exec: m.flags.exec,
            },
        ))
    }

    /// Reserva cota e espaço no vetor para `extra` regiões novas.
    fn reserve_regions(&mut self, extra: u64) -> Result<(), Error> {
        self.charge.grow(extra * Region::BYTES)?;
        let more = usize::try_from(extra).unwrap_or(usize::MAX);
        if self.regions.try_reserve(more).is_err() {
            self.charge.shrink(extra * Region::BYTES);
            return Err(Error::QuotaExceeded);
        }
        Ok(())
    }

    /// Desmapeia as páginas de `[start, end)` e invalida as traduções em
    /// toda CPU de uma vez (um shootdown por chamada, ADR 0031, item 7),
    /// antes que qualquer objeto que saia do espaço possa morrer.
    fn unmap_pages(&mut self, start: u64, end: u64) {
        let mut any = false;
        for page in pages_of(start, end) {
            any |= self.tables.unmap(page, PageSize::Size4K).is_ok();
        }
        if any {
            self.platform
                .flush(self.root(), start, (end - start) / PAGE_SIZE);
        }
    }

    /// Mapeia `len` bytes de `object`, a partir do byte `offset` dele, em
    /// `start`, com `perms` (que não podem passar de `max`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para faixa fora do usuário, desalinhada,
    /// além do objeto ou sobre região já mapeada; [`Error::AccessDenied`]
    /// se `perms` passar de `max`; [`Error::QuotaExceeded`] sem cota para
    /// tabelas e região. Nada muda em caso de erro.
    pub fn map(
        &mut self,
        start: u64,
        object: &Arc<MemoryObject>,
        offset: u64,
        len: u64,
        perms: Perms,
        max: Perms,
    ) -> Result<(), Error> {
        let end = user_range(start, len)?;
        if !perms.within(max) {
            return Err(Error::AccessDenied);
        }
        let (first, pages) = (offset / PAGE_SIZE, len / PAGE_SIZE);
        let fits = first
            .checked_add(pages)
            .is_some_and(|last| last <= object.pages());
        if !offset.is_multiple_of(PAGE_SIZE) || !fits {
            return Err(Error::InvalidArgument);
        }
        if self
            .regions
            .iter()
            .any(|r| r.start < end && start < r.end())
        {
            return Err(Error::InvalidArgument);
        }
        let needed = self.tables.tables_needed(start, end);
        self.charge.grow(needed * PAGE_SIZE)?;
        if let Err(e) = self.reserve_regions(1) {
            self.charge.shrink(needed * PAGE_SIZE);
            return Err(e);
        }
        let before = self.live_tables();
        let mut failed = None;
        let mut done = 0;
        while done < pages {
            let frame = object.frame(first + done).ok_or(MapError::NotMapped);
            let virt = start + done * PAGE_SIZE;
            match frame.and_then(|f| {
                self.tables
                    .map(virt, f, PageSize::Size4K, perms.page_flags())
            }) {
                Ok(()) => done += 1,
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        let used = self.live_tables() - before;
        self.charge.shrink(needed.saturating_sub(used) * PAGE_SIZE);
        if let Some(e) = failed {
            self.unmap_pages(start, start + done * PAGE_SIZE);
            self.charge.shrink(Region::BYTES);
            return Err(map_error(e));
        }
        let at = self.regions.partition_point(|r| r.start < start);
        self.regions.insert(
            at,
            Region {
                start,
                pages,
                object: Arc::clone(object),
                first,
                perms,
                max,
            },
        );
        Ok(())
    }

    /// Desmapeia as páginas de `[start, start + len)`; páginas sem
    /// mapeamento são ignoradas. Os objetos sem outras referências morrem.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para faixa inválida;
    /// [`Error::QuotaExceeded`] se for preciso partir uma região em duas
    /// sem cota para isso. Nada muda em caso de erro.
    pub fn unmap(&mut self, start: u64, len: u64) -> Result<(), Error> {
        let end = user_range(start, len)?;
        let splits = self
            .regions
            .iter()
            .any(|r| r.start < start && end < r.end());
        if splits {
            self.reserve_regions(1)?;
        }
        // As regiões (e talvez os objetos, com os frames) só saem depois do
        // shootdown.
        self.unmap_pages(start, end);
        let mut i = 0;
        while i < self.regions.len() {
            let r = &self.regions[i];
            let (rs, re) = (r.start, r.end());
            if re <= start || end <= rs {
                i += 1;
                continue;
            }
            match (rs < start, end < re) {
                (true, true) => {
                    let tail = r.sub(end, re);
                    self.regions[i] = r.sub(rs, start);
                    self.regions.insert(i + 1, tail);
                    i += 2;
                }
                (true, false) => {
                    self.regions[i] = r.sub(rs, start);
                    i += 1;
                }
                (false, true) => {
                    self.regions[i] = r.sub(end, re);
                    i += 1;
                }
                (false, false) => {
                    self.regions.remove(i);
                    self.charge.shrink(Region::BYTES);
                }
            }
        }
        Ok(())
    }

    /// Parte a região que contém `addr` no meio (se houver uma).
    fn split_at(&mut self, addr: u64) {
        if let Some(i) = self
            .regions
            .iter()
            .position(|r| r.start < addr && addr < r.end())
        {
            let r = &self.regions[i];
            let tail = r.sub(addr, r.end());
            self.regions[i] = r.sub(r.start, addr);
            self.regions.insert(i + 1, tail);
        }
    }

    /// Troca as permissões das páginas de `[start, start + len)`, que
    /// precisam estar todas mapeadas.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para faixa inválida ou com buracos;
    /// [`Error::AccessDenied`] se `perms` passar do máximo de alguma
    /// região; [`Error::QuotaExceeded`] sem cota para partir regiões. Nada
    /// muda em caso de erro.
    pub fn protect(&mut self, start: u64, len: u64, perms: Perms) -> Result<(), Error> {
        let end = user_range(start, len)?;
        let mut cursor = start;
        for r in self
            .regions
            .iter()
            .filter(|r| start < r.end() && r.start < end)
        {
            if r.start > cursor {
                return Err(Error::InvalidArgument);
            }
            if !perms.within(r.max) {
                return Err(Error::AccessDenied);
            }
            cursor = r.end();
        }
        if cursor < end {
            return Err(Error::InvalidArgument);
        }
        let inside = |a: u64| self.regions.iter().any(|r| r.start < a && a < r.end());
        let extra = u64::from(inside(start)) + u64::from(inside(end));
        self.reserve_regions(extra)?;
        self.split_at(start);
        self.split_at(end);
        for r in &mut self.regions {
            if start <= r.start && r.end() <= end {
                r.perms = perms;
            }
        }
        for page in pages_of(start, end) {
            // Toda página da faixa está mapeada (conferido acima).
            let _ = self
                .tables
                .protect(page, PageSize::Size4K, perms.page_flags());
        }
        // Uma rodada para a faixa toda, mesmo quando só amplia: uma tradução
        // velha mais restrita daria falta espúria.
        self.platform
            .flush(self.root(), start, (end - start) / PAGE_SIZE);
        Ok(())
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // O escalonador nunca deixa no CR3 um espaço sem referências, então
        // não há TLB a invalidar. As regiões (e talvez os objetos) morrem
        // depois, já sem nada mapeado.
        self.tables.free_user_half();
        let root = self.root();
        self.tables.memory().free_table(root);
    }
}

/// `vm_map`: mapeia `len` bytes do objeto de `object`, do byte `offset`,
/// em `start` do espaço de `aspace`, com as `flags` de [`kabi::vm`].
///
/// Exige `MAP` no espaço e `MAP` e `READ` no objeto, mais `WRITE` ou `EXEC`
/// conforme as flags. W^X vale sempre.
///
/// # Errors
///
/// [`Error::WrongType`], [`Error::AccessDenied`] e os de
/// [`AddressSpace::map`].
pub fn vm_map(
    aspace: &Cap,
    object: &Cap,
    start: u64,
    offset: u64,
    len: u64,
    flags: u64,
) -> Result<(), Error> {
    let space = aspace.object.as_address_space()?;
    let memory = object.object.as_memory_object()?;
    let perms = Perms::from_flags(flags)?;
    if !aspace.rights.contains(Rights::MAP) || !object.rights.contains(perms.rights()) {
        return Err(Error::AccessDenied);
    }
    let max = Perms::allowed_by(object.rights);
    space.lock().map(start, memory, offset, len, perms, max)
}

/// `vm_unmap`: exige `UNMAP` no espaço.
///
/// # Errors
///
/// [`Error::WrongType`], [`Error::AccessDenied`] e os de
/// [`AddressSpace::unmap`].
pub fn vm_unmap(aspace: &Cap, start: u64, len: u64) -> Result<(), Error> {
    let space = aspace.object.as_address_space()?;
    if !aspace.rights.contains(Rights::UNMAP) {
        return Err(Error::AccessDenied);
    }
    space.lock().unmap(start, len)
}

/// `vm_protect`: exige `MAP` no espaço; as permissões novas não passam das
/// que o objeto de cada região permitia no `vm_map`.
///
/// # Errors
///
/// [`Error::WrongType`], [`Error::AccessDenied`] e os de
/// [`AddressSpace::protect`].
pub fn vm_protect(aspace: &Cap, start: u64, len: u64, flags: u64) -> Result<(), Error> {
    let space = aspace.object.as_address_space()?;
    let perms = Perms::from_flags(flags)?;
    if !aspace.rights.contains(Rights::MAP) {
        return Err(Error::AccessDenied);
    }
    space.lock().protect(start, len, perms)
}

#[cfg(test)]
mod tests;
