//! Memória virtual de usuário: `MemoryObject`, `AddressSpace` e
//! `vm_map`/`vm_unmap`/`vm_protect` (T-205; SDD v1.0, seções 6.1 e 6.4).
//!
//! Um [`MemoryObject`] é um conjunto de frames zerados do buddy, cobrados da
//! cota (bytes das páginas mais a lista de frames). Um [`AddressSpace`] é
//! um PML4 próprio cuja metade alta é cópia da do kernel (as tabelas abaixo
//! dela são compartilhadas) e cuja metade baixa só recebe páginas de
//! usuário em `[USER_START, USER_END)`. Cada tabela de página e cada região
//! mapeada é cobrada da cota do espaço; as regiões guardam uma referência ao
//! objeto, que só morre (devolvendo os frames) depois de desmapeado.
//!
//! Um objeto `LAZY` (ADR 0038, item 1) nasce sem frames, cobrado só pelos
//! metadados; `mem_op` compromete as páginas sob demanda, debitando a cota
//! do dono, e as publica nos espaços em que o objeto está mapeado (o
//! objeto guarda a lista deles).
//!
//! W^X vale sempre: nenhuma página é gravável e executável ao mesmo tempo.
//! As permissões de uma região nunca passam das que a capability do objeto
//! dava no `vm_map` (o máximo guardado na região, conferido no
//! `vm_protect`).

#![forbid(unsafe_code)]

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};

use kabi::vm::{ALL_FLAGS, EXEC, PAGE_SIZE, RAW, WRITE};
use kabi::{Error, Rights};

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota};
use crate::mm::PhysAddr;
use crate::mm::paging::Flags;
use crate::platform::Platform;
use crate::sync::{LockClass, SpinLock};

mod aspace;
pub use aspace::{AddressSpace, SharedAddressSpace, vm_map, vm_protect, vm_unmap};

/// Permissões de uma página de usuário além da leitura.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perms {
    /// Gravável.
    pub write: bool,
    /// Executável.
    pub exec: bool,
    /// Visão crua de um objeto `LAZY` (mostra as páginas ocultas).
    pub raw: bool,
}

impl Perms {
    /// Lê as flags de `vm_map`/`vm_protect` ([`kabi::vm`]).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para bits desconhecidos, W e X juntos ou
    /// `RAW` com X.
    pub const fn from_flags(flags: u64) -> Result<Self, Error> {
        if flags & !ALL_FLAGS != 0
            || flags & (WRITE | EXEC) == WRITE | EXEC
            || flags & (RAW | EXEC) == RAW | EXEC
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            write: flags & WRITE != 0,
            exec: flags & EXEC != 0,
            raw: flags & RAW != 0,
        })
    }

    /// Direitos que a capability do objeto precisa ter para mapear assim.
    #[must_use]
    pub const fn rights(self) -> Rights {
        let mut bits = Rights::MAP.bits() | Rights::READ.bits();
        if self.write {
            bits |= Rights::WRITE.bits();
        }
        if self.exec {
            bits |= Rights::EXEC.bits();
        }
        if self.raw {
            bits |= Rights::EVICT.bits();
        }
        match Rights::from_bits(bits) {
            Some(r) => r,
            None => Rights::NONE,
        }
    }

    /// O máximo que `rights` permite.
    #[must_use]
    pub const fn allowed_by(rights: Rights) -> Self {
        Self {
            write: rights.contains(Rights::WRITE),
            exec: rights.contains(Rights::EXEC),
            raw: rights.contains(Rights::EVICT),
        }
    }

    /// Verdadeiro se `self` não passa de `max`.
    #[must_use]
    pub const fn within(self, max: Self) -> bool {
        (!self.write || max.write) && (!self.exec || max.exec) && (!self.raw || max.raw)
    }

    /// Flags da folha de usuário com estas permissões.
    #[must_use]
    pub const fn page_flags(self) -> Flags {
        Flags {
            write: self.write,
            exec: self.exec,
            user: true,
            ..Flags::READ
        }
    }
}

/// Bit de um slot de objeto `LAZY`: a página tem frame (oculta ou presente).
const COMMITTED: u64 = 1;
/// Bit de um slot de objeto `LAZY`: a página aparece nos mapeamentos.
const PRESENT: u64 = 2;

/// Frames comprometidos de objetos `LAZY`, em todo o sistema (`sys_info`
/// de memória, ADR 0038, item 5).
static LAZY_COMMITTED: AtomicU64 = AtomicU64::new(0);

/// Frames comprometidos de objetos `LAZY` vivos.
#[must_use]
pub fn lazy_committed() -> u64 {
    LAZY_COMMITTED.load(Ordering::Relaxed)
}

/// Estado de um objeto `LAZY` (ADR 0038, item 1), sob a trava do objeto,
/// que vem antes da do `AddressSpace` (ADR 0031).
struct Lazy {
    /// Cota do dono: metadados e um frame por página comprometida.
    charge: Charge,
    /// Por página: zero (ausente) ou o frame com [`COMMITTED`] e, se
    /// visível, [`PRESENT`].
    slots: Vec<u64>,
    /// Espaços em que o objeto foi mapeado; uma entrada pode estar
    /// obsoleta (espaço morto ou já sem região do objeto) até a próxima
    /// limpeza.
    spaces: Vec<Weak<SharedAddressSpace>>,
}

impl Lazy {
    fn present(&self, page: u64) -> Option<PhysAddr> {
        self.visible(page, false)
    }

    /// Frame da página `page` numa visão normal (só presente) ou `raw`
    /// (oculta ou presente).
    fn visible(&self, page: u64, raw: bool) -> Option<PhysAddr> {
        let slot = *self.slots.get(usize::try_from(page).ok()?)?;
        let need = if raw { COMMITTED } else { PRESENT };
        (slot & need != 0).then_some(PhysAddr(slot & !(PAGE_SIZE - 1)))
    }

    /// Tira as entradas obsoletas da lista de espaços.
    fn prune(&mut self, object: &MemoryObject) {
        self.spaces
            .retain(|w| w.upgrade().is_some_and(|s| s.lock().shows(object)));
    }
}

enum Store {
    /// Todas as páginas presentes desde a criação.
    Eager {
        charge: Charge,
        frames: Vec<PhysAddr>,
    },
    /// Comprometido sob demanda (`mem_op`).
    Lazy(SpinLock<Lazy>),
}

/// Conjunto de páginas físicas: zeradas e todas presentes desde a criação
/// ou, com `LAZY`, comprometidas sob demanda por `mem_op`.
pub struct MemoryObject {
    pages: u64,
    store: Store,
    platform: &'static dyn Platform,
}

impl fmt::Debug for MemoryObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryObject({} páginas)", self.pages)
    }
}

/// Páginas de `bytes` (múltiplo de 4 KiB, não zero) e o custo delas com
/// `per_page` bytes cada mais o objeto.
fn sized(bytes: u64, per_page: u64) -> Result<(u64, usize, u64), Error> {
    if bytes == 0 || !bytes.is_multiple_of(PAGE_SIZE) {
        return Err(Error::InvalidArgument);
    }
    let pages = bytes / PAGE_SIZE;
    let cost = pages
        .checked_mul(per_page)
        .and_then(|b| b.checked_add(object_bytes::<MemoryObject>()))
        .ok_or(Error::InvalidArgument)?;
    let count = usize::try_from(pages).map_err(|_| Error::InvalidArgument)?;
    Ok((pages, count, cost))
}

impl MemoryObject {
    /// Objeto de `bytes` (múltiplo de 4 KiB, não zero) com frames zerados,
    /// cobrado de `quota`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para tamanho inválido;
    /// [`Error::QuotaExceeded`] sem cota ou sem frames livres.
    pub fn new(
        quota: &Arc<MemoryQuota>,
        bytes: u64,
        platform: &'static dyn Platform,
    ) -> Result<Self, Error> {
        let (pages, count, cost) = sized(bytes, PAGE_SIZE + size_of::<PhysAddr>() as u64)?;
        let charge = quota.charge(cost)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(count)
            .map_err(|_| Error::QuotaExceeded)?;
        let mut object = Self {
            pages,
            store: Store::Eager { charge, frames },
            platform,
        };
        for _ in 0..count {
            // Se faltar frame, o `Drop` devolve os que já vieram.
            let frame = platform.alloc_frame().ok_or(Error::QuotaExceeded)?;
            if let Store::Eager { frames, .. } = &mut object.store {
                frames.push(frame);
            }
        }
        Ok(object)
    }

    /// Objeto `LAZY` de `bytes` (ADR 0038, item 1): todas as páginas
    /// ausentes, cobrado de `quota` só pelos metadados; cada `COMMIT`
    /// debita uma página da mesma cota (a do dono).
    ///
    /// # Errors
    ///
    /// Os de [`new`](Self::new).
    pub fn new_lazy(
        quota: &Arc<MemoryQuota>,
        bytes: u64,
        platform: &'static dyn Platform,
    ) -> Result<Self, Error> {
        let (pages, count, cost) = sized(bytes, size_of::<u64>() as u64)?;
        let charge = quota.charge(cost)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| Error::QuotaExceeded)?;
        slots.resize(count, 0);
        let lazy = Lazy {
            charge,
            slots,
            spaces: Vec::new(),
        };
        Ok(Self {
            pages,
            store: Store::Lazy(SpinLock::with_class(LockClass::Object, lazy)),
            platform,
        })
    }

    /// Verdadeiro para objeto `LAZY`.
    #[must_use]
    pub const fn is_lazy(&self) -> bool {
        matches!(self.store, Store::Lazy(_))
    }

    /// Páginas do objeto.
    #[must_use]
    pub const fn pages(&self) -> u64 {
        self.pages
    }

    /// Frame da página `page`, se presente. Num objeto `LAZY` toma a trava
    /// do objeto: nunca com a de um `AddressSpace` na mão.
    #[must_use]
    pub fn frame(&self, page: u64) -> Option<PhysAddr> {
        match &self.store {
            Store::Eager { frames, .. } => frames.get(usize::try_from(page).ok()?).copied(),
            Store::Lazy(lazy) => lazy.lock().present(page),
        }
    }

    /// Bytes cobrados da cota.
    #[must_use]
    pub fn charged(&self) -> u64 {
        match &self.store {
            Store::Eager { charge, .. } => charge.bytes(),
            Store::Lazy(lazy) => lazy.lock().charge.bytes(),
        }
    }

    /// Mapeia `len` bytes do objeto, do byte `offset`, em `start` de
    /// `space` (ver [`AddressSpace::map`]). Num objeto `LAZY` só as páginas
    /// presentes entram já; o espaço passa para a lista do objeto, que
    /// publica nele as páginas que vierem depois.
    ///
    /// # Errors
    ///
    /// Os de [`AddressSpace::map`].
    pub fn map_into(
        self: &Arc<Self>,
        space: &Arc<SharedAddressSpace>,
        start: u64,
        offset: u64,
        len: u64,
        perms: Perms,
        max: Perms,
    ) -> Result<(), Error> {
        let Store::Lazy(lazy) = &self.store else {
            return space.lock().map(start, self, offset, len, perms, max);
        };
        let mut l = lazy.lock();
        l.prune(self);
        let known = l.spaces.iter().any(|w| w.as_ptr() == Arc::as_ptr(space));
        if !known {
            l.spaces.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
        }
        let lookup = |page| l.visible(page, perms.raw);
        space
            .lock()
            .map_with(start, self, offset, len, perms, max, &lookup)?;
        if !known {
            l.spaces.push(Arc::downgrade(space));
        }
        Ok(())
    }

    /// `COMMIT` das páginas `[first, first + count)` (já conferidas):
    /// ausente → oculta, zerada, debitando a cota do dono; com `publish`,
    /// a página fica presente e entra nos mapeamentos. Num objeto sem
    /// `LAZY`, nada muda. Idempotente por página: num erro, as anteriores
    /// ficam comprometidas.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota no dono, sem frame livre ou sem
    /// frame para as tabelas de um mapeamento.
    pub fn commit(&self, first: u64, count: u64, publish: bool) -> Result<(), Error> {
        let Store::Lazy(lazy) = &self.store else {
            return Ok(());
        };
        let mut l = lazy.lock();
        for page in first..first + count {
            let i = usize::try_from(page).map_err(|_| Error::InvalidArgument)?;
            if l.slots[i] & COMMITTED == 0 {
                l.charge.grow(PAGE_SIZE)?;
                let Some(frame) = self.platform.alloc_frame() else {
                    l.charge.shrink(PAGE_SIZE);
                    return Err(Error::QuotaExceeded);
                };
                l.slots[i] = frame.0 | COMMITTED;
                LAZY_COMMITTED.fetch_add(1, Ordering::Relaxed);
                // Oculta: só as visões `RAW` a mostram.
                for space in l.spaces.iter().filter_map(Weak::upgrade) {
                    space.lock().install(self, page, frame, true)?;
                }
            }
            if publish {
                self.publish_one(&mut l, i)?;
            }
        }
        Ok(())
    }

    /// `PUBLISH` de `[first, first + count)`: oculta → presente, em todos
    /// os mapeamentos. Página ausente é recusada.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para página ausente;
    /// [`Error::QuotaExceeded`] sem frame para as tabelas.
    pub fn publish(&self, first: u64, count: u64) -> Result<(), Error> {
        let Store::Lazy(lazy) = &self.store else {
            return Ok(());
        };
        let mut l = lazy.lock();
        for page in first..first + count {
            let i = usize::try_from(page).map_err(|_| Error::InvalidArgument)?;
            if l.slots[i] & COMMITTED == 0 {
                return Err(Error::InvalidArgument);
            }
            self.publish_one(&mut l, i)?;
        }
        Ok(())
    }

    /// Marca a página `i` (comprometida) presente e a instala em cada
    /// espaço da lista; repetir só refaz o que faltou. Não há o que
    /// invalidar: a tradução sai de ausente para presente.
    fn publish_one(&self, l: &mut Lazy, i: usize) -> Result<(), Error> {
        l.slots[i] |= PRESENT;
        let frame = PhysAddr(l.slots[i] & !(PAGE_SIZE - 1));
        for space in l.spaces.iter().filter_map(Weak::upgrade) {
            space.lock().install(self, i as u64, frame, false)?;
        }
        Ok(())
    }

    /// `HIDE` de `[first, first + count)`: presente → oculta. Cada página
    /// sai das visões normais de todo espaço, e só depois do shootdown
    /// (ADR 0031) a próxima é tratada; o frame fica.
    ///
    /// # Errors
    ///
    /// [`Error::NotSupported`] num objeto sem `LAZY`.
    pub fn hide(&self, first: u64, count: u64) -> Result<(), Error> {
        let Store::Lazy(lazy) = &self.store else {
            return Err(Error::NotSupported);
        };
        let mut l = lazy.lock();
        for page in first..first + count {
            Self::hide_one(&mut l, self, page);
        }
        Ok(())
    }

    fn hide_one(l: &mut Lazy, object: &Self, page: u64) {
        let i = usize::try_from(page).unwrap_or(usize::MAX);
        if l.slots.get(i).is_some_and(|s| s & PRESENT != 0) {
            l.slots[i] &= !PRESENT;
            for space in l.spaces.iter().filter_map(Weak::upgrade) {
                space.lock().remove(object, page, false);
            }
        }
    }

    /// `DECOMMIT` de `[first, first + count)`: a página (presente é
    /// ocultada antes) sai também das visões `RAW`, com shootdown; só então
    /// o frame volta ao alocador e a cota do dono é creditada (ADR 0038,
    /// invariante 1). Página ausente fica como está.
    ///
    /// # Errors
    ///
    /// [`Error::NotSupported`] num objeto sem `LAZY`.
    pub fn decommit(&self, first: u64, count: u64) -> Result<(), Error> {
        let Store::Lazy(lazy) = &self.store else {
            return Err(Error::NotSupported);
        };
        let mut l = lazy.lock();
        for page in first..first + count {
            let i = usize::try_from(page).unwrap_or(usize::MAX);
            let Some(&slot) = l.slots.get(i) else {
                continue;
            };
            if slot & COMMITTED == 0 {
                continue;
            }
            Self::hide_one(&mut l, self, page);
            for space in l.spaces.iter().filter_map(Weak::upgrade) {
                space.lock().remove(self, page, true);
            }
            l.slots[i] = 0;
            self.platform.free_frame(PhysAddr(slot & !(PAGE_SIZE - 1)));
            l.charge.shrink(PAGE_SIZE);
            LAZY_COMMITTED.fetch_sub(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// `AGE` de `[first, first + count)` (`count` ≤ 64): o mapa de bits das
    /// páginas presentes usadas (bit de acesso ligado numa visão normal)
    /// desde a última chamada; os bits são limpos, com invalidação.
    ///
    /// # Errors
    ///
    /// [`Error::NotSupported`] num objeto sem `LAZY`.
    pub fn age(&self, first: u64, count: u64) -> Result<u64, Error> {
        let Store::Lazy(lazy) = &self.store else {
            return Err(Error::NotSupported);
        };
        let l = lazy.lock();
        let mut used = 0;
        for (bit, page) in (first..first + count.min(64)).enumerate() {
            let present = usize::try_from(page)
                .ok()
                .and_then(|i| l.slots.get(i))
                .is_some_and(|s| s & PRESENT != 0);
            if !present {
                continue;
            }
            let mut hit = false;
            for space in l.spaces.iter().filter_map(Weak::upgrade) {
                hit |= space.lock().take_accessed(self, page);
            }
            if hit {
                used |= 1 << bit;
            }
        }
        Ok(used)
    }

    /// `ZERO` de `[first, first + count)`: zera as páginas comprometidas
    /// (as ausentes já leem zero quando vierem).
    pub fn zero(&self, first: u64, count: u64) {
        let to = |p: u64| usize::try_from(p).unwrap_or(usize::MAX);
        let span = to(first)..to(first.saturating_add(count));
        match &self.store {
            Store::Eager { frames, .. } => {
                for &frame in frames.get(span).unwrap_or_default() {
                    self.platform.zero_frame(frame);
                }
            }
            Store::Lazy(lazy) => {
                let l = lazy.lock();
                for &slot in l.slots.get(span).unwrap_or_default() {
                    if slot & COMMITTED != 0 {
                        self.platform.zero_frame(PhysAddr(slot & !(PAGE_SIZE - 1)));
                    }
                }
            }
        }
    }
}

impl Drop for MemoryObject {
    fn drop(&mut self) {
        // Sem travar: o `Drop` pode rodar com a trava de um `AddressSpace`
        // na mão (a última região saiu no `vm_unmap`).
        match &mut self.store {
            Store::Eager { frames, .. } => {
                for &frame in frames.iter() {
                    self.platform.free_frame(frame);
                }
            }
            Store::Lazy(lazy) => {
                let l = lazy.get_mut();
                let mut freed = 0;
                for &slot in l.slots.iter().filter(|&&s| s & COMMITTED != 0) {
                    self.platform.free_frame(PhysAddr(slot & !(PAGE_SIZE - 1)));
                    freed += 1;
                }
                LAZY_COMMITTED.fetch_sub(freed, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
