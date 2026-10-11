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
//! W^X vale sempre: nenhuma página é gravável e executável ao mesmo tempo.
//! As permissões de uma região nunca passam das que a capability do objeto
//! dava no `vm_map` (o máximo guardado na região, conferido no
//! `vm_protect`).

#![forbid(unsafe_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::mem::size_of;

use kabi::vm::{ALL_FLAGS, EXEC, PAGE_SIZE, WRITE};
use kabi::{Error, Rights};

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota};
use crate::mm::PhysAddr;
use crate::mm::paging::Flags;
use crate::platform::Platform;

mod aspace;
pub use aspace::{AddressSpace, SharedAddressSpace, vm_map, vm_protect, vm_unmap};

/// Permissões de uma página de usuário além da leitura.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perms {
    /// Gravável.
    pub write: bool,
    /// Executável.
    pub exec: bool,
}

impl Perms {
    /// Lê as flags de `vm_map`/`vm_protect` ([`kabi::vm`]).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para bits desconhecidos ou W e X juntos.
    pub const fn from_flags(flags: u64) -> Result<Self, Error> {
        if flags & !ALL_FLAGS != 0 || flags & (WRITE | EXEC) == WRITE | EXEC {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            write: flags & WRITE != 0,
            exec: flags & EXEC != 0,
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
        }
    }

    /// Verdadeiro se `self` não passa de `max`.
    #[must_use]
    pub const fn within(self, max: Self) -> bool {
        (!self.write || max.write) && (!self.exec || max.exec)
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

/// Conjunto de frames físicos zerados.
pub struct MemoryObject {
    charge: Charge,
    frames: Vec<PhysAddr>,
    platform: &'static dyn Platform,
}

impl fmt::Debug for MemoryObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryObject({} páginas)", self.frames.len())
    }
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
        if bytes == 0 || !bytes.is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidArgument);
        }
        let pages = bytes / PAGE_SIZE;
        let cost = pages
            .checked_mul(PAGE_SIZE + size_of::<PhysAddr>() as u64)
            .and_then(|b| b.checked_add(object_bytes::<Self>()))
            .ok_or(Error::InvalidArgument)?;
        let charge = quota.charge(cost)?;
        let count = usize::try_from(pages).map_err(|_| Error::InvalidArgument)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(count)
            .map_err(|_| Error::QuotaExceeded)?;
        let mut object = Self {
            charge,
            frames,
            platform,
        };
        for _ in 0..count {
            // Se faltar frame, o `Drop` devolve os que já vieram.
            let frame = platform.alloc_frame().ok_or(Error::QuotaExceeded)?;
            object.frames.push(frame);
        }
        Ok(object)
    }

    /// Páginas do objeto.
    #[must_use]
    pub fn pages(&self) -> u64 {
        self.frames.len() as u64
    }

    /// Frame da página `page`.
    #[must_use]
    pub fn frame(&self, page: u64) -> Option<PhysAddr> {
        self.frames.get(usize::try_from(page).ok()?).copied()
    }

    /// Bytes cobrados da cota.
    #[must_use]
    pub const fn charged(&self) -> u64 {
        self.charge.bytes()
    }
}

impl Drop for MemoryObject {
    fn drop(&mut self) {
        for &frame in &self.frames {
            self.platform.free_frame(frame);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
