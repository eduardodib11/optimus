//! Memória virtual (SDD v1.0, seção 6.4): `vm_map`, `vm_unmap` e
//! [`Mapping`], que dá acesso seguro ao que o processo mapeou no próprio
//! espaço.

use kabi::vm::{PAGE_SIZE, WRITE};
use kabi::{Error, Handle, Syscall};

use crate::cap::raw;
use crate::sys::syscall;

/// `vm_map`: mapeia `len` bytes de `object` a partir de `offset` em `va`
/// do espaço `aspace`, com `flags` (`kabi::vm::WRITE` ou `EXEC`).
///
/// # Errors
///
/// Os do kernel (`AccessDenied` sem `MAP`, `InvalidArgument` para faixa
/// desalinhada ou ocupada...).
pub fn map(
    aspace: Handle,
    object: Handle,
    va: u64,
    offset: u64,
    len: u64,
    flags: u64,
) -> Result<(), Error> {
    let args = [raw(aspace), raw(object), va, offset, len, flags];
    syscall(Syscall::VmMap, args).map(drop)
}

/// `vm_unmap`.
///
/// # Errors
///
/// Os do kernel.
pub fn unmap(aspace: Handle, va: u64, len: u64) -> Result<(), Error> {
    syscall(Syscall::VmUnmap, [raw(aspace), va, len, 0, 0, 0]).map(drop)
}

/// Um objeto mapeado no espaço do próprio processo, desmapeado no `Drop`.
///
/// O kernel recusa mapear sobre uma região ocupada, então nenhum outro
/// mapeamento (nem outro `Mapping`) cobre a mesma faixa enquanto este
/// existir. Os empréstimos ([`bytes`](Self::bytes),
/// [`bytes_mut`](Self::bytes_mut)) valem sob duas condições que o kernel
/// não confere: ninguém desmapeia nem protege a faixa por fora (com
/// `vm_unmap`/`vm_protect` crus) e o objeto não está mapeado gravável em
/// outro lugar (outro processo ou outra faixa) enquanto houver empréstimo.
#[derive(Debug)]
pub struct Mapping {
    aspace: Handle,
    va: u64,
    len: u64,
    writable: bool,
}

impl Mapping {
    /// Mapeia os primeiros `len` bytes de `object` em `va` do espaço
    /// `aspace` (o do próprio processo), com `flags`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` para `len` zero ou desalinhado; os de [`map`].
    pub fn new(
        aspace: Handle,
        object: Handle,
        va: u64,
        len: u64,
        flags: u64,
    ) -> Result<Self, Error> {
        if len == 0 || !len.is_multiple_of(PAGE_SIZE) || usize::try_from(len).is_err() {
            return Err(Error::InvalidArgument);
        }
        map(aspace, object, va, 0, len, flags)?;
        Ok(Self {
            aspace,
            va,
            len,
            writable: flags & WRITE != 0,
        })
    }

    /// Endereço do início.
    #[must_use]
    pub const fn va(&self) -> u64 {
        self.va
    }

    /// Bytes mapeados (cabe em `usize`, conferido em `new`).
    #[allow(clippy::cast_possible_truncation, reason = "conferido em `new`")]
    pub(crate) const fn size(&self) -> usize {
        self.len as usize
    }

    /// Endereço do início como `usize`.
    #[allow(clippy::cast_possible_truncation, reason = "x86-64: 64 bits")]
    pub(crate) const fn addr(&self) -> usize {
        self.va as usize
    }

    /// Mapeado com escrita.
    pub(crate) const fn writable(&self) -> bool {
        self.writable
    }

    /// Os bytes mapeados.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        crate::arch::mem::bytes(self)
    }

    /// Os bytes mapeados, para escrita; `None` se o mapeamento não for
    /// gravável.
    #[must_use]
    pub fn bytes_mut(&mut self) -> Option<&mut [u8]> {
        if self.writable {
            Some(crate::arch::mem::bytes_mut(self))
        } else {
            None
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let _ = unmap(self.aspace, self.va, self.len);
    }
}
