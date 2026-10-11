//! Objetos do kernel e `obj_create` (T-202; SDD v1.0, seção 6.1).
//!
//! Cada objeto vive num `Arc` do heap do kernel (slab) e carrega o
//! [`Charge`](super::Charge) do que ocupa: o `Arc` mais a memória que o
//! objeto aloca por conta própria. Quando a última referência some, o
//! `Charge` é destruído com o objeto e os bytes voltam à cota.
//!
//! Os tipos que dependem de tarefas futuras (threads, IPC, memória virtual)
//! respondem [`Error::NotSupported`] por enquanto.

use alloc::sync::Arc;
use core::mem::size_of;

use kabi::{Error, ObjectType, Rights};

use super::quota::MemoryQuota;

/// Referência contada a um objeto do kernel, como guardada num slot.
#[derive(Clone, Debug)]
pub enum Object {
    /// Orçamento de bytes.
    MemoryQuota(Arc<MemoryQuota>),
}

impl Object {
    /// Tipo do objeto.
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        match self {
            Self::MemoryQuota(_) => ObjectType::MemoryQuota,
        }
    }

    /// Verdadeiro se as duas referências apontam para o mesmo objeto.
    #[must_use]
    pub fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::MemoryQuota(a), Self::MemoryQuota(b)) => Arc::ptr_eq(a, b),
        }
    }

    /// A cota, se o objeto for uma.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_quota(&self) -> Result<&Arc<MemoryQuota>, Error> {
        match self {
            Self::MemoryQuota(q) => Ok(q),
        }
    }
}

/// Bytes que um `Arc<T>` ocupa no heap: dois contadores mais o valor.
#[must_use]
pub const fn object_bytes<T>() -> u64 {
    (2 * size_of::<usize>() + size_of::<T>()) as u64
}

/// Direitos da capability que `obj_create` entrega para cada tipo: os
/// relevantes da tabela 6.1, de onde as cópias só podem reduzir.
#[must_use]
pub const fn default_rights(ty: ObjectType) -> Rights {
    let bits = match ty {
        ObjectType::MemoryQuota => Rights::CREATE.bits() | Rights::SPLIT.bits(),
        ObjectType::AddressSpace => Rights::MAP.bits() | Rights::UNMAP.bits(),
        ObjectType::CapSpace => Rights::MANAGE.bits(),
        ObjectType::Thread => {
            Rights::START.bits()
                | Rights::SUSPEND.bits()
                | Rights::READ_STATE.bits()
                | Rights::WRITE_STATE.bits()
        }
        ObjectType::SchedContext => Rights::BIND.bits() | Rights::CONFIGURE.bits(),
        ObjectType::MemoryObject => {
            Rights::READ.bits() | Rights::WRITE.bits() | Rights::EXEC.bits() | Rights::MAP.bits()
        }
        ObjectType::Endpoint => Rights::SEND.bits() | Rights::RECV.bits() | Rights::GRANT.bits(),
        ObjectType::Reply => Rights::SEND.bits(),
        ObjectType::Notification => Rights::SIGNAL.bits() | Rights::WAIT.bits(),
        ObjectType::Interrupt => Rights::ACK.bits() | Rights::BIND.bits(),
        ObjectType::IoPortRange => Rights::READ.bits() | Rights::WRITE.bits(),
        ObjectType::DmaDomain => Rights::MAP.bits(),
        ObjectType::Vcpu | ObjectType::Vm => Rights::RUN.bits() | Rights::MAP.bits(),
    };
    match Rights::from_bits(bits) {
        Some(r) => r,
        None => Rights::NONE,
    }
}

/// `obj_create(quota, tipo, args)`: cria um objeto cobrando o tamanho dele de
/// `quota`.
///
/// `args` por tipo: `MemoryQuota`, o orçamento da cota filha em bytes (que
/// sai de `quota` junto com o tamanho do objeto). Os direitos sobre `quota`
/// (`CREATE`, e `SPLIT` para cotas) são conferidos por quem chama, que tem a
/// capability.
///
/// # Errors
///
/// [`Error::QuotaExceeded`] se `quota` não cobrir o objeto;
/// [`Error::InvalidArgument`] para `args` fora do domínio;
/// [`Error::NotSupported`] para tipos ainda não implementados.
pub fn obj_create(quota: &Arc<MemoryQuota>, ty: ObjectType, args: u64) -> Result<Object, Error> {
    match ty {
        ObjectType::MemoryQuota => {
            let bytes = object_bytes::<MemoryQuota>()
                .checked_add(args)
                .ok_or(Error::InvalidArgument)?;
            let charge = quota.charge(bytes)?;
            Ok(Object::MemoryQuota(Arc::new(MemoryQuota::child(
                args, charge,
            ))))
        }
        _ => Err(Error::NotSupported),
    }
}

#[cfg(test)]
mod tests;
