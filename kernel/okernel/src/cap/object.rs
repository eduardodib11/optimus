//! Objetos do kernel e `obj_create` (T-202; SDD v1.0, seção 6.1).
//!
//! Cada objeto vive num `Arc` do heap do kernel (slab) e carrega o
//! [`Charge`](super::Charge) do que ocupa: o `Arc` mais a memória que o
//! objeto aloca por conta própria. Quando a última referência some, o
//! `Charge` é destruído com o objeto e os bytes voltam à cota.
//!
//! `AddressSpace`, `MemoryObject` (T-205) e `Thread` (T-206) usam a [`Platform`](crate::platform::Platform)
//! instalada pelo kernel. Os tipos que dependem de tarefas futuras (IPC,
//! interrupções, DMA) respondem [`Error::NotSupported`] por enquanto.

use alloc::sync::Arc;
use core::fmt;
use core::mem::size_of;

use kabi::{Error, ObjectType, Rights};

use super::quota::MemoryQuota;
use super::space::CapSpace;
use crate::platform;
use crate::sched::SchedContext;
use crate::sync::SpinLock;
use crate::thread::Thread;
use crate::vm::{AddressSpace, MemoryObject, SharedAddressSpace};

/// `CapSpace` compartilhado, com a trava que a seção 6.9 põe à frente de
/// todas as outras.
pub type SharedCapSpace = SpinLock<CapSpace>;

/// Referência contada a um objeto do kernel, como guardada num slot.
#[derive(Clone)]
pub enum Object {
    /// Orçamento de bytes.
    MemoryQuota(Arc<MemoryQuota>),
    /// Tabela de capabilities.
    CapSpace(Arc<SharedCapSpace>),
    /// Espaço de endereçamento.
    AddressSpace(Arc<SharedAddressSpace>),
    /// Páginas físicas.
    MemoryObject(Arc<MemoryObject>),
    /// Contexto de execução.
    Thread(Arc<Thread>),
    /// Orçamento de CPU e prioridade.
    SchedContext(Arc<SchedContext>),
}

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = match self {
            Self::MemoryQuota(q) => Arc::as_ptr(q).addr(),
            Self::CapSpace(c) => Arc::as_ptr(c).addr(),
            Self::AddressSpace(a) => Arc::as_ptr(a).addr(),
            Self::MemoryObject(m) => Arc::as_ptr(m).addr(),
            Self::Thread(t) => Arc::as_ptr(t).addr(),
            Self::SchedContext(s) => Arc::as_ptr(s).addr(),
        };
        write!(f, "{:?}@{ptr:#x}", self.object_type())
    }
}

impl Object {
    /// Tipo do objeto.
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        match self {
            Self::MemoryQuota(_) => ObjectType::MemoryQuota,
            Self::CapSpace(_) => ObjectType::CapSpace,
            Self::AddressSpace(_) => ObjectType::AddressSpace,
            Self::MemoryObject(_) => ObjectType::MemoryObject,
            Self::Thread(_) => ObjectType::Thread,
            Self::SchedContext(_) => ObjectType::SchedContext,
        }
    }

    /// Verdadeiro se as duas referências apontam para o mesmo objeto.
    #[must_use]
    pub fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::MemoryQuota(a), Self::MemoryQuota(b)) => Arc::ptr_eq(a, b),
            (Self::CapSpace(a), Self::CapSpace(b)) => Arc::ptr_eq(a, b),
            (Self::AddressSpace(a), Self::AddressSpace(b)) => Arc::ptr_eq(a, b),
            (Self::MemoryObject(a), Self::MemoryObject(b)) => Arc::ptr_eq(a, b),
            (Self::Thread(a), Self::Thread(b)) => Arc::ptr_eq(a, b),
            (Self::SchedContext(a), Self::SchedContext(b)) => Arc::ptr_eq(a, b),
            _ => false,
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
            _ => Err(Error::WrongType),
        }
    }

    /// O `CapSpace`, se o objeto for um.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_cap_space(&self) -> Result<&Arc<SharedCapSpace>, Error> {
        match self {
            Self::CapSpace(c) => Ok(c),
            _ => Err(Error::WrongType),
        }
    }

    /// O espaço de endereçamento, se o objeto for um.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_address_space(&self) -> Result<&Arc<SharedAddressSpace>, Error> {
        match self {
            Self::AddressSpace(a) => Ok(a),
            _ => Err(Error::WrongType),
        }
    }

    /// O `MemoryObject`, se o objeto for um.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_memory_object(&self) -> Result<&Arc<MemoryObject>, Error> {
        match self {
            Self::MemoryObject(m) => Ok(m),
            _ => Err(Error::WrongType),
        }
    }

    /// A thread, se o objeto for uma.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_thread(&self) -> Result<&Arc<Thread>, Error> {
        match self {
            Self::Thread(t) => Ok(t),
            _ => Err(Error::WrongType),
        }
    }

    /// O `SchedContext`, se o objeto for um.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_sched_context(&self) -> Result<&Arc<SchedContext>, Error> {
        match self {
            Self::SchedContext(s) => Ok(s),
            _ => Err(Error::WrongType),
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
/// sai de `quota` junto com o tamanho do objeto); `CapSpace`, zero (as
/// folhas da tabela são cobradas da mesma cota à medida que ela cresce);
/// `AddressSpace`, zero (tabelas e regiões são cobradas ao mapear);
/// `MemoryObject`, o tamanho em bytes, múltiplo de 4 KiB; `Thread` e
/// `SchedContext`, zero (este nasce sem configuração).
/// Os direitos sobre `quota`
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
        ObjectType::CapSpace | ObjectType::AddressSpace if args != 0 => Err(Error::InvalidArgument),
        ObjectType::CapSpace => Ok(Object::CapSpace(Arc::new(SpinLock::new(CapSpace::new(
            quota,
        )?)))),
        ObjectType::AddressSpace => {
            let platform = platform::get().ok_or(Error::NotSupported)?;
            let space = AddressSpace::new(quota, platform)?;
            Ok(Object::AddressSpace(Arc::new(SpinLock::new(space))))
        }
        ObjectType::MemoryObject => {
            let platform = platform::get().ok_or(Error::NotSupported)?;
            let memory = MemoryObject::new(quota, args, platform)?;
            Ok(Object::MemoryObject(Arc::new(memory)))
        }
        ObjectType::Thread => {
            let platform = platform::get().ok_or(Error::NotSupported)?;
            Ok(Object::Thread(Arc::new(Thread::new(quota, platform)?)))
        }
        ObjectType::SchedContext => {
            let charge = quota.charge(object_bytes::<SchedContext>())?;
            Ok(Object::SchedContext(Arc::new(SchedContext::new(charge))))
        }
        _ => Err(Error::NotSupported),
    }
}

#[cfg(test)]
mod tests;
