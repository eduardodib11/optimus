//! Objetos do kernel e `obj_create` (T-202; SDD v1.0, seção 6.1).
//!
//! Cada objeto vive num `Arc` do heap do kernel (slab) e carrega o
//! [`Charge`](super::Charge) do que ocupa: o `Arc` mais a memória que o
//! objeto aloca por conta própria. Quando a última referência some, o
//! `Charge` é destruído com o objeto e os bytes voltam à cota.
//!
//! `Notification` e `Interrupt` vêm do T-209; `Endpoint` e `Reply`, do T-208.
//! `AddressSpace`, `MemoryObject` (T-205) e `Thread` (T-206) usam a [`Platform`](crate::platform::Platform)
//! instalada pelo kernel. Os tipos que dependem de tarefas futuras (IPC,
//! interrupções, DMA) respondem [`Error::NotSupported`] por enquanto.

use alloc::sync::Arc;
use core::fmt;
use core::mem::size_of;
use core::pin::Pin;

use kabi::{Error, ObjectType, Rights};

use super::quota::MemoryQuota;
use super::space::CapSpace;
use crate::ipc::{Endpoint, Reply};
use crate::notify::{Interrupt, Notification};
use crate::platform;
use crate::sched::SchedContext;
use crate::sync::{LockClass, SpinLock};
use crate::thread::Thread;
use crate::timer::{self, Timer};
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
    /// Palavra de sinais assíncronos.
    Notification(Arc<Notification>),
    /// Linha de IRQ.
    Interrupt(Arc<Interrupt>),
    /// Ponto de IPC síncrono.
    Endpoint(Arc<Endpoint>),
    /// Resposta de uso único.
    Reply(Arc<Reply>),
    /// Prazo ligável a uma notificação (ADR 0035, item 6); fixo na memória,
    /// porque a fila de timers aponta para ele.
    Timer(Pin<Arc<Timer>>),
    /// Capability de depuração (ADR 0036, item 5). Sem estado: só o kernel
    /// a cria, no boot, e `debug_write` escreve no registro dele.
    DebugLog(Arc<DebugLog>),
}

/// Marca de identidade da [`Object::DebugLog`]; o estado é o registro do kernel.
#[derive(Debug)]
pub struct DebugLog;

impl fmt::Debug for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = match self {
            Self::MemoryQuota(q) => Arc::as_ptr(q).addr(),
            Self::CapSpace(c) => Arc::as_ptr(c).addr(),
            Self::AddressSpace(a) => Arc::as_ptr(a).addr(),
            Self::MemoryObject(m) => Arc::as_ptr(m).addr(),
            Self::Thread(t) => Arc::as_ptr(t).addr(),
            Self::SchedContext(s) => Arc::as_ptr(s).addr(),
            Self::Notification(n) => Arc::as_ptr(n).addr(),
            Self::Interrupt(i) => Arc::as_ptr(i).addr(),
            Self::Endpoint(e) => Arc::as_ptr(e).addr(),
            Self::Reply(r) => Arc::as_ptr(r).addr(),
            Self::Timer(t) => core::ptr::from_ref::<Timer>(t).addr(),
            Self::DebugLog(d) => Arc::as_ptr(d).addr(),
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
            Self::Notification(_) => ObjectType::Notification,
            Self::Interrupt(_) => ObjectType::Interrupt,
            Self::Endpoint(_) => ObjectType::Endpoint,
            Self::Reply(_) => ObjectType::Reply,
            Self::Timer(_) => ObjectType::Timer,
            Self::DebugLog(_) => ObjectType::DebugLog,
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
            (Self::Notification(a), Self::Notification(b)) => Arc::ptr_eq(a, b),
            (Self::Interrupt(a), Self::Interrupt(b)) => Arc::ptr_eq(a, b),
            (Self::Endpoint(a), Self::Endpoint(b)) => Arc::ptr_eq(a, b),
            (Self::Reply(a), Self::Reply(b)) => Arc::ptr_eq(a, b),
            (Self::Timer(a), Self::Timer(b)) => {
                core::ptr::eq::<Timer>(&raw const **a, &raw const **b)
            }
            (Self::DebugLog(a), Self::DebugLog(b)) => Arc::ptr_eq(a, b),
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

    /// A notificação, se o objeto for uma.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_notification(&self) -> Result<&Arc<Notification>, Error> {
        match self {
            Self::Notification(n) => Ok(n),
            _ => Err(Error::WrongType),
        }
    }

    /// A interrupção, se o objeto for uma.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_interrupt(&self) -> Result<&Arc<Interrupt>, Error> {
        match self {
            Self::Interrupt(i) => Ok(i),
            _ => Err(Error::WrongType),
        }
    }

    /// O endpoint, se o objeto for um.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_endpoint(&self) -> Result<&Arc<Endpoint>, Error> {
        match self {
            Self::Endpoint(e) => Ok(e),
            _ => Err(Error::WrongType),
        }
    }

    /// O `Reply`, se o objeto for um.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_reply(&self) -> Result<&Arc<Reply>, Error> {
        match self {
            Self::Reply(r) => Ok(r),
            _ => Err(Error::WrongType),
        }
    }
}

impl Object {
    /// O `Timer`, se o objeto for um.
    ///
    /// # Errors
    ///
    /// [`Error::WrongType`] para outro tipo de objeto.
    pub fn as_timer(&self) -> Result<Pin<&Timer>, Error> {
        match self {
            Self::Timer(t) => Ok(t.as_ref()),
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
/// relevantes da tabela 6.1, de onde as cópias só podem reduzir. O criador
/// de `CapSpace`, `Thread` e `Endpoint` recebe também `DESTROY`, e o de
/// `CapSpace` e `Thread`, `BIND` (o evento de morte; ADR 0035, itens 3 e 4).
#[must_use]
pub const fn default_rights(ty: ObjectType) -> Rights {
    let bits = match ty {
        ObjectType::MemoryQuota => Rights::CREATE.bits() | Rights::SPLIT.bits(),
        ObjectType::AddressSpace => Rights::MAP.bits() | Rights::UNMAP.bits(),
        ObjectType::CapSpace => {
            Rights::MANAGE.bits() | Rights::BIND.bits() | Rights::DESTROY.bits()
        }
        ObjectType::Thread => {
            Rights::START.bits()
                | Rights::SUSPEND.bits()
                | Rights::READ_STATE.bits()
                | Rights::WRITE_STATE.bits()
                | Rights::BIND.bits()
                | Rights::DESTROY.bits()
        }
        ObjectType::SchedContext => Rights::BIND.bits() | Rights::CONFIGURE.bits(),
        ObjectType::MemoryObject => {
            Rights::READ.bits() | Rights::WRITE.bits() | Rights::EXEC.bits() | Rights::MAP.bits()
        }
        ObjectType::Endpoint => {
            Rights::SEND.bits()
                | Rights::RECV.bits()
                | Rights::GRANT.bits()
                | Rights::DESTROY.bits()
        }
        ObjectType::Reply => Rights::SEND.bits(),
        ObjectType::Notification => Rights::SIGNAL.bits() | Rights::WAIT.bits(),
        ObjectType::Interrupt => Rights::ACK.bits() | Rights::BIND.bits(),
        ObjectType::IoPortRange => Rights::READ.bits() | Rights::WRITE.bits(),
        ObjectType::DmaDomain => Rights::MAP.bits(),
        ObjectType::Vcpu | ObjectType::Vm => Rights::RUN.bits() | Rights::MAP.bits(),
        ObjectType::Timer => Rights::BIND.bits(),
        ObjectType::DebugLog => Rights::WRITE.bits() | Rights::BIND.bits(),
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
/// sai de `quota` junto com o tamanho do objeto); `CapSpace`, o limite de
/// threads vivas do processo (0 = sem limite, ADR 0035, item 5; as folhas
/// da tabela são cobradas da mesma cota à medida que ela cresce);
/// `AddressSpace`, zero (tabelas e regiões são cobradas ao mapear);
/// `MemoryObject`, o tamanho em bytes, múltiplo de 4 KiB; `Thread` e
/// `SchedContext`, `Notification`, `Endpoint`, `Reply` e `Timer`, zero (o
/// primeiro nasce sem configuração; o `Timer`, desarmado, e o criador recebe
/// só `BIND`, ADR 0035, item 6). `Interrupt` só o kernel cria (o `root` as recebe), e
/// `obj_create` a recusa com `NotSupported`.
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
    // Cada tipo num construtor à parte: no build de depuração os
    // temporários de todos os braços somariam no quadro desta função, que
    // está no caminho de toda syscall `obj_create` (pilha de kernel de
    // 16 KiB).
    match ty {
        ObjectType::MemoryQuota => new_quota(quota, args),
        ObjectType::AddressSpace
        | ObjectType::Notification
        | ObjectType::Endpoint
        | ObjectType::Reply
        | ObjectType::Timer
            if args != 0 =>
        {
            Err(Error::InvalidArgument)
        }
        ObjectType::CapSpace => new_cap_space(quota, args),
        ObjectType::AddressSpace => new_address_space(quota),
        ObjectType::MemoryObject => new_memory_object(quota, args, false),
        ObjectType::Thread => new_thread(quota),
        ObjectType::SchedContext => new_sched_context(quota),
        ObjectType::Notification => new_notification(quota),
        ObjectType::Endpoint => new_endpoint(quota),
        ObjectType::Reply => new_reply(quota),
        ObjectType::Timer => new_timer(quota),
        _ => Err(Error::NotSupported),
    }
}

#[inline(never)]
fn new_quota(quota: &Arc<MemoryQuota>, args: u64) -> Result<Object, Error> {
    let bytes = object_bytes::<MemoryQuota>()
        .checked_add(args)
        .ok_or(Error::InvalidArgument)?;
    let charge = quota.charge(bytes)?;
    Ok(Object::MemoryQuota(Arc::new(MemoryQuota::child(
        args, charge,
    ))))
}

#[inline(never)]
fn new_cap_space(quota: &Arc<MemoryQuota>, args: u64) -> Result<Object, Error> {
    let limit = u32::try_from(args).map_err(|_| Error::InvalidArgument)?;
    let mut table = CapSpace::new(quota)?;
    table.process_mut().set_limit(limit);
    Ok(Object::CapSpace(Arc::new(SpinLock::with_class(
        LockClass::CapSpace,
        table,
    ))))
}

#[inline(never)]
fn new_address_space(quota: &Arc<MemoryQuota>) -> Result<Object, Error> {
    let platform = platform::get().ok_or(Error::NotSupported)?;
    let space = AddressSpace::new(quota, platform)?;
    Ok(Object::AddressSpace(Arc::new(SpinLock::with_class(
        LockClass::AddressSpace,
        space,
    ))))
}

/// `MemoryObject` de `bytes`; com `lazy`, sem frames (ADR 0038, item 1).
#[inline(never)]
pub(crate) fn new_memory_object(
    quota: &Arc<MemoryQuota>,
    bytes: u64,
    lazy: bool,
) -> Result<Object, Error> {
    let platform = platform::get().ok_or(Error::NotSupported)?;
    let memory = if lazy {
        MemoryObject::new_lazy(quota, bytes, platform)?
    } else {
        MemoryObject::new(quota, bytes, platform)?
    };
    Ok(Object::MemoryObject(Arc::new(memory)))
}

/// `MemoryObject` de MMIO (T-402); ver [`MemoryObject::new_device`].
pub(crate) fn new_device_memory(
    quota: &Arc<MemoryQuota>,
    base: u64,
    bytes: u64,
) -> Result<Object, Error> {
    let platform = platform::get().ok_or(Error::NotSupported)?;
    let memory = MemoryObject::new_device(quota, base, bytes, platform)?;
    Ok(Object::MemoryObject(Arc::new(memory)))
}

#[inline(never)]
fn new_thread(quota: &Arc<MemoryQuota>) -> Result<Object, Error> {
    let platform = platform::get().ok_or(Error::NotSupported)?;
    Ok(Object::Thread(Arc::new(Thread::new(quota, platform)?)))
}

#[inline(never)]
fn new_sched_context(quota: &Arc<MemoryQuota>) -> Result<Object, Error> {
    let charge = quota.charge(object_bytes::<SchedContext>())?;
    Ok(Object::SchedContext(Arc::new(SchedContext::new(charge))))
}

#[inline(never)]
fn new_notification(quota: &Arc<MemoryQuota>) -> Result<Object, Error> {
    Ok(Object::Notification(Arc::new(Notification::new(quota)?)))
}

#[inline(never)]
fn new_endpoint(quota: &Arc<MemoryQuota>) -> Result<Object, Error> {
    Ok(Object::Endpoint(Arc::new(Endpoint::new(quota)?)))
}

#[inline(never)]
fn new_reply(quota: &Arc<MemoryQuota>) -> Result<Object, Error> {
    Ok(Object::Reply(Arc::new(Reply::new(quota)?)))
}

#[inline(never)]
fn new_timer(quota: &Arc<MemoryQuota>) -> Result<Object, Error> {
    Ok(Object::Timer(Arc::pin(Timer::new(quota, &timer::QUEUES)?)))
}

#[cfg(test)]
mod tests;
