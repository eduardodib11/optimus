//! Memória gerenciada (ADR 0038, itens 1, 2 e 5): `MemoryObject` `LAZY`,
//! `mem_op` e a classe de memória de `sys_info`.

use kabi::mem::{COMMIT, LAZY, PUBLISH_FLAG};
use kabi::sched::SYS_INFO_MEMORY;
use kabi::{Error, Handle, ObjectType, Syscall};

use crate::cap::{handle, raw};
use crate::sys::syscall;

/// `obj_create(quota, MemoryObject, bytes, LAZY)`: objeto sem frames, cobrado
/// só pelos metadados; o criador recebe também `EVICT`.
///
/// # Errors
///
/// Os do kernel.
pub fn create_lazy(quota: Handle, bytes: u64) -> Result<Handle, Error> {
    let ty = ObjectType::MemoryObject.to_raw();
    let [h, ..] = syscall(Syscall::ObjCreate, [raw(quota), ty, bytes, LAZY, 0, 0])?;
    handle(h)
}

/// `mem_op(object, op, offset, len, flags)`; devolve o valor da operação.
///
/// # Errors
///
/// Os do kernel.
pub fn op(object: Handle, op: u64, offset: u64, len: u64, flags: u64) -> Result<u64, Error> {
    syscall(Syscall::MemOp, [raw(object), op, offset, len, flags, 0]).map(|[v, ..]| v)
}

/// `COMMIT` de `[offset, offset + len)`, publicando se `publish`. Página já
/// comprometida fica como está.
///
/// # Errors
///
/// Os do kernel (`QuotaExceeded` sem cota...).
pub fn commit(object: Handle, offset: u64, len: u64, publish: bool) -> Result<(), Error> {
    let flags = if publish { PUBLISH_FLAG } else { 0 };
    op(object, COMMIT, offset, len, flags).map(drop)
}

/// Estado global da memória (`sys_info` classe 3), em quadros de 4 KiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Quadros gerenciados pelo kernel.
    pub total: u64,
    /// Quadros livres (buddy e caches por CPU).
    pub free: u64,
    /// Quadros comprometidos de objetos `LAZY`.
    pub lazy_committed: u64,
}

/// `sys_info(SYS_INFO_MEMORY)`.
///
/// # Errors
///
/// Os do kernel.
pub fn stats() -> Result<Stats, Error> {
    syscall(Syscall::SysInfo, [SYS_INFO_MEMORY, 0, 0, 0, 0, 0]).map(|[total, free, lazy]| Stats {
        total,
        free,
        lazy_committed: lazy,
    })
}
