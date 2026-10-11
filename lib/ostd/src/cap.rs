//! Capabilities e objetos do kernel (SDD v1.0, seções 6.1 e 6.2):
//! `obj_create`, `cap_mint`, `cap_delete` e `cap_info`.

use kabi::{Badge, Error, Handle, ObjectType, Rights, Syscall};

use crate::sys::syscall;

pub(crate) fn raw(h: Handle) -> u64 {
    u64::from(h.raw())
}

fn handle(v: u64) -> Result<Handle, Error> {
    u32::try_from(v)
        .map(Handle::from_raw)
        .map_err(|_| Error::InvalidHandle)
}

/// `obj_create`: objeto novo de `ty` na cota `quota`, com `args` (bytes de
/// um `MemoryObject` ou de uma cota filha; zero para os demais).
///
/// # Errors
///
/// Os do kernel (`QuotaExceeded`, `AccessDenied` sem `CREATE`...).
pub fn create(quota: Handle, ty: ObjectType, args: u64) -> Result<Handle, Error> {
    let [h, ..] = syscall(Syscall::ObjCreate, [raw(quota), ty.to_raw(), args, 0, 0, 0])?;
    handle(h)
}

/// `cap_mint`: cópia de `src` com os direitos reduzidos por `rights` e,
/// se `src` não tiver badge, `badge` (0 mantém). Com `dest`, a cópia vai
/// para aquele `CapSpace` (precisa de `MANAGE`; ADR 0029) e o handle
/// devolvido vale lá.
///
/// # Errors
///
/// Os do kernel.
pub fn mint(
    src: Handle,
    rights: Rights,
    badge: Badge,
    dest: Option<Handle>,
) -> Result<Handle, Error> {
    let dest = dest.map_or(0, raw);
    let args = [raw(src), u64::from(rights.bits()), badge, dest, 0, 0];
    let [h, ..] = syscall(Syscall::CapMint, args)?;
    handle(h)
}

/// `cap_delete`.
///
/// # Errors
///
/// `InvalidHandle` para handle sem capability.
pub fn delete(h: Handle) -> Result<(), Error> {
    syscall(Syscall::CapDelete, [raw(h), 0, 0, 0, 0, 0]).map(drop)
}

/// O que `cap_info` diz de uma capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// Tipo do objeto.
    pub object_type: ObjectType,
    /// Direitos.
    pub rights: Rights,
    /// Badge.
    pub badge: Badge,
}

/// `cap_info`.
///
/// # Errors
///
/// `InvalidHandle` para handle sem capability.
pub fn info(h: Handle) -> Result<Info, Error> {
    let [ty, rights, badge] = syscall(Syscall::CapInfo, [raw(h), 0, 0, 0, 0, 0])?;
    Ok(Info {
        object_type: ObjectType::try_from(ty).map_err(|_| Error::NotSupported)?,
        rights: Rights::try_from(rights).map_err(|_| Error::NotSupported)?,
        badge,
    })
}
