//! Despacho portável das syscalls que só dependem do `CapSpace` do
//! chamador (T-206; SDD v1.0, seções 14.1 e 14.2).
//!
//! Argumentos chegam crus, na ordem de registradores da seção 14.1 (`rdi`,
//! `rsi`, `rdx`, `r10`, `r8`, `r9`), e todo valor é validado por
//! `TryFrom<u64>` da `kabi`. Os valores de retorno vão na mesma ordem a
//! partir do segundo registrador de retorno: `rdx`, `r10`, `r8` (definido
//! aqui; a seção 14.1 só diz "rdx e seguintes"). Syscalls que o kernel trata
//! fora daqui (yield, saída e partida de threads, tempo) e as ainda não implementadas
//! devolvem [`Error::NotSupported`].
//!
//! Ordem de travas (seção 6.9): o `CapSpace` é solto antes de tocar no
//! objeto; capabilities apagadas morrem já sem a trava.

#![forbid(unsafe_code)]

use alloc::sync::Arc;

use kabi::{Error, Handle, ObjectType, Rights, Syscall};

use crate::cap::SharedCapSpace;
use crate::cap::space::Revoke;
use crate::sched::Params;
use crate::vm::{vm_map, vm_protect, vm_unmap};

/// Valores devolvidos em `rdx`, `r10` e `r8`.
pub type Values = [u64; 3];

fn handle(raw: u64) -> Result<Handle, Error> {
    Handle::try_from(raw).map_err(|_| Error::InvalidHandle)
}

fn rights(raw: u64) -> Result<Rights, Error> {
    Rights::try_from(raw).map_err(|_| Error::InvalidArgument)
}

/// Executa a syscall `call` com os argumentos `a` sobre `space`.
///
/// `cap_revoke` roda em fatias de `revoke_budget` passos e chama
/// `between_slices` (o ponto de preempção do kernel, ADR 0009) entre elas,
/// sem a trava do `CapSpace`.
///
/// # Errors
///
/// Os da syscall; [`Error::NotSupported`] para as tratadas fora daqui.
pub fn invoke(
    space: &SharedCapSpace,
    call: Syscall,
    a: [u64; 6],
    revoke_budget: u32,
    between_slices: &mut dyn FnMut(),
) -> Result<Values, Error> {
    match call {
        Syscall::CapMint => {
            let badge = (a[2] != 0).then_some(a[2]);
            let h = space.lock().mint(handle(a[0])?, rights(a[1])?, badge)?;
            Ok([u64::from(h.raw()), 0, 0])
        }
        Syscall::CapDelete => {
            let cap = space.lock().delete(handle(a[0])?)?;
            drop(cap);
            Ok([0; 3])
        }
        Syscall::CapRevoke => {
            let h = handle(a[0])?;
            while space.lock().revoke(h, revoke_budget)? == Revoke::Continue {
                between_slices();
            }
            Ok([0; 3])
        }
        Syscall::CapInfo => {
            let info = space.lock().info(handle(a[0])?)?;
            Ok([
                info.object_type.to_raw(),
                u64::from(info.rights.bits()),
                info.badge,
            ])
        }
        Syscall::ObjCreate => {
            let ty = ObjectType::try_from(a[1]).map_err(|_| Error::InvalidArgument)?;
            let h = space.lock().obj_create(handle(a[0])?, ty, a[2])?;
            Ok([u64::from(h.raw()), 0, 0])
        }
        Syscall::VmMap => {
            let (aspace, object) = {
                let s = space.lock();
                (s.get(handle(a[0])?)?.clone(), s.get(handle(a[1])?)?.clone())
            };
            vm_map(&aspace, &object, a[2], a[3], a[4], a[5]).map(|()| [0; 3])
        }
        Syscall::VmUnmap => {
            let aspace = space.lock().get(handle(a[0])?)?.clone();
            vm_unmap(&aspace, a[1], a[2]).map(|()| [0; 3])
        }
        Syscall::VmProtect => {
            let aspace = space.lock().get(handle(a[0])?)?.clone();
            vm_protect(&aspace, a[1], a[2], a[3]).map(|()| [0; 3])
        }
        Syscall::SchedConfigure => {
            let cap = space.lock().get(handle(a[0])?)?.clone();
            let sc = cap.object.as_sched_context()?;
            if !cap.rights.contains(Rights::CONFIGURE) {
                return Err(Error::AccessDenied);
            }
            sc.configure(Params::new(a[1], a[2], a[3])?);
            Ok([0; 3])
        }
        Syscall::SchedBind => {
            let (sc, thread) = {
                let s = space.lock();
                (s.get(handle(a[0])?)?.clone(), s.get(handle(a[1])?)?.clone())
            };
            let (sc_obj, t) = (sc.object.as_sched_context()?, thread.object.as_thread()?);
            if !sc.rights.contains(Rights::BIND) || !thread.rights.contains(Rights::WRITE_STATE) {
                return Err(Error::AccessDenied);
            }
            t.bind_sched(Arc::clone(sc_obj))?;
            Ok([0; 3])
        }
        _ => Err(Error::NotSupported),
    }
}

#[cfg(test)]
mod tests;
