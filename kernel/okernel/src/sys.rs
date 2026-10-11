//! Despacho portável das syscalls (T-206, T-209; SDD v1.0, seções 14.1 e
//! 14.2): as que dependem do `CapSpace` do chamador e, por [`Env`], as que
//! bloqueiam ou acordam threads (notificações e futex).
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

use kabi::vm::{USER_END, USER_START};
use kabi::{Error, Handle, ObjectType, Rights, Syscall};

use crate::cap::space::Revoke;
use crate::cap::{Cap, SharedCapSpace};
use crate::futex::FUTEXES;
use crate::notify::Wait;
use crate::sched::Params;
use crate::thread::Thread;
use crate::vm::{vm_map, vm_protect, vm_unmap};

/// Valores devolvidos em `rdx`, `r10` e `r8`.
pub type Values = [u64; 3];

/// O que o despacho pede ao kernel além do `CapSpace`.
pub trait Env {
    /// Ponto de preempção (ADR 0009): entre fatias de `cap_revoke` e depois
    /// de acordar alguém, que pode ter prioridade maior.
    fn preempt(&mut self);
    /// Põe `thread` (bloqueada) de volta na fila, recebendo `value`.
    fn wake(&mut self, thread: Arc<Thread>, value: u64);
    /// A thread que fez a syscall.
    fn current(&self) -> Option<Arc<Thread>>;
    /// Tira da CPU a thread atual, já marcada como bloqueada, até que
    /// alguém a acorde.
    fn block(&mut self);
    /// Lê a palavra de 32 bits do usuário em `addr` (no espaço ativo).
    fn read_u32(&mut self, addr: u64) -> Option<u32>;
}

fn handle(raw: u64) -> Result<Handle, Error> {
    Handle::try_from(raw).map_err(|_| Error::InvalidHandle)
}

fn rights(raw: u64) -> Result<Rights, Error> {
    Rights::try_from(raw).map_err(|_| Error::InvalidArgument)
}

/// A capability de `raw`, conferindo os direitos `need`.
fn cap_with(space: &SharedCapSpace, raw: u64, need: Rights) -> Result<Cap, Error> {
    let cap = space.lock().get(handle(raw)?)?.clone();
    if cap.rights.contains(need) {
        Ok(cap)
    } else {
        Err(Error::AccessDenied)
    }
}

/// Chave de futex da palavra em `addr`: o endereço físico dela no espaço
/// da thread.
fn futex_key(thread: &Thread, addr: u64) -> Result<u64, Error> {
    if !addr.is_multiple_of(4) || !(USER_START..=USER_END - 4).contains(&addr) {
        return Err(Error::InvalidArgument);
    }
    let aspace = thread.aspace().ok_or(Error::InvalidArgument)?;
    let (page, _) = aspace.lock().query(addr).ok_or(Error::InvalidArgument)?;
    Ok((page.0 & !0xfff) | (addr & 0xfff))
}

/// Executa a syscall `call` com os argumentos `a` sobre `space`.
///
/// `cap_revoke` roda em fatias de `revoke_budget` passos e chama
/// [`Env::preempt`] entre elas, sem a trava do `CapSpace`.
///
/// # Errors
///
/// Os da syscall; [`Error::NotSupported`] para as tratadas fora daqui.
pub fn invoke(
    space: &SharedCapSpace,
    call: Syscall,
    a: [u64; 6],
    revoke_budget: u32,
    env: &mut dyn Env,
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
                env.preempt();
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
        _ => invoke_sync(space, call, a, env),
    }
}

/// Notificações, interrupções e futex (T-209).
fn invoke_sync(
    space: &SharedCapSpace,
    call: Syscall,
    a: [u64; 6],
    env: &mut dyn Env,
) -> Result<Values, Error> {
    match call {
        Syscall::NtfySignal => {
            let cap = cap_with(space, a[0], Rights::SIGNAL)?;
            let bits = a[1] | cap.badge;
            if bits == 0 {
                return Err(Error::InvalidArgument);
            }
            if let Some((thread, word)) = cap.object.as_notification()?.signal(bits) {
                env.wake(thread, word);
                env.preempt();
            }
            Ok([0; 3])
        }
        Syscall::NtfyPoll => {
            let cap = cap_with(space, a[0], Rights::WAIT)?;
            Ok([cap.object.as_notification()?.poll(), 0, 0])
        }
        Syscall::NtfyWait => {
            let cap = cap_with(space, a[0], Rights::WAIT)?;
            let ntfy = cap.object.as_notification()?;
            let me = env.current().ok_or(Error::NotSupported)?;
            match ntfy.wait(&me)? {
                Wait::Ready(bits) => Ok([bits, 0, 0]),
                Wait::Blocked => {
                    drop(cap);
                    env.block();
                    Ok([me.wake_value(), 0, 0])
                }
            }
        }
        Syscall::ObjBindNotify => {
            let obj = cap_with(space, a[0], Rights::BIND)?;
            let ntfy = cap_with(space, a[1], Rights::SIGNAL)?;
            let ntfy = Arc::clone(ntfy.object.as_notification()?);
            obj.object.as_interrupt()?.bind(ntfy, a[2])?;
            Ok([0; 3])
        }
        Syscall::IrqAck => {
            let cap = cap_with(space, a[0], Rights::ACK)?;
            if let Some((ntfy, bits)) = cap.object.as_interrupt()?.ack()
                && let Some((thread, word)) = ntfy.signal(bits)
            {
                env.wake(thread, word);
                env.preempt();
            }
            Ok([0; 3])
        }
        Syscall::FutexWait => {
            let me = env.current().ok_or(Error::NotSupported)?;
            let key = futex_key(&me, a[0])?;
            let expected = u32::try_from(a[1]).map_err(|_| Error::InvalidArgument)?;
            FUTEXES.wait(key, &me, expected, || env.read_u32(a[0]))?;
            env.block();
            Ok([0; 3])
        }
        Syscall::FutexWake => {
            let me = env.current().ok_or(Error::NotSupported)?;
            let key = futex_key(&me, a[0])?;
            let woken = FUTEXES.wake(key, a[1], &mut |t| env.wake(t, 0));
            if woken > 0 {
                env.preempt();
            }
            Ok([woken, 0, 0])
        }
        _ => Err(Error::NotSupported),
    }
}

#[cfg(test)]
mod tests;
