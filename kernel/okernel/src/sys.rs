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
//! Ordem de travas (seção 6.9, com a `CDT` da ADR 0028 à frente): o
//! `CapSpace` é solto antes de tocar no objeto; capabilities apagadas
//! morrem já sem a trava. `cap_mint`, `cap_delete` e `cap_revoke` passam
//! pela árvore entre tabelas ([`xcdt`]).

#![forbid(unsafe_code)]

use alloc::sync::Arc;

use kabi::sched::{CPU_MASK_BYTES, CpuMask};
use kabi::vm::{USER_END, USER_START};
use kabi::{Error, Handle, ObjectType, Rights, Syscall};

use crate::cap::space::Revoke;
use crate::cap::{Cap, Object, SharedCapSpace, default_rights, xcdt};
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
    /// Relógio monotônico, em ns.
    fn now(&self) -> u64;
    /// Como [`block`](Self::block), mas acorda com `TimedOut` em
    /// `deadline` (0 = sem prazo) se ninguém a acordar antes (IPC).
    fn block_until(&mut self, deadline: u64);
    /// Caminho rápido de IPC: a atual (já bloqueada) cede a CPU direto a
    /// `to` (bloqueada, já atendida), sem passar pela fila; se `to` não
    /// puder rodar agora, vale como acordá-la e [`block_until`](Self::block_until).
    fn handoff(&mut self, to: Arc<Thread>, deadline: u64);
    /// Como [`handoff`](Self::handoff), para o receptor `to` de uma
    /// chamada: ele segue quem chama e passa a rodar na CPU da atual, mesmo
    /// que esperasse noutra (ADR 0032, item 6). Sem várias CPUs, é o
    /// próprio `handoff`.
    fn follow(&mut self, to: Arc<Thread>, deadline: u64) {
        self.handoff(to, deadline);
    }
    /// Lê palavras do buffer de IPC de `thread`, a partir da palavra `at`;
    /// falso se não houver buffer ou a página não estiver mapeada.
    fn read_buffer(&mut self, thread: &Thread, at: usize, out: &mut [u64]) -> bool;
    /// Grava palavras no buffer de IPC de `thread`, a partir da palavra
    /// `at`; falso se não houver buffer ou ele não for gravável.
    fn write_buffer(&mut self, thread: &Thread, at: usize, data: &[u64]) -> bool;
    /// Lê `out.len()` bytes do usuário em `addr` (no espaço ativo); falso
    /// se alguma página não puder ser lida.
    fn read_bytes(&mut self, _addr: u64, _out: &mut [u8]) -> bool {
        false
    }
    /// CPUs ligadas (uma só, sem SMP).
    fn online_cpus(&self) -> CpuMask {
        CpuMask::only(0)
    }
    /// Um `SchedContext` passou a permitir só `mask` (ADR 0032, item 4):
    /// as CPUs fora dela que rodam ou têm na fila uma thread sobre ele
    /// reavaliam quem roda. Volta sem esperar.
    fn affinity_changed(&mut self, _mask: CpuMask) {}
    /// Põe `va` no `FS_BASE` desta CPU: `thread_configure` mudou o TLS da
    /// própria thread, que o vê ao voltar da syscall (ADR 0039, item 3).
    fn load_tls(&mut self, _va: u64) {}
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
    space: &Arc<SharedCapSpace>,
    call: Syscall,
    a: [u64; 6],
    revoke_budget: u32,
    env: &mut dyn Env,
) -> Result<Values, Error> {
    match call {
        Syscall::CapMint => mint(space, a),
        Syscall::CapDelete => {
            xcdt::delete(space, handle(a[0])?)?;
            Ok([0; 3])
        }
        Syscall::CapRevoke => {
            let h = handle(a[0])?;
            while xcdt::revoke(space, h, revoke_budget)? == Revoke::Continue {
                env.preempt();
                // Entre as fatias, uma revogação de fora pode ter apagado
                // o alvo (ADR 0028).
                if space.lock().get(h).is_err() {
                    return Err(Error::Revoked);
                }
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
            let object = space.lock().get(handle(a[1])?)?.clone();
            let aspace = aspace_of(space, a[0], env)?;
            vm_map(&aspace, &object, a[2], a[3], a[4], a[5]).map(|()| [0; 3])
        }
        Syscall::VmUnmap => {
            let aspace = aspace_of(space, a[0], env)?;
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
            if a[5] != 0 {
                return Err(Error::InvalidArgument);
            }
            let params = Params::new(a[1], a[2], a[3])?;
            let mask = match a[4] {
                0 => None,
                addr => Some(cpu_mask(addr, env)?),
            };
            sc.configure(params);
            if let Some(mask) = mask {
                sc.set_mask(mask);
                env.affinity_changed(mask);
                // Esta CPU pode ter saído da máscara da própria thread.
                env.preempt();
            }
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
        Syscall::ThreadConfigure => thread_configure(space, a, env).map(|()| [0; 3]),
        _ => invoke_sync(space, call, a, env),
    }
}

/// O espaço de `vm_map`/`vm_unmap`: a capability de `raw` ou, com
/// [`kabi::vm::SELF`], o espaço da thread que chama, com os direitos que um
/// `AddressSpace` recém-criado dá (`MAP` e `UNMAP`; ADR 0039, item 2).
fn aspace_of(space: &SharedCapSpace, raw: u64, env: &dyn Env) -> Result<Cap, Error> {
    if raw != kabi::vm::SELF {
        return Ok(space.lock().get(handle(raw)?)?.clone());
    }
    let own = env
        .current()
        .and_then(|t| t.aspace())
        .ok_or(Error::InvalidHandle)?;
    Ok(Cap {
        object: Object::AddressSpace(own),
        rights: default_rights(ObjectType::AddressSpace),
        badge: 0,
    })
}

/// Máscara de afinidade de `sched_configure` (`r8`, ADR 0032, item 4): uma
/// [`CpuMask`] alinhada a 8 na memória do usuário, com alguma CPU ligada.
fn cpu_mask(addr: u64, env: &mut dyn Env) -> Result<CpuMask, Error> {
    let end = USER_END - CPU_MASK_BYTES as u64;
    if !addr.is_multiple_of(8) || !(USER_START..=end).contains(&addr) {
        return Err(Error::InvalidArgument);
    }
    let mut bytes = [0u8; CPU_MASK_BYTES];
    if !env.read_bytes(addr, &mut bytes) {
        return Err(Error::InvalidArgument);
    }
    let mask = CpuMask::from_bytes(&bytes);
    if mask.and(&env.online_cpus()).is_empty() {
        return Err(Error::InvalidArgument);
    }
    Ok(mask)
}

/// `cap_mint(origem, máscara, badge, destino)`: com `destino` (um
/// `CapSpace` com `MANAGE`) diferente da própria tabela, a cópia, com as
/// regras de `mint`, nasce lá como filha remota da origem (ADR 0029 sobre
/// a árvore da ADR 0028): revogar a origem apaga a cópia.
fn mint(space: &Arc<SharedCapSpace>, a: [u64; 6]) -> Result<Values, Error> {
    let badge = (a[2] != 0).then_some(a[2]);
    let (src, mask) = (handle(a[0])?, rights(a[1])?);
    let h = match a[3] {
        0 => xcdt::mint(space, src, mask, badge)?,
        raw => {
            let cap = cap_with(space, raw, Rights::MANAGE)?;
            let dest = Arc::clone(cap.object.as_cap_space()?);
            drop(cap);
            xcdt::mint_into(space, src, mask, badge, &dest)?
        }
    };
    Ok([u64::from(h.raw()), 0, 0])
}

/// `thread_configure(thread, cspace, aspace, buffer ou TLS, exceção,
/// flags)` (ADR 0029 e ADR 0039, item 3): confere tudo antes de mudar
/// qualquer campo. `thread = SELF` é a própria, sem capability, e não liga
/// `CapSpace` nem `AddressSpace`.
fn thread_configure(space: &SharedCapSpace, a: [u64; 6], env: &mut dyn Env) -> Result<(), Error> {
    use kabi::thread::{CONFIGURE_ALL, CONFIGURE_EXCEPTION, CONFIGURE_IPC_BUFFER, CONFIGURE_TLS};
    let flags = a[5];
    let buffer = flags & CONFIGURE_IPC_BUFFER != 0;
    let tls = flags & CONFIGURE_TLS != 0;
    // As duas usam `r10`.
    if flags & !CONFIGURE_ALL != 0 || (buffer && tls) {
        return Err(Error::InvalidArgument);
    }
    let me = env.current();
    let t = if a[0] == kabi::thread::SELF {
        if a[1] != 0 || a[2] != 0 {
            return Err(Error::InvalidArgument);
        }
        me.clone().ok_or(Error::InvalidHandle)?
    } else {
        let thread = cap_with(space, a[0], Rights::WRITE_STATE)?;
        Arc::clone(thread.object.as_thread()?)
    };
    let bind = match (a[1], a[2]) {
        (0, 0) => None,
        (0, _) | (_, 0) => return Err(Error::InvalidArgument),
        (c, s) => {
            let cspace = cap_with(space, c, Rights::MANAGE)?;
            let aspace = cap_with(space, s, Rights::MAP)?;
            Some((
                Arc::clone(cspace.object.as_cap_space()?),
                Arc::clone(aspace.object.as_address_space()?),
            ))
        }
    };
    if (buffer && !Thread::valid_ipc_buffer(a[3])) || (tls && !Thread::valid_tls(a[3])) {
        return Err(Error::InvalidArgument);
    }
    let exception = if flags & CONFIGURE_EXCEPTION != 0 {
        Some(handle(a[4])?)
    } else {
        None
    };
    if let Some((cspace, aspace)) = bind {
        t.configure(cspace, aspace)?;
    }
    if buffer {
        t.set_ipc_buffer(a[3])?;
    }
    if let Some(h) = exception {
        t.set_exception_handler(h);
    }
    if tls {
        t.set_tls(a[3])?;
        if me.is_some_and(|m| Arc::ptr_eq(&m, &t)) {
            env.load_tls(a[3]);
        }
    }
    Ok(())
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
                    if let Some(e) = me.take_wake_error() {
                        return Err(e);
                    }
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
