//! As quatro primitivas de IPC (T-208; seção 6.7; ADR 0027; spec `Ipc.tla`).
//!
//! - `ipc_send(ep)`: entrega ao primeiro receptor ou espera na fila de
//!   envio. `ipc_send(reply)` responde a quem chamou, sem bloquear.
//! - `ipc_call(ep)`: como `ipc_send`, mas o receptor guarda o chamador no
//!   `Reply` dele e o chamador espera a resposta.
//! - `ipc_recv(ep | reply)`: recebe do primeiro remetente ou espera na fila
//!   de receptores. Recusado com `Busy` se o `Reply` ainda tem chamador
//!   (ele ficaria órfão; `Recv` da spec exige `reply = None`).
//! - `ipc_reply_recv(ep | reply)`: responde pelo `Reply` (se houver quem
//!   espere), que fica vazio, e recebe nele de novo.
//!
//! Direitos: `SEND` no endpoint para enviar, `RECV` para receber, `SEND` no
//! `Reply`. Capabilities na mensagem exigem `GRANT` na capability do
//! endpoint do remetente (senão `AccessDenied` e nada é enviado,
//! `GrantRequired` da spec); numa resposta, exigem `GRANT` na capability do
//! endpoint pela qual o servidor recebeu a chamada (definido aqui).
//!
//! A capability transferida é uma cópia com os mesmos direitos e badge,
//! filha da original na árvore de derivação (ADR 0028,
//! [`xcdt::transfer`]): revogar a original apaga a cópia. Os handles são
//! conferidos no envio e copiados na entrega; o que sumiu do remetente
//! entre um e outro não chega.
//! Receptor sem buffer de IPC, ou sem espaço no `CapSpace`, recebe menos
//! capabilities e palavras longas; `info` diz quantas chegaram.
//!
//! Prazo (`r10`): instante absoluto do relógio monotônico; vencido (e não
//! zero), a syscall não bloqueia e devolve `TimedOut` se não houver par
//! pronto; [`FLAG_NONBLOCK`] faz o mesmo com `WouldBlock`. O prazo de
//! `ipc_call` vale também para a espera da resposta.
//!
//! Doação de `SchedContext` (seção 6.6): quem recebe uma chamada roda com
//! o `SchedContext` de quem chamou (o tempo e a prioridade dele) até
//! responder pelo `Reply`, ou até a espera acabar de outro jeito (prazo,
//! `Reply` destruído); a doação passa adiante em chamadas aninhadas.
//!
//! Caminho rápido (seção 6.7): `ipc_call` que encontra o servidor esperando
//! e `ipc_reply_recv` que não encontra outro remetente, ambos só com
//! registradores, pedem a [`Env::handoff`] a troca direta para a outra
//! thread, sem passar pela fila de prontas.
//!
//! Cada syscall se divide em [`begin`], que pode deixar a thread bloqueada
//! ([`Step::Block`]), e [`finish`], que lê o resultado depois que alguém a
//! acorda; [`invoke`] junta as duas com o [`Env`].

#![forbid(unsafe_code)]

use alloc::sync::{Arc, Weak};

use kabi::ipc::{FLAG_NONBLOCK, IpcBuffer, MsgInfo, split_recv_target};
use kabi::{Error, Handle, MSG_MAX_CAPS, MSG_REG_WORDS, Rights, Syscall};

use super::{Blocked, Endpoint, Message, Outgoing, Reply};
use crate::cap::{Cap, Object, SharedCapSpace, xcdt};
use crate::sys::Env;
use crate::thread::{RunState, Thread};

/// Registradores de entrada (ADR 0027).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    /// `rdi`: endpoint, `Reply` ou os dois (`recv_target`).
    pub target: u64,
    /// `rsi`: rótulo.
    pub label: u64,
    /// `rdx`: `MsgInfo` cru.
    pub info: u64,
    /// `r10`: prazo absoluto em ns (0 = sem prazo).
    pub deadline: u64,
    /// `r8`, `r9`, `r12`–`r15`.
    pub words: [u64; MSG_REG_WORDS],
}

/// Registradores de saída (ADR 0027).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Out {
    /// `rdi`: badge do remetente (zero numa resposta).
    pub badge: u64,
    /// `rsi`: rótulo.
    pub label: u64,
    /// `rdx`: `MsgInfo` cru do que chegou.
    pub info: u64,
    /// `r8`, `r9`, `r12`–`r15`.
    pub words: [u64; MSG_REG_WORDS],
}

/// Resultado de [`begin`].
#[derive(Debug)]
pub enum Step {
    /// Terminou sem bloquear.
    Done(Out),
    /// A thread atual ficou bloqueada (já marcada) até `deadline` (0 =
    /// sem prazo); com `handoff`, deve ceder a CPU direto a essa thread.
    Block {
        /// Prazo absoluto.
        deadline: u64,
        /// Thread para a troca direta do caminho rápido.
        handoff: Option<Arc<Thread>>,
    },
}

/// Como esperar: pode bloquear e o erro de quando não pode.
#[derive(Clone, Copy)]
struct Wait {
    deadline: u64,
    refuse: Option<Error>,
}

impl Wait {
    fn new(info: MsgInfo, deadline: u64, now: u64) -> Self {
        let refuse = if info.flags & FLAG_NONBLOCK != 0 {
            Some(Error::WouldBlock)
        } else if deadline != 0 && deadline <= now {
            Some(Error::TimedOut)
        } else {
            None
        };
        Self { deadline, refuse }
    }
}

fn cap(space: &SharedCapSpace, h: Handle, need: Rights) -> Result<Cap, Error> {
    let cap = space.lock().get(h)?.clone();
    if cap.rights.contains(need) {
        Ok(cap)
    } else {
        Err(Error::AccessDenied)
    }
}

fn handle(raw: u64) -> Result<Handle, Error> {
    Handle::try_from(raw).map_err(|_| Error::InvalidHandle)
}

/// Monta a mensagem de saída da thread atual: só as palavras declaradas,
/// e as capabilities do cabeçalho do buffer dela, se `grant` permitir.
fn outgoing(
    space: &Arc<SharedCapSpace>,
    me: &Thread,
    regs: &Regs,
    grant: bool,
    env: &mut dyn Env,
) -> Result<Outgoing, Error> {
    let mut info = MsgInfo::try_from(regs.info).map_err(|_| Error::InvalidArgument)?;
    info.flags = 0;
    let mut words = [0; MSG_REG_WORDS];
    let n = usize::from(info.words);
    words[..n].copy_from_slice(&regs.words[..n]);
    let mut out = Outgoing {
        msg: Message {
            label: regs.label,
            info,
            words,
        },
        ..Outgoing::default()
    };
    if info.caps > 0 && !grant {
        return Err(Error::AccessDenied);
    }
    if !info.registers_only() && me.ipc_buffer().is_none() {
        return Err(Error::InvalidArgument);
    }
    if info.caps > 0 {
        let mut header = [0u64; 2];
        if !env.read_buffer(me, 0, &mut header) {
            return Err(Error::InvalidArgument);
        }
        let s = space.lock();
        for (i, slot) in out.caps.iter_mut().take(usize::from(info.caps)).enumerate() {
            #[allow(clippy::cast_possible_truncation, reason = "metade de 32 bits")]
            let h = Handle::from_raw((header[i / 2] >> (32 * (i % 2))) as u32);
            s.get(h)?;
            *slot = Some(h);
        }
        out.from = Some(Arc::downgrade(space));
    }
    Ok(out)
}

/// Copia as palavras longas de `from` para `to`; quantas chegaram.
fn copy_words(from: &Thread, to: &Thread, count: u16, env: &mut dyn Env) -> u16 {
    let mut chunk = [0u64; 63];
    let mut done = 0;
    while done < count {
        let n = (count - done).min(63);
        let at = IpcBuffer::WORDS_OFFSET + usize::from(done);
        let part = &mut chunk[..usize::from(n)];
        if !env.read_buffer(from, at, part) || !env.write_buffer(to, at, part) {
            return done;
        }
        done += n;
    }
    done
}

/// Copia as capabilities de `from` para o `CapSpace` de `to` e grava os
/// handles no buffer dela; quantas chegaram (para na primeira que não
/// couber ou que sumiu do remetente).
fn transfer_caps(
    to: &Thread,
    from: Option<Weak<SharedCapSpace>>,
    caps: [Option<Handle>; MSG_MAX_CAPS],
    env: &mut dyn Env,
) -> u8 {
    let (Some(space), Some(from)) = (to.cspace(), from.and_then(|f| f.upgrade())) else {
        return 0;
    };
    let mut handles = [0u32; MSG_MAX_CAPS];
    let mut n = 0;
    for h in caps.into_iter().flatten() {
        match xcdt::transfer(&from, h, &space) {
            Ok(h) => {
                handles[n] = h.raw();
                n += 1;
            }
            Err(_) => break,
        }
    }
    let header = [
        u64::from(handles[0]) | (u64::from(handles[1]) << 32),
        u64::from(handles[2]) | (u64::from(handles[3]) << 32),
    ];
    if n > 0 && !env.write_buffer(to, 0, &header) {
        for &h in &handles[..n] {
            let _ = xcdt::delete(&space, Handle::from_raw(h));
        }
        return 0;
    }
    #[allow(clippy::cast_possible_truncation, reason = "no máximo 4")]
    let n = n as u8;
    n
}

/// Entrega `out` (de `from`) na caixa de entrada de `to` e marca a espera
/// de `to` como atendida.
fn deliver(from: &Thread, out: Outgoing, to: &Thread, env: &mut dyn Env) {
    let mut msg = out.msg;
    let has_buffer = to.ipc_buffer().is_some();
    msg.info.buffer_words = if has_buffer {
        copy_words(from, to, msg.info.buffer_words, env)
    } else {
        0
    };
    msg.info.caps = if has_buffer {
        transfer_caps(to, out.from, out.caps, env)
    } else {
        0
    };
    let mut slot = to.ipc().lock();
    slot.inbox = msg;
    slot.badge = out.badge;
    slot.blocked = Blocked::None;
    slot.result = Ok(());
}

/// Bloqueia `me` como `blocked`; a fila é posta por quem chama.
fn block(me: &Thread, blocked: Blocked, out: Option<Outgoing>) {
    let mut slot = me.ipc().lock();
    slot.blocked = blocked;
    slot.out = out;
    slot.result = Err(Error::Cancelled);
    drop(slot);
    me.set_state(RunState::Blocked);
}

/// Desfaz [`block`] quando a fila recusa a thread.
fn unblock(me: &Thread) {
    let mut slot = me.ipc().lock();
    slot.blocked = Blocked::None;
    slot.out = None;
    drop(slot);
    me.set_state(RunState::Running);
}

/// Envio ou chamada num endpoint.
fn send(
    space: &Arc<SharedCapSpace>,
    me: &Arc<Thread>,
    ep_cap: &Cap,
    regs: &Regs,
    call: bool,
    env: &mut dyn Env,
) -> Result<Step, Error> {
    let ep = ep_cap.object.as_endpoint()?;
    if !ep_cap.rights.contains(Rights::SEND) {
        return Err(Error::AccessDenied);
    }
    let info = MsgInfo::try_from(regs.info).map_err(|_| Error::InvalidArgument)?;
    let wait = Wait::new(info, regs.deadline, env.now());
    let mut out = outgoing(space, me, regs, ep_cap.rights.contains(Rights::GRANT), env)?;
    out.badge = ep_cap.badge;
    out.call = call;
    send_out(me, ep, out, wait, env)
}

/// Entrega `out` ao primeiro receptor de `ep` ou põe `me` na fila de envio.
fn send_out(
    me: &Arc<Thread>,
    ep: &Arc<Endpoint>,
    out: Outgoing,
    wait: Wait,
    env: &mut dyn Env,
) -> Result<Step, Error> {
    let call = out.call;
    let fast = out.msg.info.registers_only();
    let Some(r) = ep.pop_receiver() else {
        if let Some(e) = wait.refuse {
            return Err(e);
        }
        block(me, Blocked::Send(Arc::downgrade(ep)), Some(out));
        if let Err(e) = ep.push_sender(me) {
            unblock(me);
            return Err(e);
        }
        return Ok(Step::Block {
            deadline: wait.deadline,
            handoff: None,
        });
    };
    let recv = core::mem::take(&mut r.ipc().lock().blocked);
    deliver(me, out, &r, env);
    if !call {
        env.wake(r, 0);
        env.preempt();
        return Ok(Step::Done(Out::default()));
    }
    let Blocked::Recv(_, reply, grant) = recv else {
        // Só threads em `Recv` entram na fila de receptores.
        env.wake(r, 0);
        return Err(Error::Cancelled);
    };
    // O receptor só entra na fila com o `Reply` vazio.
    let _ = reply.bind(Arc::clone(me), grant);
    reply.donate(&r);
    block(me, Blocked::Reply(Arc::downgrade(&reply)), None);
    let handoff = if fast {
        Some(r)
    } else {
        env.wake(r, 0);
        None
    };
    Ok(Step::Block {
        deadline: wait.deadline,
        handoff,
    })
}

/// Resposta pelo `Reply` (sem receber); devolve quem foi acordado.
fn reply_to(
    space: &Arc<SharedCapSpace>,
    me: &Thread,
    reply: &Reply,
    regs: &Regs,
    env: &mut dyn Env,
) -> Result<(Arc<Thread>, bool), Error> {
    let grant = reply.grant().ok_or(Error::PeerClosed)?;
    let out = outgoing(space, me, regs, grant, env)?;
    let fast = out.msg.info.registers_only();
    let (caller, _) = reply.take().ok_or(Error::PeerClosed)?;
    deliver(me, out, &caller, env);
    Ok((caller, fast))
}

/// Parte de recepção de `ipc_recv`/`ipc_reply_recv` (`RecvPart` da spec).
fn receive(
    me: &Arc<Thread>,
    ep: &Arc<Endpoint>,
    reply: &Arc<Reply>,
    grant: bool,
    wait: Wait,
) -> Result<Option<Arc<Thread>>, Error> {
    let Some(s) = ep.pop_sender() else {
        if let Some(e) = wait.refuse {
            return Err(e);
        }
        block(
            me,
            Blocked::Recv(Arc::downgrade(ep), Arc::clone(reply), grant),
            None,
        );
        if let Err(e) = ep.push_receiver(me) {
            unblock(me);
            return Err(e);
        }
        return Ok(None);
    };
    Ok(Some(s))
}

/// Entrega a mensagem do remetente `s`, já fora da fila, a `me`; devolve
/// se era uma chamada (e `me` passou a rodar com o tempo de `s`).
fn take_from(
    me: &Arc<Thread>,
    s: Arc<Thread>,
    reply: &Arc<Reply>,
    grant: bool,
    env: &mut dyn Env,
) -> bool {
    let out = s.ipc().lock().out.take().unwrap_or_default();
    let call = out.call;
    deliver(&s, out, me, env);
    if call {
        let _ = reply.bind(Arc::clone(&s), grant);
        reply.donate(me);
        s.ipc().lock().blocked = Blocked::Reply(Arc::downgrade(reply));
    } else {
        let mut slot = s.ipc().lock();
        slot.blocked = Blocked::None;
        slot.result = Ok(());
        drop(slot);
        env.wake(s, 0);
    }
    call
}

fn recv_caps(space: &SharedCapSpace, target: u64) -> Result<(Cap, Arc<Reply>), Error> {
    let (ep, reply) = split_recv_target(target);
    let ep = cap(space, ep, Rights::RECV)?;
    ep.object.as_endpoint()?;
    let reply = cap(space, reply, Rights::SEND)?;
    Ok((ep, Arc::clone(reply.object.as_reply()?)))
}

/// Primeira parte da syscall IPC `call`: tudo até bloquear (ou terminar).
///
/// # Errors
///
/// Os da syscall (ver o módulo).
pub fn begin(
    space: &Arc<SharedCapSpace>,
    call: Syscall,
    regs: &Regs,
    env: &mut dyn Env,
) -> Result<Step, Error> {
    let me = env.current().ok_or(Error::NotSupported)?;
    match call {
        Syscall::IpcSend | Syscall::IpcCall => {
            let target = cap(space, handle(regs.target)?, Rights::NONE)?;
            match (&target.object, call) {
                (Object::Reply(reply), Syscall::IpcSend) => {
                    if !target.rights.contains(Rights::SEND) {
                        return Err(Error::AccessDenied);
                    }
                    let (caller, _) = reply_to(space, &me, reply, regs, env)?;
                    env.wake(caller, 0);
                    env.preempt();
                    Ok(Step::Done(Out::default()))
                }
                _ => send(space, &me, &target, regs, call == Syscall::IpcCall, env),
            }
        }
        Syscall::IpcRecv | Syscall::IpcReplyRecv => {
            let (ep_cap, reply) = recv_caps(space, regs.target)?;
            let ep = ep_cap.object.as_endpoint()?;
            let grant = ep_cap.rights.contains(Rights::GRANT);
            let info = MsgInfo::try_from(regs.info).map_err(|_| Error::InvalidArgument)?;
            let wait = Wait::new(info, regs.deadline, env.now());
            let replied = if call == Syscall::IpcReplyRecv && reply.pending() {
                Some(reply_to(space, &me, &reply, regs, env)?)
            } else if reply.pending() {
                return Err(Error::Busy);
            } else {
                None
            };
            match receive(&me, ep, &reply, grant, wait) {
                Ok(Some(s)) => {
                    let donated = take_from(&me, s, &reply, grant, env);
                    if let Some((caller, _)) = &replied {
                        env.wake(Arc::clone(caller), 0);
                    }
                    // Acordou alguém ou mudou o `SchedContext` em que roda:
                    // o escalonador reavalia (e passa a cobrar o certo).
                    if donated || replied.is_some() {
                        env.preempt();
                    }
                    Ok(Step::Done(finish(&me)?))
                }
                Ok(None) => {
                    let handoff = match replied {
                        Some((caller, true)) => Some(caller),
                        Some((caller, false)) => {
                            env.wake(caller, 0);
                            None
                        }
                        None => None,
                    };
                    Ok(Step::Block {
                        deadline: wait.deadline,
                        handoff,
                    })
                }
                Err(e) => {
                    if let Some((caller, _)) = replied {
                        env.wake(caller, 0);
                    }
                    Err(e)
                }
            }
        }
        _ => Err(Error::NotSupported),
    }
}

/// O que a thread recebeu na última espera (depois de acordada).
///
/// # Errors
///
/// O erro gravado por quem a acordou (`TimedOut` no prazo).
pub fn finish(me: &Thread) -> Result<Out, Error> {
    let slot = me.ipc().lock();
    slot.result?;
    Ok(Out {
        badge: slot.badge,
        label: slot.inbox.label,
        info: slot.inbox.info.to_raw(),
        words: slot.inbox.words,
    })
}

/// Executa a syscall de IPC `call` da thread atual sobre `space`.
///
/// # Errors
///
/// Os da syscall (ver o módulo).
pub fn invoke(
    space: &Arc<SharedCapSpace>,
    call: Syscall,
    regs: &Regs,
    env: &mut dyn Env,
) -> Result<Out, Error> {
    let step = begin(space, call, regs, env)?;
    let me = env.current().ok_or(Error::NotSupported)?;
    let out = wait_for(&me, step, env)?;
    Ok(if call == Syscall::IpcSend {
        Out::default()
    } else {
        out
    })
}

/// Espera o fim de `step` (bloqueando `me`, se for o caso) e devolve o que
/// chegou.
fn wait_for(me: &Thread, step: Step, env: &mut dyn Env) -> Result<Out, Error> {
    match step {
        Step::Done(out) => Ok(out),
        Step::Block { deadline, handoff } => {
            match handoff {
                Some(to) => env.handoff(to, deadline),
                None => env.block_until(deadline),
            }
            finish(me)
        }
    }
}

/// `ipc_call` feito pelo kernel em nome de `me`, a thread atual, pela
/// capability `ep_cap` (falta de usuário, T-210): `msg` só em
/// registradores, sem capabilities e sem prazo. Devolve a resposta.
///
/// `ep_cap` é solta antes de esperar: a espera não mantém o endpoint vivo.
///
/// # Errors
///
/// [`Error::WrongType`] se `ep_cap` não for de endpoint;
/// [`Error::AccessDenied`] sem `SEND`; o erro da espera (`PeerClosed` se o
/// endpoint ou o `Reply` morrer antes da resposta).
pub fn kernel_call(
    me: &Arc<Thread>,
    ep_cap: Cap,
    msg: Message,
    env: &mut dyn Env,
) -> Result<Out, Error> {
    let ep = ep_cap.object.as_endpoint()?;
    if !ep_cap.rights.contains(Rights::SEND) {
        return Err(Error::AccessDenied);
    }
    let out = Outgoing {
        msg,
        badge: ep_cap.badge,
        call: true,
        ..Outgoing::default()
    };
    let wait = Wait {
        deadline: 0,
        refuse: None,
    };
    let step = send_out(me, ep, out, wait, env)?;
    drop(ep_cap);
    wait_for(me, step, env)
}

#[cfg(test)]
mod model;
#[cfg(test)]
pub(crate) mod tests;
