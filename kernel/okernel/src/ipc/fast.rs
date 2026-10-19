//! Caminho rápido de IPC (T-331; seção 6.7; ADR 0027; spec `Ipc.tla`).
//!
//! Dois casos, os da ida e volta cliente-servidor:
//!
//! - `ipc_call` que acha o servidor esperando no endpoint, nesta CPU;
//! - `ipc_reply_recv` que responde a quem chamou, nesta CPU, e não acha
//!   remetente na fila.
//!
//! Nos dois, a mensagem vai só em registradores, sem flags e sem prazo.
//!
//! Como no seL4, cada função primeiro confere as condições sem mudar nada
//! e devolve [`Fast::Slow`] se alguma falha; quem chama segue então pelo
//! caminho comum ([`ops::invoke_as`]). Valendo as condições, faz as mesmas
//! transições do caminho comum, na mesma ordem e com as mesmas travas, sem
//! montar `Outgoing` nem `Step` e sem clonar as capabilities. O endpoint e
//! o `Reply` ficam emprestados do `CapSpace`, com a trava dele na mão, que
//! vem antes das do objeto (seção 6.9). O fim é a troca direta para a
//! outra thread ([`Fast::Switch`]), que quem chama faz no escalonador; ao
//! voltar a rodar, a atual lê o que chegou com [`ops::finish`].

#![forbid(unsafe_code)]

use alloc::sync::Arc;

use kabi::ipc::{MsgInfo, split_recv_target};
use kabi::{Error, Handle, MSG_REG_WORDS, Rights};

use super::ops::{self, Out, Regs, Wait};
use super::{Blocked, Message};
use crate::cap::{Object, SharedCapSpace};
use crate::sys::Env;
use crate::thread::Thread;

/// Resultado do caminho rápido.
#[derive(Debug)]
pub enum Fast {
    /// As condições não valem e nada mudou: segue pelo caminho comum.
    Slow,
    /// A atual ficou bloqueada; a outra thread, nesta CPU e já atendida,
    /// recebe a CPU direto.
    Switch(Arc<Thread>),
    /// Terminou sem trocar (`ipc_reply_recv` que, depois de responder,
    /// achou um remetente que chegou de outra CPU, ou um erro).
    Done(Result<Out, Error>),
}

/// A mensagem, se cabe no caminho rápido: só palavras em registradores
/// (`MsgInfo` sem capabilities, buffer nem flags) e sem prazo. É a que o
/// caminho comum montaria.
fn message(regs: &Regs) -> Option<Message> {
    if regs.deadline != 0 || regs.info > MSG_REG_WORDS as u64 {
        return None;
    }
    #[allow(clippy::cast_possible_truncation, reason = "no máximo 6")]
    let n = regs.info as u8;
    let mut words = [0; MSG_REG_WORDS];
    words[..usize::from(n)].copy_from_slice(&regs.words[..usize::from(n)]);
    Some(Message {
        label: regs.label,
        info: MsgInfo::words(n),
        words,
    })
}

/// `t` pode receber a troca direta na CPU `cpu`: é dela e a pilha está
/// livre.
fn here(t: &Thread, cpu: u32) -> bool {
    t.cpu() == cpu && !t.on_cpu()
}

/// Entrega `msg` com `badge` no slot de `to` e marca a espera como
/// atendida (o `deliver` do caminho comum, sem buffer).
fn deliver(slot: &mut super::IpcSlot, msg: Message, badge: u64) {
    slot.inbox = msg;
    slot.badge = badge;
    slot.blocked = Blocked::None;
    slot.result = Ok(());
}

/// `ipc_call` da thread atual `me`, na CPU `cpu`, pelo caminho rápido.
pub fn call(space: &SharedCapSpace, me: &Arc<Thread>, regs: &Regs, cpu: u32) -> Fast {
    let Some(msg) = message(regs) else {
        return Fast::Slow;
    };
    let Ok(h) = Handle::try_from(regs.target) else {
        return Fast::Slow;
    };
    let cs = space.lock();
    let Ok(cap) = cs.get(h) else {
        return Fast::Slow;
    };
    let (Object::Endpoint(ep), true) = (&cap.object, cap.rights.contains(Rights::SEND)) else {
        return Fast::Slow;
    };
    let badge = cap.badge;
    // O receptor da frente serve se espera em `Recv` nesta CPU; então é
    // atendido ali mesmo, com as travas da fila e do slot dele na mão.
    let taken = ep.take_receiver(|r| {
        if !here(r, cpu) {
            return None;
        }
        let mut slot = r.ipc().lock();
        if !slot.receiving() {
            return None;
        }
        let Blocked::Recv(_, reply, grant) = core::mem::take(&mut slot.blocked) else {
            return None;
        };
        deliver(&mut slot, msg, badge);
        Some((reply, grant))
    });
    drop(cs);
    let Some((server, (reply, grant))) = taken else {
        return Fast::Slow;
    };
    // Como no `send_out`: o receptor só entra na fila com o `Reply` vazio.
    let _ = reply.bind(Arc::clone(me), grant);
    reply.donate(&server);
    ops::block(me, Blocked::Reply(Arc::downgrade(&reply)), None);
    drop(reply);
    Fast::Switch(server)
}

/// `ipc_reply_recv` da thread atual `me`, na CPU `cpu`, pelo caminho
/// rápido; `env` só serve se um remetente chegar de outra CPU entre a
/// conferência e a entrada na fila.
pub fn reply_recv(
    space: &SharedCapSpace,
    me: &Arc<Thread>,
    regs: &Regs,
    cpu: u32,
    env: &mut dyn Env,
) -> Fast {
    let Some(msg) = message(regs) else {
        return Fast::Slow;
    };
    let (eh, rh) = split_recv_target(regs.target);
    let cs = space.lock();
    let (Ok(ec), Ok(rc)) = (cs.get(eh), cs.get(rh)) else {
        return Fast::Slow;
    };
    let (Object::Endpoint(ep), Object::Reply(reply)) = (&ec.object, &rc.object) else {
        return Fast::Slow;
    };
    if !ec.rights.contains(Rights::RECV) || !rc.rights.contains(Rights::SEND) {
        return Fast::Slow;
    }
    let grant = ec.rights.contains(Rights::GRANT);
    if !reply.caller_on(cpu) || ep.has_senders() {
        return Fast::Slow;
    }
    // Daqui em diante, o que o caminho comum faz (`reply_to` e
    // `receive`). Quem chamou pode ter saído do `Reply` (prazo) desde a
    // conferência: então nada mudou e o caminho comum decide.
    let Some((caller, _)) = reply.take() else {
        return Fast::Slow;
    };
    deliver(&mut caller.ipc().lock(), msg, 0);
    let received = ops::receive(me, ep, reply, grant, Wait::FOREVER);
    match received {
        Ok(None) => {
            drop(cs);
            Fast::Switch(caller)
        }
        Ok(Some(sender)) => {
            // Chegou de outra CPU depois da conferência: como no caminho
            // comum, recebe dele, sem a trava do `CapSpace` (a entrega
            // pode transferir capabilities).
            let reply = Arc::clone(reply);
            drop(cs);
            ops::take_from(me, sender, &reply, grant, env);
            env.wake(caller, 0);
            env.preempt();
            Fast::Done(ops::finish(me))
        }
        Err(e) => {
            drop(cs);
            env.wake(caller, 0);
            Fast::Done(Err(e))
        }
    }
}

#[cfg(test)]
mod tests;
