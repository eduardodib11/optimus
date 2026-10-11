//! `Endpoint` e `Reply` (T-208; SDD v1.0, seções 6.1, 6.2 e 6.7; spec
//! `docs/spec/tla/Ipc.tla`).
//!
//! Um [`Endpoint`] é um ponto de encontro síncrono: duas filas FIFO, de
//! remetentes e de receptores bloqueados, das quais no máximo uma tem
//! alguém (`NoMissedRendezvous`). Um [`Reply`] guarda quem fez `ipc_call`
//! até a resposta; é de uso único: responder o esvazia.
//!
//! O que a thread leva ou recebe fica no [`IpcSlot`] dela: a mensagem de
//! saída enquanto espera na fila de envio, a de entrada entregue por quem a
//! acordou, onde está bloqueada e o resultado da espera. As syscalls ficam
//! em [`ops`].
//!
//! Travas (seção 6.9): a fila do objeto (`Endpoint` ou `Reply`) antes do
//! `IpcSlot` de uma thread; nada aqui segura duas delas ao mesmo tempo.
//! As filas crescem no heap sem cobrança de cota, como as de notificação:
//! uma thread espera em um objeto por vez.

#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::fmt;

use kabi::ipc::MsgInfo;
use kabi::{Badge, Error, MSG_MAX_CAPS, MSG_REG_WORDS};

use crate::cap::object::object_bytes;
use crate::cap::{Cap, Charge, MemoryQuota};
use crate::sync::SpinLock;
use crate::thread::Thread;

pub mod ops;

/// Rótulo, `info` e palavras em registradores.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// Rótulo de 64 bits.
    pub label: u64,
    /// Contagens e flags.
    pub info: MsgInfo,
    /// Palavras 0 a 5.
    pub words: [u64; MSG_REG_WORDS],
}

/// O que um remetente leva: a mensagem, as capabilities já resolvidas no
/// `CapSpace` dele e o badge da capability do endpoint.
#[derive(Debug, Default)]
pub struct Outgoing {
    /// Registradores da mensagem.
    pub msg: Message,
    /// Capabilities a transferir.
    pub caps: [Option<Cap>; MSG_MAX_CAPS],
    /// Badge entregue ao receptor.
    pub badge: Badge,
    /// `ipc_call`: espera a resposta.
    pub call: bool,
}

/// Onde a thread está bloqueada por IPC.
#[derive(Debug, Default)]
pub enum Blocked {
    /// Em lugar nenhum.
    #[default]
    None,
    /// Na fila de envio do endpoint (`SendBlk`/`CallBlk` da spec).
    Send(Weak<Endpoint>),
    /// Na fila de receptores, com o `Reply` onde guardar quem chamar e se a
    /// capability do endpoint tem `GRANT` (que vale para a resposta).
    Recv(Weak<Endpoint>, Arc<Reply>, bool),
    /// Esperando a resposta guardada no `Reply` (`WaitReply`).
    Reply(Weak<Reply>),
}

/// Estado de IPC de uma thread.
#[derive(Debug)]
pub struct IpcSlot {
    /// Mensagem de saída enquanto espera na fila de envio.
    pub out: Option<Outgoing>,
    /// Última mensagem entregue.
    pub inbox: Message,
    /// Badge da última mensagem entregue.
    pub badge: Badge,
    /// Onde está bloqueada.
    pub blocked: Blocked,
    /// Resultado da espera, gravado por quem acorda a thread.
    pub result: Result<(), Error>,
}

impl Default for IpcSlot {
    fn default() -> Self {
        Self {
            out: None,
            inbox: Message::default(),
            badge: 0,
            blocked: Blocked::None,
            result: Ok(()),
        }
    }
}

impl IpcSlot {
    /// A thread está numa fila de envio.
    #[must_use]
    pub const fn sending(&self) -> bool {
        matches!(self.blocked, Blocked::Send(_))
    }

    /// A thread está numa fila de receptores.
    #[must_use]
    pub const fn receiving(&self) -> bool {
        matches!(self.blocked, Blocked::Recv(..))
    }

    /// A thread espera uma resposta.
    #[must_use]
    pub const fn awaiting_reply(&self) -> bool {
        matches!(self.blocked, Blocked::Reply(_))
    }
}

#[derive(Default)]
struct Queues {
    senders: VecDeque<Arc<Thread>>,
    receivers: VecDeque<Arc<Thread>>,
}

/// Ponto de IPC síncrono.
pub struct Endpoint {
    _charge: Charge,
    queues: SpinLock<Queues>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (s, r) = self.queued();
        write!(f, "Endpoint({s} remetentes, {r} receptores)")
    }
}

fn push(queue: &mut VecDeque<Arc<Thread>>, t: &Arc<Thread>) -> Result<(), Error> {
    queue.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
    queue.push_back(Arc::clone(t));
    Ok(())
}

fn remove(queue: &mut VecDeque<Arc<Thread>>, t: &Thread) -> bool {
    let at = queue.iter().position(|q| core::ptr::eq(Arc::as_ptr(q), t));
    at.and_then(|i| queue.remove(i)).is_some()
}

impl Endpoint {
    /// Endpoint sem ninguém, cobrado de `quota`.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota.
    pub fn new(quota: &Arc<MemoryQuota>) -> Result<Self, Error> {
        Ok(Self {
            _charge: quota.charge(object_bytes::<Self>())?,
            queues: SpinLock::new(Queues::default()),
        })
    }

    /// Remetentes e receptores na fila.
    #[must_use]
    pub fn queued(&self) -> (usize, usize) {
        let q = self.queues.lock();
        (q.senders.len(), q.receivers.len())
    }

    /// As duas filas, na ordem (para testes e invariantes).
    #[must_use]
    pub fn snapshot(&self) -> (alloc::vec::Vec<Arc<Thread>>, alloc::vec::Vec<Arc<Thread>>) {
        let q = self.queues.lock();
        (
            q.senders.iter().cloned().collect(),
            q.receivers.iter().cloned().collect(),
        )
    }

    /// Primeiro receptor da fila.
    pub fn pop_receiver(&self) -> Option<Arc<Thread>> {
        self.queues.lock().receivers.pop_front()
    }

    /// Primeiro remetente da fila.
    pub fn pop_sender(&self) -> Option<Arc<Thread>> {
        self.queues.lock().senders.pop_front()
    }

    /// Põe `t` no fim da fila de envio.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem memória para a fila.
    pub fn push_sender(&self, t: &Arc<Thread>) -> Result<(), Error> {
        push(&mut self.queues.lock().senders, t)
    }

    /// Põe `t` no fim da fila de receptores.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem memória para a fila.
    pub fn push_receiver(&self, t: &Arc<Thread>) -> Result<(), Error> {
        push(&mut self.queues.lock().receivers, t)
    }

    /// Tira `t` de qualquer das filas; falso se não estava em nenhuma.
    pub fn remove(&self, t: &Thread) -> bool {
        let mut q = self.queues.lock();
        remove(&mut q.senders, t) || remove(&mut q.receivers, t)
    }
}

/// Quem espera a resposta e se ela pode levar capabilities.
type Caller = (Arc<Thread>, bool);

/// Capability de resposta de uso único.
pub struct Reply {
    _charge: Charge,
    caller: SpinLock<Option<Caller>>,
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reply(pendente: {})", self.pending())
    }
}

impl Reply {
    /// `Reply` vazio, cobrado de `quota`.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota.
    pub fn new(quota: &Arc<MemoryQuota>) -> Result<Self, Error> {
        Ok(Self {
            _charge: quota.charge(object_bytes::<Self>())?,
            caller: SpinLock::new(None),
        })
    }

    /// Há alguém esperando a resposta.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.caller.lock().is_some()
    }

    /// Se a resposta pendente pode transferir capabilities.
    #[must_use]
    pub fn grant(&self) -> Option<bool> {
        self.caller.lock().as_ref().map(|c| c.1)
    }

    /// Verdadeiro se `t` é quem espera.
    #[must_use]
    pub fn holds(&self, t: &Thread) -> bool {
        self.caller
            .lock()
            .as_ref()
            .is_some_and(|c| core::ptr::eq(Arc::as_ptr(&c.0), t))
    }

    /// Guarda `caller`; `grant` diz se a resposta pode levar capabilities.
    ///
    /// # Errors
    ///
    /// [`Error::Busy`] se já há alguém esperando.
    pub fn bind(&self, caller: Arc<Thread>, grant: bool) -> Result<(), Error> {
        let mut c = self.caller.lock();
        if c.is_some() {
            return Err(Error::Busy);
        }
        *c = Some((caller, grant));
        Ok(())
    }

    /// Consome a resposta: devolve quem espera (uma vez só).
    pub fn take(&self) -> Option<Caller> {
        self.caller.lock().take()
    }

    /// Esquece `t`, se for quem espera (prazo vencido).
    pub fn remove(&self, t: &Thread) -> bool {
        let mut c = self.caller.lock();
        let ours = c
            .as_ref()
            .is_some_and(|c| core::ptr::eq(Arc::as_ptr(&c.0), t));
        if ours {
            *c = None;
        }
        ours
    }
}

/// Interrompe a espera de IPC de `t` com `why` (prazo vencido): tira-a da
/// fila ou do `Reply` e solta a mensagem de saída. Falso se `t` não estava
/// bloqueada por IPC (já foi atendida); quem chama a acorda se verdadeiro.
pub fn cancel(t: &Arc<Thread>, why: Error) -> bool {
    let (blocked, out) = {
        let mut slot = t.ipc().lock();
        let blocked = core::mem::take(&mut slot.blocked);
        if matches!(blocked, Blocked::None) {
            return false;
        }
        slot.result = Err(why);
        (blocked, slot.out.take())
    };
    match blocked {
        Blocked::Send(ep) | Blocked::Recv(ep, ..) => {
            if let Some(ep) = ep.upgrade() {
                ep.remove(t);
            }
        }
        Blocked::Reply(reply) => {
            if let Some(reply) = reply.upgrade() {
                reply.remove(t);
            }
        }
        Blocked::None => {}
    }
    // As capabilities da mensagem morrem fora das travas.
    drop(out);
    true
}

#[cfg(test)]
mod tests;
