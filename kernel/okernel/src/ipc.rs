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
//! Quando a última capability de um `Endpoint` ou `Reply` some, o objeto
//! morre e quem esperava nele acorda com `PeerClosed` (pela
//! [`Platform`](crate::platform::Platform) da thread), em vez de esperar
//! para sempre.
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
use kabi::{Badge, Error, Handle, MSG_MAX_CAPS, MSG_REG_WORDS};

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota, SharedCapSpace};
use crate::sched::SchedContext;
use crate::sync::{LockClass, SpinLock};
use crate::thread::Thread;

pub mod fast;
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

/// O que um remetente leva: a mensagem, os handles das capabilities a
/// transferir (conferidos no envio e copiados na entrega, como filhas das
/// originais) e o badge da capability do endpoint.
#[derive(Debug, Default)]
pub struct Outgoing {
    /// Registradores da mensagem.
    pub msg: Message,
    /// `CapSpace` do remetente, se a mensagem leva capabilities.
    pub from: Option<Weak<SharedCapSpace>>,
    /// Handles, em `from`, das capabilities a transferir.
    pub caps: [Option<Handle>; MSG_MAX_CAPS],
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

/// Como [`push`], com `mark` logo antes de entrar (e só se couber).
fn push_marked(
    queue: &mut VecDeque<Arc<Thread>>,
    t: &Arc<Thread>,
    mark: impl FnOnce(),
) -> Result<(), Error> {
    queue.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
    mark();
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
            queues: SpinLock::with_class(LockClass::Object, Queues::default()),
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

    /// `Deliver` da spec `Ipc.tla`, num passo só sob a trava das filas:
    /// tira o primeiro receptor ou, se não houver (e `queue`), põe `t` no
    /// fim da fila de envio. Dois passos separados deixariam, com duas
    /// CPUs, um remetente e um receptor ambos na fila, esperando um pelo
    /// outro (`NoMissedRendezvous`).
    ///
    /// `mark` roda, com a trava das filas na mão, logo antes de `t` entrar
    /// na fila: marca `t` como bloqueada (a trava do slot de IPC vem depois
    /// da do objeto), já que outra CPU pode tirá-la de lá assim que a trava
    /// for solta. Quem acha par não é marcado (T-331).
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem memória para a fila; `mark` não roda.
    pub fn pop_receiver_or_push_sender(
        &self,
        t: &Arc<Thread>,
        queue: bool,
        mark: impl FnOnce(),
    ) -> Result<Option<Arc<Thread>>, Error> {
        let mut q = self.queues.lock();
        if let Some(r) = q.receivers.pop_front() {
            return Ok(Some(r));
        }
        if queue {
            push_marked(&mut q.senders, t, mark)?;
        }
        Ok(None)
    }

    /// `RecvPart` da spec `Ipc.tla`, num passo só: tira o primeiro
    /// remetente ou, se não houver (e `queue`), põe `t` no fim da fila de
    /// receptores, marcada por `mark`. Ver
    /// [`Endpoint::pop_receiver_or_push_sender`].
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem memória para a fila; `mark` não roda.
    pub fn pop_sender_or_push_receiver(
        &self,
        t: &Arc<Thread>,
        queue: bool,
        mark: impl FnOnce(),
    ) -> Result<Option<Arc<Thread>>, Error> {
        let mut q = self.queues.lock();
        if let Some(s) = q.senders.pop_front() {
            return Ok(Some(s));
        }
        if queue {
            push_marked(&mut q.receivers, t, mark)?;
        }
        Ok(None)
    }

    /// Há remetente na fila (o caminho rápido de `ipc_reply_recv` só vale
    /// sem ninguém para receber).
    #[must_use]
    pub fn has_senders(&self) -> bool {
        !self.queues.lock().senders.is_empty()
    }

    /// Caminho rápido de `ipc_call` (`Deliver` da spec): com a trava das
    /// filas na mão, passa o primeiro receptor a `take`, que confere se ele
    /// serve e o atende (com a trava do slot dele, que vem depois); só então
    /// ele sai da fila. Nada muda se a fila está vazia ou `take` recusa.
    pub fn take_receiver<T>(
        &self,
        take: impl FnOnce(&Arc<Thread>) -> Option<T>,
    ) -> Option<(Arc<Thread>, T)> {
        let mut q = self.queues.lock();
        let got = take(q.receivers.front()?)?;
        let r = q.receivers.pop_front()?;
        Some((r, got))
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
    /// Quem atende a chamada e o `SchedContext` que recebeu de quem
    /// chamou (seção 6.6), devolvido quando a espera acaba. Trava tomada
    /// depois de `caller`, nunca junto.
    donation: SpinLock<Option<(Weak<Thread>, Arc<SchedContext>)>>,
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
            caller: SpinLock::with_class(LockClass::Object, None),
            donation: SpinLock::with_class(LockClass::Object, None),
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

    /// Quem espera está na CPU `cpu`, fora dela (a pilha livre), para a
    /// troca direta do caminho rápido.
    #[must_use]
    pub fn caller_on(&self, cpu: u32) -> bool {
        self.caller
            .lock()
            .as_ref()
            .is_some_and(|c| c.0.cpu() == cpu && !c.0.on_cpu())
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
        let caller = self.caller.lock().take();
        self.end_donation();
        caller
    }

    /// Doação (seção 6.6): `server` atende a chamada pendente com o
    /// `SchedContext` de quem chamou, até a resposta (ou até a espera
    /// acabar de outro jeito).
    pub fn donate(&self, server: &Arc<Thread>) {
        let Some(sc) = self
            .caller
            .lock()
            .as_ref()
            .and_then(|c| c.0.sched_context())
        else {
            return;
        };
        server.donate(Arc::clone(&sc));
        *self.donation.lock() = Some((Arc::downgrade(server), sc));
    }

    /// Devolve a doação, se houver.
    fn end_donation(&self) {
        let donation = self.donation.lock().take();
        if let Some((server, sc)) = donation
            && let Some(server) = server.upgrade()
        {
            server.undonate(&sc);
        }
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
        drop(c);
        if ours {
            self.end_donation();
        }
        ours
    }
}

/// Acorda com `PeerClosed` a thread `t`, que esperava em `object` (um
/// `Endpoint` ou `Reply` sendo destruído); nada se ela já não esperava
/// ali.
fn close(t: Arc<Thread>, object: *const ()) {
    let (blocked, out) = {
        let mut slot = t.ipc().lock();
        let here = match &slot.blocked {
            Blocked::Send(ep) | Blocked::Recv(ep, ..) => ep.as_ptr().cast::<()>() == object,
            Blocked::Reply(reply) => reply.as_ptr().cast::<()>() == object,
            Blocked::None => false,
        };
        if !here {
            return;
        }
        slot.result = Err(Error::PeerClosed);
        (core::mem::take(&mut slot.blocked), slot.out.take())
    };
    // O `Reply` de quem esperava receber morre fora da trava.
    drop((blocked, out));
    t.platform().wake(t);
}

impl Drop for Endpoint {
    /// Ninguém mais pode enviar nem receber: quem espera nas filas acorda
    /// com `PeerClosed`.
    fn drop(&mut self) {
        let Queues { senders, receivers } = core::mem::take(&mut *self.queues.lock());
        let me = core::ptr::from_ref(self).cast();
        for t in senders.into_iter().chain(receivers) {
            close(t, me);
        }
    }
}

impl Drop for Reply {
    /// A resposta nunca virá: quem espera acorda com `PeerClosed`.
    fn drop(&mut self) {
        let caller = self.caller.lock().take();
        self.end_donation();
        if let Some((t, _)) = caller {
            close(t, core::ptr::from_ref(self).cast());
        }
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
    // O que a mensagem segura morre fora das travas.
    drop(out);
    true
}

#[cfg(test)]
mod tests;
