//! `Notification` e `Interrupt` (T-209; SDD v1.0, seções 6.7 e 6.8).
//!
//! Uma [`Notification`] é uma palavra de 64 bits de sinais pendentes mais
//! uma fila FIFO de threads esperando. `ntfy_signal` faz OR dos bits na
//! palavra; se alguém espera, o primeiro da fila recebe a palavra inteira
//! (que volta a zero) e acorda. `ntfy_wait` devolve e zera a palavra se
//! houver bit pendente, senão bloqueia; `ntfy_poll` nunca bloqueia.
//!
//! Um [`Interrupt`] é uma linha de IRQ (vetor) que, ligada por
//! `obj_bind_notify` a um bit de uma notificação, sinaliza esse bit a cada
//! disparo. Depois de um disparo a linha fica mascarada até `irq_ack`; um
//! disparo com a linha mascarada fica pendente e é entregue no `irq_ack`.
//! Só o kernel cria interrupções (o `root` as recebe entre as capabilities
//! iniciais); `obj_create` as recusa.
//!
//! O objeto só decide quem acorda: marca a thread como
//! [`RunState::Blocked`] ao enfileirá-la (com a trava do objeto na mão,
//! para nenhum sinal se perder entre a decisão e o bloqueio) e devolve a
//! thread a acordar, que o kernel põe na fila de prontas.
//!
//! A fila de espera cresce no heap do kernel sem cobrança de cota: uma
//! thread espera em um objeto por vez, então ela cresce no máximo uma
//! entrada por thread viva, e as threads já são cobradas.

#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::fmt;

use kabi::Error;

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota};
use crate::ipc::Blocked;
use crate::sync::{LockClass, SpinLock};
use crate::thread::{RunState, Thread};

/// Resultado de [`Notification::wait`].
#[derive(Debug, PartialEq, Eq)]
pub enum Wait {
    /// Havia bits pendentes: eles (a palavra volta a zero).
    Ready(u64),
    /// A thread entrou na fila, já bloqueada.
    Blocked,
}

struct State {
    pending: u64,
    waiters: VecDeque<Arc<Thread>>,
}

/// Palavra de 64 bits de sinais assíncronos.
pub struct Notification {
    _charge: Charge,
    state: SpinLock<State>,
}

impl fmt::Debug for Notification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Notification({:#x})", self.pending())
    }
}

impl Notification {
    /// Notificação sem bits, cobrada de `quota`.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota.
    pub fn new(quota: &Arc<MemoryQuota>) -> Result<Self, Error> {
        Ok(Self {
            _charge: quota.charge(object_bytes::<Self>())?,
            state: SpinLock::with_class(
                LockClass::Object,
                State {
                    pending: 0,
                    waiters: VecDeque::new(),
                },
            ),
        })
    }

    /// Bits pendentes, sem consumi-los.
    #[must_use]
    pub fn pending(&self) -> u64 {
        self.state.lock().pending
    }

    /// Threads na fila de espera.
    #[must_use]
    pub fn waiters(&self) -> usize {
        self.state.lock().waiters.len()
    }

    /// `ntfy_signal`: soma `bits` à palavra. Se alguém espera, devolve a
    /// primeira thread da fila e a palavra que ela recebe (a palavra zera).
    pub fn signal(&self, bits: u64) -> Option<(Arc<Thread>, u64)> {
        let mut s = self.state.lock();
        s.pending |= bits;
        if s.pending == 0 {
            return None;
        }
        let thread = s.waiters.pop_front()?;
        // Atendida: a espera sai do slot (a trava do slot vem depois da do
        // objeto), e o encerramento já não a acha aqui.
        thread.ipc().lock().blocked = Blocked::None;
        Some((thread, core::mem::take(&mut s.pending)))
    }

    /// Tira `t` da fila de espera (encerramento, ADR 0035, item 4); falso
    /// se ela não estava (um sinal já a tirou e a acorda).
    pub fn remove(&self, t: &Thread) -> bool {
        let mut s = self.state.lock();
        let at = s
            .waiters
            .iter()
            .position(|w| core::ptr::eq(Arc::as_ptr(w), t));
        let removed = at.and_then(|i| s.waiters.remove(i));
        drop(s);
        // A última referência pode ir aqui: solta sem a trava.
        removed.is_some()
    }

    /// `ntfy_poll`: devolve e zera a palavra, sem bloquear.
    pub fn poll(&self) -> u64 {
        core::mem::take(&mut self.state.lock().pending)
    }

    /// `ntfy_wait`: devolve e zera os bits pendentes ou põe `thread` na
    /// fila, já como [`RunState::Blocked`], com a espera publicada no slot
    /// dela (para o encerramento a achar, ADR 0035, item 4).
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem memória para a fila.
    pub fn wait(self: &Arc<Self>, thread: &Arc<Thread>) -> Result<Wait, Error> {
        let mut s = self.state.lock();
        if s.pending != 0 {
            return Ok(Wait::Ready(core::mem::take(&mut s.pending)));
        }
        s.waiters.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
        let _ = thread.take_wake_error();
        thread.ipc().lock().blocked = Blocked::Notify(Arc::downgrade(self));
        thread.set_state(RunState::Blocked);
        s.waiters.push_back(Arc::clone(thread));
        Ok(Wait::Blocked)
    }
}

impl Drop for Notification {
    /// Ninguém mais pode sinalizar: quem espera acorda com `PeerClosed`
    /// (ADR 0032, item 6), de qualquer CPU, em vez de esperar para sempre.
    fn drop(&mut self) {
        let waiters = core::mem::take(&mut self.state.lock().waiters);
        for t in waiters {
            t.ipc().lock().blocked = Blocked::None;
            t.set_wake_error(Error::PeerClosed);
            t.platform().wake(t);
        }
    }
}

/// O que um disparo de [`Interrupt`] sinaliza.
type Binding = (Arc<Notification>, u64);

#[derive(Default)]
struct Line {
    binding: Option<Binding>,
    masked: bool,
    /// Disparou com a linha mascarada.
    pending: bool,
}

/// Linha de IRQ ligável a um bit de notificação.
pub struct Interrupt {
    _charge: Charge,
    vector: u8,
    line: SpinLock<Line>,
}

impl fmt::Debug for Interrupt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Interrupt(vetor {:#x})", self.vector)
    }
}

impl Interrupt {
    /// Interrupção do vetor `vector`, cobrada de `quota` (só o kernel cria).
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota.
    pub fn new(quota: &Arc<MemoryQuota>, vector: u8) -> Result<Self, Error> {
        Ok(Self {
            _charge: quota.charge(object_bytes::<Self>())?,
            vector,
            line: SpinLock::with_class(LockClass::Object, Line::default()),
        })
    }

    /// Vetor da linha.
    #[must_use]
    pub const fn vector(&self) -> u8 {
        self.vector
    }

    /// `obj_bind_notify`: cada disparo passa a sinalizar o bit `bit` de
    /// `ntfy`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para `bit` ≥ 64; [`Error::Busy`] se a
    /// linha já está ligada.
    pub fn bind(&self, ntfy: Arc<Notification>, bit: u64) -> Result<(), Error> {
        let mask = 1u64.checked_shl(u32::try_from(bit).map_err(|_| Error::InvalidArgument)?);
        let mask = mask.ok_or(Error::InvalidArgument)?;
        let mut line = self.line.lock();
        if line.binding.is_some() {
            return Err(Error::Busy);
        }
        line.binding = Some((ntfy, mask));
        Ok(())
    }

    /// Um disparo do hardware: se a linha está ligada e livre, mascara-a e
    /// devolve o que sinalizar; mascarada, guarda o disparo para o `ack`.
    pub fn fire(&self) -> Option<Binding> {
        let mut line = self.line.lock();
        let binding = line.binding.clone()?;
        if line.masked {
            line.pending = true;
            return None;
        }
        line.masked = true;
        Some(binding)
    }

    /// `irq_ack`: libera a linha; um disparo guardado é entregue já.
    pub fn ack(&self) -> Option<Binding> {
        let mut line = self.line.lock();
        line.masked = false;
        if core::mem::take(&mut line.pending) {
            line.masked = true;
            return line.binding.clone();
        }
        None
    }
}

#[cfg(test)]
mod tests;
