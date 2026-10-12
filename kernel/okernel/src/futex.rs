//! Filas de futex (T-209; SDD v1.0, seções 7.1 e 14.2).
//!
//! `futex_wait(endereço, esperado)` bloqueia a thread se a palavra de 32
//! bits do usuário em `endereço` ainda vale `esperado`; `futex_wake
//! (endereço, n)` acorda até `n` threads esperando no mesmo endereço, em
//! ordem de chegada. A chave é o endereço físico da palavra, então
//! processos que compartilham a página (o mesmo `MemoryObject` mapeado em
//! espaços diferentes) usam a mesma fila.
//!
//! Atomicidade: quem chama lê a palavra do usuário com a trava da tabela na
//! mão ([`FutexTable::wait`] recebe a leitura como função), e `wake` toma a
//! mesma trava. Um `futex_wake` que vem depois de o usuário mudar a palavra
//! ou acha a thread já na fila ou faz a leitura devolver outro valor:
//! nenhum despertar se perde.
//!
//! Como na [`Notification`](crate::notify::Notification), a fila cresce no
//! heap do kernel, no máximo uma entrada por thread viva.

#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use kabi::Error;

use crate::sync::{LockClass, SpinLock};
use crate::thread::{RunState, Thread};

/// Estatísticas da tabela (para os testes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Threads que bloquearam.
    pub blocked: u64,
    /// `futex_wait` recusados porque a palavra já tinha mudado.
    pub stale: u64,
    /// Threads acordadas.
    pub woken: u64,
}

struct Table {
    waiters: VecDeque<(u64, Arc<Thread>)>,
    stats: Stats,
}

/// Tabela de esperas por endereço físico.
pub struct FutexTable {
    inner: SpinLock<Table>,
}

impl Default for FutexTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexTable {
    /// Tabela vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::with_class(
                LockClass::Object,
                Table {
                    waiters: VecDeque::new(),
                    stats: Stats {
                        blocked: 0,
                        stale: 0,
                        woken: 0,
                    },
                },
            ),
        }
    }

    /// `futex_wait`: com a trava da tabela, lê a palavra por `read` e, se
    /// ela vale `expected`, põe `thread` na fila de `key` como
    /// [`RunState::Blocked`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] se a leitura falhar;
    /// [`Error::WouldBlock`] se a palavra já mudou;
    /// [`Error::QuotaExceeded`] sem memória para a fila.
    pub fn wait(
        &self,
        key: u64,
        thread: &Arc<Thread>,
        expected: u32,
        read: impl FnOnce() -> Option<u32>,
    ) -> Result<(), Error> {
        let mut t = self.inner.lock();
        let value = read().ok_or(Error::InvalidArgument)?;
        if value != expected {
            t.stats.stale += 1;
            return Err(Error::WouldBlock);
        }
        t.waiters.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
        thread.set_state(RunState::Blocked);
        t.waiters.push_back((key, Arc::clone(thread)));
        t.stats.blocked += 1;
        Ok(())
    }

    /// `futex_wake`: tira da fila até `max` threads de `key`, na ordem em
    /// que chegaram, e as entrega a `wake` (com a trava na mão: `wake` não
    /// pode voltar à tabela). Devolve quantas acordou.
    pub fn wake(&self, key: u64, max: u64, wake: &mut dyn FnMut(Arc<Thread>)) -> u64 {
        let mut t = self.inner.lock();
        let mut woken = 0;
        let mut i = 0;
        while woken < max && i < t.waiters.len() {
            if t.waiters[i].0 == key
                && let Some((_, thread)) = t.waiters.remove(i)
            {
                wake(thread);
                woken += 1;
            } else {
                i += 1;
            }
        }
        t.stats.woken += woken;
        woken
    }

    /// Threads esperando em `key`.
    #[must_use]
    pub fn waiting(&self, key: u64) -> usize {
        self.inner
            .lock()
            .waiters
            .iter()
            .filter(|(k, _)| *k == key)
            .count()
    }

    /// Estatísticas acumuladas.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.inner.lock().stats
    }
}

/// A tabela do kernel.
pub static FUTEXES: FutexTable = FutexTable::new();

#[cfg(test)]
mod tests;
