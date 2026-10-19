//! Filas de futex (T-209; SDD v1.0, seções 7.1 e 14.2).
//!
//! `futex_wait(endereço, esperado)` bloqueia a thread se a palavra de 32
//! bits do usuário em `endereço` ainda vale `esperado`; `futex_wake
//! (endereço, n)` acorda até `n` threads esperando no mesmo endereço, em
//! ordem de chegada. A chave é o endereço físico da palavra, então
//! processos que compartilham a página (o mesmo `MemoryObject` mapeado em
//! espaços diferentes) usam a mesma fila.
//!
//! A tabela tem [`BUCKETS`] baldes, cada um com a sua trava, escolhidos por
//! hash da chave (ADR 0032, item 6): CPUs que esperam em palavras
//! diferentes quase nunca disputam a mesma trava.
//!
//! Atomicidade: quem chama lê a palavra do usuário com a trava do balde na
//! mão ([`FutexTable::wait`] recebe a leitura como função), e `wake` toma a
//! mesma trava (a mesma chave cai no mesmo balde). Um `futex_wake` que vem
//! depois de o usuário mudar a palavra, de qualquer CPU, ou acha a thread
//! já na fila ou faz a leitura devolver outro valor: nenhum despertar se
//! perde. Nada segura dois baldes ao mesmo tempo.
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

/// Baldes da tabela.
pub const BUCKETS: usize = 64;

/// Tabela de esperas por endereço físico.
pub struct FutexTable {
    buckets: [SpinLock<Table>; BUCKETS],
}

/// O balde de `key`: o endereço é múltiplo de 4, então os dois bits de
/// baixo ficam de fora antes da mistura (Fibonacci).
fn bucket_of(key: u64) -> usize {
    #[allow(clippy::cast_possible_truncation, reason = "seis bits")]
    let i = ((key >> 2).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 58) as usize;
    i
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
            buckets: [const {
                SpinLock::with_class(
                    LockClass::Object,
                    Table {
                        waiters: VecDeque::new(),
                        stats: Stats {
                            blocked: 0,
                            stale: 0,
                            woken: 0,
                        },
                    },
                )
            }; BUCKETS],
        }
    }

    fn bucket(&self, key: u64) -> &SpinLock<Table> {
        &self.buckets[bucket_of(key)]
    }

    /// `futex_wait`: com a trava do balde de `key`, lê a palavra por `read` e, se
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
        let mut t = self.bucket(key).lock();
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
        let mut t = self.bucket(key).lock();
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
        self.bucket(key)
            .lock()
            .waiters
            .iter()
            .filter(|(k, _)| *k == key)
            .count()
    }

    /// Estatísticas acumuladas, somadas de todos os baldes (um de cada
    /// vez: a soma pode juntar momentos diferentes de cada balde).
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.buckets.iter().fold(Stats::default(), |acc, b| {
            let s = b.lock().stats;
            Stats {
                blocked: acc.blocked + s.blocked,
                stale: acc.stale + s.stale,
                woken: acc.woken + s.woken,
            }
        })
    }
}

/// A tabela do kernel.
pub static FUTEXES: FutexTable = FutexTable::new();

#[cfg(test)]
mod tests;
