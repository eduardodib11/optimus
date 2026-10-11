//! Escalonador de prioridade fixa com `SchedContext` (T-207; SDD v1.0,
//! seção 6.6; ADR 0008 e 0009).
//!
//! Lógica portável: a fila de prontas de 256 níveis (bitmap + uma fila por
//! nível, round-robin dentro do nível), os parâmetros e o orçamento de um
//! `SchedContext` e o objeto em si.
//!
//! Orçamento: cada `SchedContext` dá `budget` ns de CPU a cada `period` ns.
//! A primeira janela começa quando a thread roda pela primeira vez; ao
//! esgotar o orçamento, a thread espera o fim da janela, quando o orçamento
//! volta inteiro (servidor periódico: o que sobra numa janela não passa
//! para a próxima). Com `budget >= period` não há limite. O kernel mede o
//! consumo pelo relógio monotônico, não por ticks (ADR 0009).

#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kabi::Error;

use crate::cap::Charge;

/// Níveis de prioridade (0 = ocioso, 255 = mais alta).
pub const PRIORITIES: usize = 256;
/// Fatia de tempo dentro do mesmo nível (round-robin).
pub const DEFAULT_SLICE_NS: u64 = 5_000_000;
/// Menor período aceito: evita um timer disparando sem parar.
pub const MIN_PERIOD_NS: u64 = 100_000;
/// Menor orçamento aceito.
pub const MIN_BUDGET_NS: u64 = 10_000;

/// Parâmetros de um `SchedContext` (`sched_configure`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Orçamento por período, em ns.
    pub budget_ns: u64,
    /// Período, em ns.
    pub period_ns: u64,
    /// Prioridade.
    pub priority: u8,
}

impl Params {
    /// Valida os parâmetros crus de `sched_configure`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para prioridade acima de 255, período
    /// menor que [`MIN_PERIOD_NS`] ou orçamento menor que [`MIN_BUDGET_NS`]
    /// ou maior que o período.
    pub fn new(budget_ns: u64, period_ns: u64, priority: u64) -> Result<Self, Error> {
        let priority = u8::try_from(priority).map_err(|_| Error::InvalidArgument)?;
        if period_ns < MIN_PERIOD_NS || budget_ns < MIN_BUDGET_NS || budget_ns > period_ns {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            budget_ns,
            period_ns,
            priority,
        })
    }

    /// Orçamento do período inteiro: sem limite.
    #[must_use]
    pub const fn unlimited(&self) -> bool {
        self.budget_ns >= self.period_ns
    }
}

/// Estado do orçamento de um `SchedContext`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Budget {
    /// Ns que restam na janela atual.
    pub remaining: u64,
    /// Fim da janela atual: quando o orçamento volta.
    pub replenish_at: u64,
    /// A primeira janela já começou.
    pub active: bool,
}

impl Budget {
    /// Começa a primeira janela em `now`, se ainda não começou.
    pub fn activate(&mut self, p: &Params, now: u64) {
        if !self.active {
            *self = Self {
                remaining: p.budget_ns,
                replenish_at: now.saturating_add(p.period_ns),
                active: true,
            };
        }
    }

    /// Reabastece se a janela acabou, alinhando ao próximo limite de
    /// período. Devolve se reabasteceu.
    pub fn refill(&mut self, p: &Params, now: u64) -> bool {
        if !self.active || now < self.replenish_at {
            return false;
        }
        let periods = (now - self.replenish_at) / p.period_ns + 1;
        self.replenish_at = self
            .replenish_at
            .saturating_add(periods.saturating_mul(p.period_ns));
        self.remaining = p.budget_ns;
        true
    }

    /// Desconta `ns` de CPU usados.
    pub fn consume(&mut self, p: &Params, ns: u64) {
        if !p.unlimited() {
            self.remaining = self.remaining.saturating_sub(ns);
        }
    }

    /// O orçamento da janela acabou.
    #[must_use]
    pub fn exhausted(&self, p: &Params) -> bool {
        self.active && !p.unlimited() && self.remaining == 0
    }

    /// Até quando a thread pode rodar a partir de `now` sem passar do
    /// orçamento (`None`: sem limite).
    #[must_use]
    pub fn deadline(&self, p: &Params, now: u64) -> Option<u64> {
        (!p.unlimited()).then(|| now.saturating_add(self.remaining))
    }
}

/// Orçamento de CPU e prioridade de uma thread (objeto `SchedContext`).
///
/// Os campos são atômicos para o escalonador lê-los sem tomar trava de
/// objeto com a da fila na mão (ordem da seção 6.9); só ele muda o
/// orçamento, e com a trava da fila.
pub struct SchedContext {
    charge: Charge,
    budget_ns: AtomicU64,
    period_ns: AtomicU64,
    /// Prioridade + 1; zero = não configurado.
    priority: AtomicU64,
    remaining: AtomicU64,
    replenish_at: AtomicU64,
    active: AtomicBool,
    bound: AtomicBool,
}

impl fmt::Debug for SchedContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SchedContext({:?}, {:?})", self.params(), self.budget())
    }
}

impl SchedContext {
    /// `SchedContext` sem configuração (não deixa rodar), pago por `charge`.
    #[must_use]
    pub const fn new(charge: Charge) -> Self {
        Self {
            charge,
            budget_ns: AtomicU64::new(0),
            period_ns: AtomicU64::new(0),
            priority: AtomicU64::new(0),
            remaining: AtomicU64::new(0),
            replenish_at: AtomicU64::new(0),
            active: AtomicBool::new(false),
            bound: AtomicBool::new(false),
        }
    }

    /// Bytes cobrados da cota.
    #[must_use]
    pub const fn charged(&self) -> u64 {
        self.charge.bytes()
    }

    /// `sched_configure`: novos parâmetros; a janela recomeça na próxima
    /// vez que a thread rodar.
    pub fn configure(&self, p: Params) {
        self.budget_ns.store(p.budget_ns, Ordering::Relaxed);
        self.period_ns.store(p.period_ns, Ordering::Relaxed);
        self.set_budget(Budget::default());
        self.priority
            .store(u64::from(p.priority) + 1, Ordering::Release);
    }

    /// Parâmetros, se configurado.
    #[must_use]
    pub fn params(&self) -> Option<Params> {
        let priority = self.priority.load(Ordering::Acquire).checked_sub(1)?;
        Some(Params {
            budget_ns: self.budget_ns.load(Ordering::Relaxed),
            period_ns: self.period_ns.load(Ordering::Relaxed),
            priority: u8::try_from(priority).ok()?,
        })
    }

    /// Estado do orçamento.
    #[must_use]
    pub fn budget(&self) -> Budget {
        Budget {
            remaining: self.remaining.load(Ordering::Relaxed),
            replenish_at: self.replenish_at.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
        }
    }

    /// Grava o estado do orçamento (pelo escalonador).
    pub fn set_budget(&self, b: Budget) {
        self.remaining.store(b.remaining, Ordering::Relaxed);
        self.replenish_at.store(b.replenish_at, Ordering::Relaxed);
        self.active.store(b.active, Ordering::Relaxed);
    }

    /// Marca como ligado a uma thread; `false` se já estava.
    pub fn try_bind(&self) -> bool {
        self.bound
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// Fila de prontas: um bitmap de 256 bits diz quais níveis têm alguém, e
/// cada nível é uma fila FIFO (round-robin).
pub struct RunQueue<T> {
    bitmap: [u64; PRIORITIES / 64],
    levels: [VecDeque<T>; PRIORITIES],
}

impl<T> Default for RunQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> RunQueue<T> {
    /// Fila vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bitmap: [0; PRIORITIES / 64],
            levels: [const { VecDeque::new() }; PRIORITIES],
        }
    }

    /// Põe `item` no fim do nível `priority`.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem memória para a fila; nada muda.
    pub fn push(&mut self, priority: u8, item: T) -> Result<(), Error> {
        let level = &mut self.levels[usize::from(priority)];
        level.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
        level.push_back(item);
        self.bitmap[usize::from(priority / 64)] |= 1 << (priority % 64);
        Ok(())
    }

    /// Maior prioridade com alguém pronto.
    #[must_use]
    pub fn highest(&self) -> Option<u8> {
        let (word, bits) = self
            .bitmap
            .iter()
            .enumerate()
            .rev()
            .find(|(_, bits)| **bits != 0)?;
        u8::try_from(word * 64 + 63 - bits.leading_zeros() as usize).ok()
    }

    /// Tira o primeiro do nível mais alto.
    pub fn pop(&mut self) -> Option<(u8, T)> {
        let priority = self.highest()?;
        let level = &mut self.levels[usize::from(priority)];
        let item = level.pop_front()?;
        if level.is_empty() {
            self.bitmap[usize::from(priority / 64)] &= !(1 << (priority % 64));
        }
        Some((priority, item))
    }

    /// Itens na fila.
    #[must_use]
    pub fn len(&self) -> usize {
        self.levels.iter().map(VecDeque::len).sum()
    }

    /// Fila vazia.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bitmap.iter().all(|w| *w == 0)
    }
}

#[cfg(test)]
mod tests;
