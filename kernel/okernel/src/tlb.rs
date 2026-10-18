//! TLB shootdown entre CPUs (ADR 0031, item 7; T-326): o pedido de cada
//! CPU e a caixa de entrada de cada uma.
//!
//! Quem muda um espaço (CPU `I`) já trocou as entradas e invalidou a
//! própria TLB; então preenche o próprio [`Request`] (raiz, o que
//! invalidar e quantos alvos), liga o bit `I` na [`Inbox`] de cada alvo,
//! liga `TLB` na caixa de pedidos dele e manda o IPI. Cada alvo, ao
//! atender, troca a caixa de entrada por zero, lê o pedido de cada CPU que
//! achou, invalida se ele vale para o `CR3` que tem ([`applies`]) e
//! confirma ([`Request::ack`]). `I` espera todas as confirmações (atendendo
//! a própria caixa) e só então libera o que saiu do mapeamento.
//!
//! Um pedido por CPU que pede, uma rodada por vez: a CPU só preenche o
//! pedido de novo depois de todas as confirmações da rodada anterior.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Raiz dos pedidos do kernel (metade alta): valem em qualquer `CR3`.
pub const KERNEL_ROOT: u64 = 0;
/// Acima de tantas páginas, invalidar página a página custa mais que
/// esvaziar a TLB inteira.
pub const MAX_PAGES: u64 = 32;
/// CPUs que cabem na caixa de entrada (`kabi::MAX_CPUS`).
const CPUS: usize = 256;
/// `pages` de um pedido que esvazia tudo.
const ALL: u64 = u64::MAX;

/// O que invalidar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flush {
    /// `pages` páginas de 4 KiB a partir de `start`.
    Pages {
        /// Primeira página.
        start: u64,
        /// Quantas.
        pages: u64,
    },
    /// A TLB inteira.
    All,
}

impl Flush {
    /// `pages` páginas a partir de `start`, ou [`Flush::All`] se forem mais
    /// que [`MAX_PAGES`].
    #[must_use]
    pub const fn range(start: u64, pages: u64) -> Self {
        if pages > MAX_PAGES {
            Self::All
        } else {
            Self::Pages { start, pages }
        }
    }
}

/// O pedido em vigor desde que `root` tem o `CR3` `current` (raiz do
/// pedido do kernel vale sempre).
#[must_use]
pub const fn applies(root: u64, current: u64) -> bool {
    root == KERNEL_ROOT || root == current
}

/// O pedido de shootdown de uma CPU.
pub struct Request {
    root: AtomicU64,
    start: AtomicU64,
    /// Páginas, ou `ALL`.
    pages: AtomicU64,
    /// Alvos que ainda não confirmaram.
    acks: AtomicU32,
}

impl Default for Request {
    fn default() -> Self {
        Self::new()
    }
}

impl Request {
    /// Pedido vazio (sem rodada em curso).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root: AtomicU64::new(0),
            start: AtomicU64::new(0),
            pages: AtomicU64::new(0),
            acks: AtomicU32::new(0),
        }
    }

    /// Preenche o pedido para `targets` alvos (pela CPU dona, sem rodada em
    /// curso); quem chama avisa os alvos depois ([`Inbox::signal`]).
    pub fn post(&self, root: u64, flush: Flush, targets: u32) {
        debug_assert!(self.done(), "rodada de shootdown anterior em curso");
        let (start, pages) = match flush {
            Flush::Pages { start, pages } => (start, pages),
            Flush::All => (0, ALL),
        };
        self.root.store(root, Ordering::Relaxed);
        self.start.store(start, Ordering::Relaxed);
        self.pages.store(pages, Ordering::Relaxed);
        self.acks.store(targets, Ordering::Release);
    }

    /// Raiz e o que invalidar (pelo alvo, depois de achar o bit da dona
    /// na caixa de entrada).
    #[must_use]
    pub fn read(&self) -> (u64, Flush) {
        let root = self.root.load(Ordering::Relaxed);
        let start = self.start.load(Ordering::Relaxed);
        let flush = match self.pages.load(Ordering::Relaxed) {
            ALL => Flush::All,
            pages => Flush::Pages { start, pages },
        };
        (root, flush)
    }

    /// Confirma (pelo alvo, depois de invalidar).
    pub fn ack(&self) {
        self.acks.fetch_sub(1, Ordering::Release);
    }

    /// Todos os alvos confirmaram.
    #[must_use]
    pub fn done(&self) -> bool {
        self.acks.load(Ordering::Acquire) == 0
    }

    /// Alvos que faltam confirmar.
    #[must_use]
    pub fn pending(&self) -> u32 {
        self.acks.load(Ordering::Acquire)
    }
}

/// Caixa de entrada de shootdown de uma CPU: um bit por CPU que pede.
pub struct Inbox {
    bits: [AtomicU64; CPUS / 64],
}

impl Default for Inbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Inbox {
    /// Caixa vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bits: [const { AtomicU64::new(0) }; CPUS / 64],
        }
    }

    /// A CPU `from` tem um pedido para esta (depois de [`Request::post`]).
    pub fn signal(&self, from: usize) {
        if let Some(word) = self.bits.get(from / 64) {
            word.fetch_or(1 << (from % 64), Ordering::Release);
        }
    }

    /// O pedido de `from` ainda está na caixa, sem atender (para o
    /// diagnóstico de um shootdown que não fechou).
    #[must_use]
    pub fn signaled(&self, from: usize) -> bool {
        self.bits
            .get(from / 64)
            .is_some_and(|w| w.load(Ordering::Acquire) & (1 << (from % 64)) != 0)
    }

    /// Esvazia a caixa e chama `serve` com cada CPU que tinha pedido.
    pub fn drain(&self, serve: &mut dyn FnMut(usize)) {
        for (i, word) in self.bits.iter().enumerate() {
            if word.load(Ordering::Relaxed) == 0 {
                continue;
            }
            let mut bits = word.swap(0, Ordering::Acquire);
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                serve(i * 64 + bit);
            }
        }
    }
}

#[cfg(test)]
mod tests;
