//! Caches por CPU na frente do buddy e do heap (T-328; ADR 0031, item 3):
//! pilhas ([`Magazine`]) que só a própria CPU usa, sem trava.
//!
//! Alocar tira da pilha; vazia, a CPU toma a trava do alocador de trás uma
//! vez e traz um lote. Liberar põe na pilha; cheia, devolve um lote numa
//! tomada só. Assim cada CPU passa pela trava no máximo uma vez a cada
//! lote, e a pilha fica com entre zero e a capacidade.
//!
//! - **Frames** ([`FrameCache`]): só os de 4 KiB; até [`FRAME_CAPACITY`]
//!   por CPU fora do buddy (256 KiB), em lotes de [`FRAME_BATCH`].
//! - **Objetos do heap** ([`ObjectCache`]): uma pilha por classe do slab
//!   (`slab::CLASSES`), até [`OBJECT_CAPACITY`] objetos cada, em lotes de
//!   [`OBJECT_BATCH`]. Um objeto parado na pilha conta como alocado para o
//!   slab e segura o slab dele; a capacidade pequena limita isso.

#![forbid(unsafe_code)]

use super::slab::CLASSES;

/// Frames de 4 KiB que cabem no cache de uma CPU.
pub const FRAME_CAPACITY: usize = 64;
/// Frames trazidos do buddy ou devolvidos a ele de uma vez.
pub const FRAME_BATCH: usize = 32;
/// Objetos de uma classe que cabem no cache de uma CPU.
pub const OBJECT_CAPACITY: usize = 8;
/// Objetos trazidos do slab ou devolvidos a ele de uma vez.
pub const OBJECT_BATCH: usize = 4;

const _: () = assert!(FRAME_BATCH > 0 && FRAME_BATCH <= FRAME_CAPACITY);
const _: () = assert!(OBJECT_BATCH > 0 && OBJECT_BATCH <= OBJECT_CAPACITY);

/// Cache de frames de uma CPU (endereços físicos).
pub type FrameCache = Magazine<FRAME_CAPACITY>;
/// Cache de objetos do heap de uma CPU, uma pilha por classe do slab
/// (endereços no mapa direto).
pub type ObjectCache = [Magazine<OBJECT_CAPACITY>; CLASSES.len()];

/// Cache de objetos vazio.
#[must_use]
pub const fn object_cache() -> ObjectCache {
    [const { Magazine::new() }; CLASSES.len()]
}

/// Uma pilha de até `CAP` endereços.
#[derive(Debug)]
pub struct Magazine<const CAP: usize> {
    items: [u64; CAP],
    len: usize,
}

impl<const CAP: usize> Default for Magazine<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> Magazine<CAP> {
    /// Pilha vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: [0; CAP],
            len: 0,
        }
    }

    /// Endereços na pilha.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// A pilha está vazia.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// O endereço do topo, se houver.
    pub fn pop(&mut self) -> Option<u64> {
        self.len = self.len.checked_sub(1)?;
        Some(self.items[self.len])
    }

    /// Põe `item` na pilha; `false` se ela está cheia (quem chama esvazia
    /// com [`spill`](Self::spill) e tenta de novo).
    pub fn push(&mut self, item: u64) -> bool {
        let Some(slot) = self.items.get_mut(self.len) else {
            return false;
        };
        *slot = item;
        self.len += 1;
        true
    }

    /// `item` já está na pilha (liberação dupla nesta CPU).
    #[must_use]
    pub fn contains(&self, item: u64) -> bool {
        self.items[..self.len].contains(&item)
    }

    /// Enche a pilha com até `batch` endereços de `alloc` (com a trava de
    /// trás na mão), parando no primeiro `None`; devolve quantos vieram.
    pub fn refill(&mut self, batch: usize, alloc: &mut dyn FnMut() -> Option<u64>) -> usize {
        let mut got = 0;
        while got < batch && self.len < CAP {
            let Some(item) = alloc() else {
                break;
            };
            self.items[self.len] = item;
            self.len += 1;
            got += 1;
        }
        got
    }

    /// Devolve a `free` até `count` endereços do topo (com a trava de trás
    /// na mão); devolve quantos saíram.
    pub fn spill(&mut self, count: usize, free: &mut dyn FnMut(u64)) -> usize {
        let n = count.min(self.len);
        for _ in 0..n {
            self.len -= 1;
            free(self.items[self.len]);
        }
        n
    }
}

#[cfg(test)]
mod tests;
