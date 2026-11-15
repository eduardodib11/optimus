//! `obcache` (T-521; ADR 0056, item 7): o cache de blocos do `optfs`, em
//! texto claro, acima da cifra. Nunca guarda mais blocos que a cota dele
//! (`capacity`), despeja o menos recente quando enche e devolve memória sob
//! pressão ([`BlockCache::trim`]), que é o que o `memd` pede ao `optfs`.
//!
//! Sem `unsafe`: um mapa endereço → bloco e um índice por "carimbo de uso"
//! dão o LRU em `O(log n)`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;

/// Bytes de um bloco.
pub const BLOCK_SIZE: usize = 4096;

struct Entry {
    data: Box<[u8; BLOCK_SIZE]>,
    stamp: u64,
}

/// Contadores do cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Leituras atendidas pelo cache.
    pub hits: u64,
    /// Leituras que não estavam no cache.
    pub misses: u64,
    /// Blocos despejados (por falta de espaço ou por [`BlockCache::trim`]).
    pub evictions: u64,
}

/// Cache LRU de blocos limitado a `capacity` blocos.
pub struct BlockCache {
    map: BTreeMap<u64, Entry>,
    /// Carimbo de uso → endereço; o menor carimbo é o menos recente.
    order: BTreeMap<u64, u64>,
    capacity: usize,
    clock: u64,
    stats: Stats,
}

impl BlockCache {
    /// Cache que cabe em `quota_bytes` de memória (blocos inteiros).
    #[must_use]
    pub fn with_quota(quota_bytes: usize) -> Self {
        Self::with_capacity(quota_bytes / BLOCK_SIZE)
    }

    /// Cache de até `capacity` blocos; com zero não guarda nada.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            order: BTreeMap::new(),
            capacity,
            clock: 0,
            stats: Stats::default(),
        }
    }

    /// Blocos no cache agora.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Se o cache está vazio.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Limite de blocos.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Bytes de dados em uso.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.map.len() * BLOCK_SIZE
    }

    /// Contadores.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// O bloco `addr`, se estiver no cache; conta como uso recente.
    pub fn get(&mut self, addr: u64) -> Option<&[u8; BLOCK_SIZE]> {
        let stamp = self.tick();
        let Some(e) = self.map.get_mut(&addr) else {
            self.stats.misses += 1;
            return None;
        };
        self.order.remove(&e.stamp);
        e.stamp = stamp;
        self.order.insert(stamp, addr);
        self.stats.hits += 1;
        Some(&*e.data)
    }

    /// Guarda (ou troca) o bloco `addr`, despejando o menos recente se o
    /// cache está cheio.
    pub fn insert(&mut self, addr: u64, data: &[u8; BLOCK_SIZE]) {
        if self.capacity == 0 {
            return;
        }
        let stamp = self.tick();
        if let Some(e) = self.map.get_mut(&addr) {
            *e.data = *data;
            self.order.remove(&e.stamp);
            e.stamp = stamp;
            self.order.insert(stamp, addr);
            return;
        }
        while self.map.len() >= self.capacity {
            if !self.evict_one() {
                break;
            }
        }
        self.map.insert(
            addr,
            Entry {
                data: Box::new(*data),
                stamp,
            },
        );
        self.order.insert(stamp, addr);
    }

    /// Tira `addr` do cache (o bloco foi liberado ou mudou por fora).
    pub fn invalidate(&mut self, addr: u64) {
        if let Some(e) = self.map.remove(&addr) {
            self.order.remove(&e.stamp);
        }
    }

    fn evict_one(&mut self) -> bool {
        let Some((_, addr)) = self.order.pop_first() else {
            return false;
        };
        self.map.remove(&addr);
        self.stats.evictions += 1;
        true
    }

    /// Pressão de memória: despeja os menos recentes até sobrarem no máximo
    /// `keep` blocos e baixa o limite para `keep` (o `memd` devolve a cota).
    /// Devolve quantos blocos saíram.
    pub fn trim(&mut self, keep: usize) -> usize {
        let before = self.map.len();
        self.capacity = self.capacity.min(keep);
        while self.map.len() > keep {
            if !self.evict_one() {
                break;
            }
        }
        before - self.map.len()
    }

    /// Sobe o limite (a cota voltou a crescer), sem passar de `max`.
    pub fn grow(&mut self, capacity: usize, max: usize) {
        self.capacity = capacity.min(max);
    }
}

#[cfg(test)]
mod tests;
