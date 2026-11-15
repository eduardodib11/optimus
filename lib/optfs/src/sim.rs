#![allow(clippy::cast_possible_truncation)]

//! Disco de teste: escrita fica em cache até o `flush`; a queda a perde.

use crate::{BlockIo, IoError};
use optfs_format::BLOCK_SIZE;
use std::collections::BTreeMap;

pub struct Sim {
    pub durable: Vec<[u8; BLOCK_SIZE]>,
    cache: BTreeMap<u64, [u8; BLOCK_SIZE]>,
    /// Pedidos (escrita ou flush) restantes; no zero o disco "cai".
    pub budget: Option<usize>,
    pub log: Vec<&'static str>,
}

impl Sim {
    pub fn new(blocks: usize) -> Self {
        Self {
            durable: vec![[0; BLOCK_SIZE]; blocks],
            cache: BTreeMap::new(),
            budget: None,
            log: Vec::new(),
        }
    }
    fn tick(&mut self) -> Result<(), IoError> {
        match &mut self.budget {
            Some(0) => Err(IoError::Io),
            Some(n) => {
                *n -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    }
    /// Queda de energia em que parte das escritas ainda no cache chegou ao
    /// disco, em ordem qualquer (cada uma com 50% de chance, pelo `rng`).
    pub fn crash_partial(&mut self, rng: &mut u64) {
        for (b, d) in std::mem::take(&mut self.cache) {
            *rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            if *rng >> 33 & 1 == 1 {
                self.durable[b as usize] = d;
            }
        }
        self.budget = None;
    }

    /// Queda de energia: o cache some.
    pub fn crash(&mut self) {
        self.cache.clear();
        self.budget = None;
    }
}

impl BlockIo for Sim {
    fn blocks(&self) -> u64 {
        self.durable.len() as u64
    }
    fn read(&mut self, b: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), IoError> {
        let b = usize::try_from(b).map_err(|_| IoError::Io)?;
        *buf = *self
            .cache
            .get(&(b as u64))
            .or(self.durable.get(b))
            .ok_or(IoError::Io)?;
        Ok(())
    }
    fn write(&mut self, b: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), IoError> {
        self.tick()?;
        if b >= self.blocks() {
            return Err(IoError::Io);
        }
        self.log.push("write");
        self.cache.insert(b, *buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), IoError> {
        self.tick()?;
        self.log.push("flush");
        for (b, d) in std::mem::take(&mut self.cache) {
            self.durable[b as usize] = d;
        }
        Ok(())
    }
}
