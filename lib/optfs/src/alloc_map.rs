//! Alocador com liberação adiada (ADR 0052, item 5).

use crate::io::IoError;
use alloc::vec::Vec;
use optfs_format::FIRST_ALLOC;

/// Mapa de bits em memória mais a lista de blocos liberados ainda não
/// reutilizáveis.
///
/// Um bloco liberado no txg `N` ainda é referenciado pela árvore do txg
/// `N - 1`, o superbloco de reserva. Só depois que o txg `N + 1` é
/// confirmado ([`Allocator::confirmed`]) ele volta a ser alocável.
pub struct Allocator {
    used: Vec<u64>,
    blocks: u64,
    pending: Vec<(u64, u64)>,
    hint: u64,
}

impl Allocator {
    /// Alocador de um volume de `blocks` blocos, com os reservados em uso
    /// e o último (cópia do cabeçalho).
    #[must_use]
    pub fn new(blocks: u64) -> Self {
        let words = usize::try_from(blocks.div_ceil(64)).unwrap_or(0);
        let mut a = Self {
            used: alloc::vec![0; words],
            blocks,
            pending: Vec::new(),
            hint: FIRST_ALLOC,
        };
        for b in 0..FIRST_ALLOC.min(blocks) {
            a.set(b, true);
        }
        if blocks > 0 {
            a.set(blocks - 1, true);
        }
        a
    }

    fn set(&mut self, b: u64, v: bool) {
        let (w, bit) = (usize::try_from(b / 64).unwrap_or(0), b % 64);
        if let Some(x) = self.used.get_mut(w) {
            if v {
                *x |= 1 << bit;
            } else {
                *x &= !(1 << bit);
            }
        }
    }

    /// Se o bloco está em uso.
    #[must_use]
    pub fn is_used(&self, b: u64) -> bool {
        let (w, bit) = (usize::try_from(b / 64).unwrap_or(usize::MAX), b % 64);
        self.used.get(w).is_none_or(|x| x >> bit & 1 == 1)
    }

    /// Marca um bloco como em uso (montagem: o que a árvore alcança).
    pub fn mark_used(&mut self, b: u64) {
        self.set(b, true);
    }

    /// Aloca um bloco livre.
    ///
    /// # Errors
    /// [`IoError::Full`] se não há bloco livre.
    pub fn alloc(&mut self) -> Result<u64, IoError> {
        for i in 0..self.blocks {
            let b = FIRST_ALLOC + (self.hint - FIRST_ALLOC + i) % (self.blocks - FIRST_ALLOC);
            if !self.is_used(b) {
                self.set(b, true);
                self.hint = b + 1;
                if self.hint >= self.blocks {
                    self.hint = FIRST_ALLOC;
                }
                return Ok(b);
            }
        }
        Err(IoError::Full)
    }

    /// Libera `b` no txg `txg`: o bloco continua em uso até o txg
    /// seguinte ser confirmado.
    pub fn free(&mut self, txg: u64, b: u64) {
        self.pending.push((txg, b));
    }

    /// Libera já um bloco que nasceu no txg corrente e nunca foi gravado.
    pub fn free_now(&mut self, b: u64) {
        self.set(b, false);
    }

    /// O txg `txg` foi confirmado: o que foi liberado em `txg - 1` ou
    /// antes volta a ser alocável.
    pub fn confirmed(&mut self, txg: u64) {
        let mut keep = Vec::new();
        for (t, b) in core::mem::take(&mut self.pending) {
            if t < txg {
                self.set(b, false);
            } else {
                keep.push((t, b));
            }
        }
        self.pending = keep;
    }

    /// Blocos livres agora (sem contar os pendentes).
    #[must_use]
    pub fn free_blocks(&self) -> u64 {
        (0..self.blocks).filter(|b| !self.is_used(*b)).count() as u64
    }
}
