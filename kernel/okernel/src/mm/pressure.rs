//! Limiares de pressão de memória (ADR 0038, item 5): o nível **baixo**
//! afirma com menos de 1/8 dos quadros livres e o **crítico** com menos de
//! 1/32; cada um só desafirma ao passar de 1/8 + 1/16 (ou 1/32 + 1/64), a
//! histerese.
//!
//! Só há atômicos: [`Pressure::update`] pode correr em várias CPUs (cada
//! nível muda por troca atômica), e a sinalização (os `Interrupt`s
//! sintéticos) roda num ponto sem travas, a partir de [`Pressure::take`].

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, Ordering};

/// Nível baixo (índice em [`Pressure::take`]).
pub const LOW: usize = 0;
/// Nível crítico.
pub const CRITICAL: usize = 1;

/// O nível `level` fica afirmado com `free` de `total` quadros livres, se
/// antes estava `asserted`.
#[must_use]
pub const fn next(level: usize, asserted: bool, free: usize, total: usize) -> bool {
    let (limit, rearm) = if level == LOW {
        (total / 8, total / 8 + total / 16)
    } else {
        (total / 32, total / 32 + total / 64)
    };
    if asserted {
        free <= rearm
    } else {
        free < limit
    }
}

/// Estado dos dois níveis e um bit de mudança ainda não sinalizada.
pub struct Pressure {
    asserted: [AtomicBool; 2],
    changed: AtomicBool,
}

impl Default for Pressure {
    fn default() -> Self {
        Self::new()
    }
}

impl Pressure {
    /// Nada afirmado.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            asserted: [AtomicBool::new(false), AtomicBool::new(false)],
            changed: AtomicBool::new(false),
        }
    }

    /// Recalcula os níveis com `free` de `total` quadros.
    pub fn update(&self, free: usize, total: usize) {
        for (level, flag) in self.asserted.iter().enumerate() {
            let was = flag.load(Ordering::Relaxed);
            let now = next(level, was, free, total);
            if now != was
                && flag
                    .compare_exchange(was, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                self.changed.store(true, Ordering::Release);
            }
        }
    }

    /// Os níveis afirmados agora (baixo, crítico).
    pub fn peek(&self) -> [bool; 2] {
        self.asserted.each_ref().map(|f| f.load(Ordering::Relaxed))
    }

    /// Os níveis afirmados, se mudaram desde a última chamada; custa uma
    /// leitura quando nada mudou.
    pub fn take(&self) -> Option<[bool; 2]> {
        if !self.changed.load(Ordering::Relaxed) || !self.changed.swap(false, Ordering::Acquire) {
            return None;
        }
        Some(self.peek())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiares_e_histerese() {
        let total = 3200;
        // Baixo: afirma abaixo de 400 e só desafirma acima de 600.
        assert!(!next(LOW, false, 400, total) && next(LOW, false, 399, total));
        assert!(next(LOW, true, 600, total) && !next(LOW, true, 601, total));
        // Crítico: abaixo de 100, desafirma acima de 150.
        assert!(!next(CRITICAL, false, 100, total) && next(CRITICAL, false, 99, total));
        assert!(next(CRITICAL, true, 150, total) && !next(CRITICAL, true, 151, total));
    }

    #[test]
    fn so_sinaliza_mudanca() {
        let p = Pressure::new();
        p.update(1000, 3200);
        assert_eq!(p.take(), None);
        p.update(90, 3200);
        assert_eq!(p.take(), Some([true, true]));
        assert_eq!(p.take(), None);
        p.update(500, 3200);
        assert_eq!(p.take(), Some([true, false]));
        p.update(500, 3200);
        assert_eq!(p.take(), None);
        p.update(700, 3200);
        assert_eq!(p.take(), Some([false, false]));
    }
}
