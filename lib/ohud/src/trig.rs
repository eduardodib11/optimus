//! Tabela de seno e cosseno em inteiros, com passo de quarto de grau (ADR 0040,
//! item 7). As contas de ponto flutuante rodam uma vez, na construção.

use alloc::vec::Vec;
use core::f64::consts::{PI, TAU};

/// Passos por volta: um quarto de grau cada.
pub const PASSOS: i32 = 1440;
/// Escala dos valores: `ESCALA` equivale a 1.0.
pub const ESCALA: i32 = 1 << 14;

/// Tabela de seno de uma volta inteira.
pub struct Trig {
    seno: Vec<i32>,
}

impl Trig {
    /// Calcula a tabela de seno.
    #[must_use]
    pub fn new() -> Self {
        let seno = (0..PASSOS)
            .map(|passo| {
                let theta = f64::from(passo) * TAU / f64::from(PASSOS);
                (sen(theta) * f64::from(ESCALA)) as i32
            })
            .collect();
        Self { seno }
    }

    /// Seno do `passo` (módulo uma volta), em unidades de [`ESCALA`].
    #[must_use]
    pub fn seno(&self, passo: i32) -> i32 {
        self.seno[passo.rem_euclid(PASSOS) as usize]
    }

    /// Cosseno do `passo`, em unidades de [`ESCALA`].
    #[must_use]
    pub fn cosseno(&self, passo: i32) -> i32 {
        self.seno(passo + PASSOS / 4)
    }

    /// Ponto a `raio` pixels de (`cx`, `cy`) no `passo` dado.
    #[must_use]
    pub fn ponto(&self, cx: i32, cy: i32, raio: i32, passo: i32) -> (i32, i32) {
        let x = cx + raio * self.cosseno(passo) / ESCALA;
        let y = cy + raio * self.seno(passo) / ESCALA;
        (x, y)
    }
}

impl Default for Trig {
    fn default() -> Self {
        Self::new()
    }
}

/// Seno por Bhaskara I (erro menor que 0,002); a outra metade da volta sai
/// por simetria.
fn sen(theta: f64) -> f64 {
    let t = theta % TAU;
    if t < PI {
        bhaskara(t)
    } else {
        -bhaskara(t - PI)
    }
}

fn bhaskara(x: f64) -> f64 {
    let p = x * (PI - x);
    16.0 * p / (5.0 * PI * PI - 4.0 * p)
}
