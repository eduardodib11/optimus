//! Faixas de sequência confirmadas por SACK (RFC 2018 e RFC 6675). O
//! placar do remetente guarda, ordenadas e sem sobreposição, as faixas
//! acima de `snd_una` que o outro lado disse ter recebido.

use alloc::vec::Vec;

/// Faixas que o placar guarda no máximo. Passando disso, blocos novos que
/// não se juntam a nenhuma são ignorados (o RTO recupera o resto).
pub const MAX_RANGES: usize = 64;

/// Distância de `x` a `base` no espaço de sequência.
fn off(x: u32, base: u32) -> u32 {
    x.wrapping_sub(base)
}

/// O placar do remetente.
#[derive(Debug, Default)]
pub struct Scoreboard {
    /// (início, fim exclusivo), em ordem crescente de sequência.
    ranges: Vec<(u32, u32)>,
}

impl Scoreboard {
    /// Placar vazio.
    #[must_use]
    pub const fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Esquece tudo (RTO: o receptor pode ter desistido do que confirmou).
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Registra o bloco `[a, b)` com `una` como menor sequência não
    /// confirmada e `max` como o maior enviado. Bloco fora de `(una, max]`,
    /// vazio ou invertido é ignorado.
    pub fn insert(&mut self, una: u32, max: u32, a: u32, b: u32) {
        let (oa, ob, om) = (off(a, una), off(b, una), off(max, una));
        if oa == 0 || oa >= ob || ob > om || om >= 0x8000_0000 {
            return;
        }
        let (mut a, mut b) = (a, b);
        let mut out: Vec<(u32, u32)> = Vec::with_capacity(self.ranges.len() + 1);
        let mut placed = false;
        for &(x, y) in &self.ranges {
            if off(y, una) < off(a, una) {
                out.push((x, y));
            } else if off(x, una) > off(b, una) {
                if !placed {
                    out.push((a, b));
                    placed = true;
                }
                out.push((x, y));
            } else {
                // Encosta ou sobrepõe: junta.
                if off(x, una) < off(a, una) {
                    a = x;
                }
                if off(y, una) > off(b, una) {
                    b = y;
                }
            }
        }
        if !placed {
            out.push((a, b));
        }
        if out.len() > MAX_RANGES {
            return;
        }
        self.ranges = out;
    }

    /// `snd_una` avançou: some o que ficou para trás.
    pub fn advance(&mut self, una: u32) {
        self.ranges.retain_mut(|r| {
            if off(r.1, una) >= 0x8000_0000 || r.1 == una {
                return false;
            }
            if off(r.0, una) >= 0x8000_0000 {
                r.0 = una;
            }
            true
        });
    }

    /// Bytes confirmados por SACK.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.ranges.iter().map(|&(x, y)| off(y, x) as usize).sum()
    }

    /// Bytes confirmados em `[seq, ∞)`.
    #[must_use]
    pub fn above(&self, seq: u32) -> usize {
        self.ranges
            .iter()
            .map(|&(x, y)| {
                if off(x, seq) < 0x8000_0000 {
                    off(y, x) as usize
                } else if off(y, seq) < 0x8000_0000 && y != seq {
                    off(y, seq) as usize
                } else {
                    0
                }
            })
            .sum()
    }

    /// As faixas.
    #[must_use]
    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }

    /// Lacunas (não confirmadas) em `[una, high)`: cada uma como (início, fim).
    pub fn holes(&self, una: u32) -> impl Iterator<Item = (u32, u32)> + '_ {
        let mut prev = una;
        self.ranges.iter().filter_map(move |&(x, y)| {
            let hole = (off(x, prev) > 0 && off(x, prev) < 0x8000_0000).then_some((prev, x));
            prev = y;
            hole
        })
    }
}
