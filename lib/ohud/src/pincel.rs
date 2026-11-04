//! Primitivas de desenho em torno de um centro: disco, halo, arco, traço
//! radial e linha. Tudo em inteiros.

use crate::tela::{Cor, Tela};
use crate::trig::{PASSOS, Trig};

/// Passos da tabela por grau.
const PASSOS_POR_GRAU: i32 = PASSOS / 360;

/// Pincel com centro fixo: as primitivas desenham em volta de (`cx`, `cy`).
pub(crate) struct Pincel<'a> {
    pub(crate) tela: &'a mut Tela,
    pub(crate) trig: &'a Trig,
    pub(crate) cx: i32,
    pub(crate) cy: i32,
}

impl Pincel<'_> {
    /// Disco cheio de raio `raio`.
    pub(crate) fn disco(&mut self, raio: i32, cor: Cor) {
        for dy in -raio..=raio {
            for dx in -raio..=raio {
                if dx * dx + dy * dy <= raio * raio {
                    self.tela.sobrepoe(self.cx + dx, self.cy + dy, cor);
                }
            }
        }
    }

    /// Disco com brilho radial: a opacidade de `cor` cai do centro à borda.
    pub(crate) fn halo(&mut self, raio: i32, cor: Cor) {
        if raio <= 0 {
            return;
        }
        let alfa = (cor >> 24) as i32;
        for dy in -raio..=raio {
            for dx in -raio..=raio {
                let d2 = dx * dx + dy * dy;
                if d2 <= raio * raio {
                    let d = raiz(d2 as u32) as i32;
                    let a = (alfa * (raio - d) / raio) as u32;
                    let pintado = (a << 24) | (cor & 0xFF_FFFF);
                    self.tela.sobrepoe(self.cx + dx, self.cy + dy, pintado);
                }
            }
        }
    }

    /// Arco de anel de raio `raio` e espessura `espessura` pixels, dos passos
    /// `ini` até `fim` (quartos de grau).
    pub(crate) fn arco(&mut self, raio: i32, espessura: i32, ini: i32, fim: i32, cor: Cor) {
        let base = raio - espessura / 2;
        for passo in ini..fim {
            for r in base..base + espessura {
                let (x, y) = self.trig.ponto(self.cx, self.cy, r, passo);
                self.tela.sobrepoe(x, y, cor);
            }
        }
    }

    /// Anel tracejado. `padrao` são pares (traço, vão) em graus, com valores
    /// positivos, repetidos por uma volta a partir do passo `fase`.
    pub(crate) fn tracejado(
        &mut self,
        raio: i32,
        espessura: i32,
        fase: i32,
        padrao: &[(i32, i32)],
        cor: Cor,
    ) {
        let fim = fase + PASSOS;
        let mut ini = fase;
        for &(traco, vao) in padrao.iter().cycle() {
            if ini >= fim || traco + vao <= 0 {
                break;
            }
            let corte = (ini + traco * PASSOS_POR_GRAU).min(fim);
            self.arco(raio, espessura, ini, corte, cor);
            ini += (traco + vao) * PASSOS_POR_GRAU;
        }
    }

    /// Traço radial de `r0` a `r1` pixels, no `passo`.
    pub(crate) fn radial(&mut self, r0: i32, r1: i32, passo: i32, cor: Cor) {
        for r in r0..=r1 {
            let (x, y) = self.trig.ponto(self.cx, self.cy, r, passo);
            self.tela.sobrepoe(x, y, cor);
        }
    }

    /// Linha entre dois pontos absolutos da tela.
    pub(crate) fn linha(&mut self, (x0, y0): (i32, i32), (x1, y1): (i32, i32), cor: Cor) {
        let (dx, dy) = (x1 - x0, y1 - y0);
        let n = dx.abs().max(dy.abs()).max(1);
        for i in 0..=n {
            self.tela.sobrepoe(x0 + dx * i / n, y0 + dy * i / n, cor);
        }
    }
}

/// Raiz quadrada inteira (parte inteira), por deslocamento de bits.
fn raiz(n: u32) -> u32 {
    let (mut resto, mut raiz, mut bit) = (n, 0u32, 1u32 << 30);
    while bit > resto {
        bit >>= 2;
    }
    while bit != 0 {
        if resto >= raiz + bit {
            resto -= raiz + bit;
            raiz = (raiz >> 1) + bit;
        } else {
            raiz >>= 1;
        }
        bit >>= 2;
    }
    raiz
}

#[cfg(test)]
mod testes {
    use super::raiz;

    #[test]
    fn raiz_inteira_confere_com_a_força_bruta() {
        for n in 0..5000u32 {
            let r = raiz(n);
            assert!(r * r <= n && (r + 1) * (r + 1) > n, "raiz({n}) = {r}");
        }
    }
}
