//! Moldura do HUD: painel de vidro reto, sem perspectiva, com reflexo
//! diagonal (ADR 0040, item 3).

use crate::tela::{Tela, cor};
use crate::tema::{CIANO, VIDRO_BORDA};

/// Parte do painel onde o reflexo diagonal fica no pico, de 0 a 1000.
const REFLEXO_CENTRO: i64 = 380;
/// Meia largura do reflexo, na mesma escala.
const REFLEXO_META: i64 = 80;

/// Desenha o painel de vidro, inset `margem` pixels das bordas da tela.
pub fn desenha_moldura(tela: &mut Tela, margem: i32) {
    let w = tela.largura() as i32 - 2 * margem;
    let h = tela.altura() as i32 - 2 * margem;
    if w <= 0 || h <= 0 {
        return;
    }
    let borda = cor(0x55, VIDRO_BORDA);
    let vidro = cor(0x0D, CIANO);
    for y in 0..h {
        for x in 0..w {
            let (px, py) = (margem + x, margem + y);
            if x == 0 || y == 0 || x == w - 1 || y == h - 1 {
                tela.sobrepoe(px, py, borda);
                continue;
            }
            tela.sobrepoe(px, py, vidro);
            let reflexo = reflexo(x, y, w, h);
            if reflexo > 0 {
                tela.sobrepoe(px, py, cor(reflexo, 0x00FF_FFFF));
            }
        }
    }
}

/// Opacidade do reflexo branco em (`x`, `y`) de um painel `w` por `h`: um
/// triângulo sobre a diagonal, zero fora da faixa.
fn reflexo(x: i32, y: i32, w: i32, h: i32) -> u8 {
    let (x, y, w, h) = (i64::from(x), i64::from(y), i64::from(w), i64::from(h));
    let diagonal = (x * h + y * w) * 1000 / (2 * w * h);
    let folga = REFLEXO_META - (diagonal - REFLEXO_CENTRO).abs();
    if folga <= 0 {
        0
    } else {
        (0x12 * folga / REFLEXO_META) as u8
    }
}
