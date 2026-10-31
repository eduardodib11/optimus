//! Superfície de pixels do HUD e a mistura de cores com opacidade.

use alloc::vec::Vec;

/// Cor `0xAARRGGBB`: o byte alto é a opacidade (`0xFF` é opaco).
pub type Cor = u32;

/// Monta uma cor com opacidade `alfa` e o RGB `rgb` (`0xRRGGBB`).
#[must_use]
pub const fn cor(alfa: u8, rgb: u32) -> Cor {
    ((alfa as u32) << 24) | (rgb & 0x00FF_FFFF)
}

/// Superfície de desenho: pixels `0xAARRGGBB` em ordem de linha.
pub struct Tela {
    largura: usize,
    altura: usize,
    pixels: Vec<Cor>,
}

impl Tela {
    /// Tela de `largura` por `altura` pixels, preenchida com `fundo`.
    #[must_use]
    pub fn nova(largura: usize, altura: usize, fundo: Cor) -> Self {
        Self {
            largura,
            altura,
            pixels: alloc::vec![fundo; largura * altura],
        }
    }

    /// Largura em pixels.
    #[must_use]
    pub fn largura(&self) -> usize {
        self.largura
    }

    /// Altura em pixels.
    #[must_use]
    pub fn altura(&self) -> usize {
        self.altura
    }

    /// Pixels em ordem de linha.
    #[must_use]
    pub fn pixels(&self) -> &[Cor] {
        &self.pixels
    }

    /// Pixel em (`x`, `y`), ou `None` fora da tela.
    #[must_use]
    pub fn pixel(&self, x: i32, y: i32) -> Option<Cor> {
        self.indice(x, y).map(|i| self.pixels[i])
    }

    /// Mistura `cor` sobre o pixel (`x`, `y`) pela opacidade dela. Fora da
    /// tela, não faz nada.
    pub fn sobrepoe(&mut self, x: i32, y: i32, cor: Cor) {
        if let Some(i) = self.indice(x, y) {
            self.pixels[i] = mistura(self.pixels[i], cor);
        }
    }

    /// Retângulo de `w` por `h` a partir de (`x`, `y`), recortado à tela.
    pub fn retangulo(&mut self, x: i32, y: i32, w: i32, h: i32, cor: Cor) {
        for py in y..y + h {
            for px in x..x + w {
                self.sobrepoe(px, py, cor);
            }
        }
    }

    fn indice(&self, x: i32, y: i32) -> Option<usize> {
        let (x, y) = (usize::try_from(x).ok()?, usize::try_from(y).ok()?);
        (x < self.largura && y < self.altura).then_some(y * self.largura + x)
    }
}

/// Mistura `src` sobre `dst`; o resultado é sempre opaco.
fn mistura(dst: Cor, src: Cor) -> Cor {
    let a = src >> 24;
    let canal = |shift: u32| {
        let s = (src >> shift) & 0xFF;
        let d = (dst >> shift) & 0xFF;
        (s * a + d * (255 - a) + 127) / 255
    };
    0xFF00_0000 | (canal(16) << 16) | (canal(8) << 8) | canal(0)
}
