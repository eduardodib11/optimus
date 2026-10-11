//! Texto no framebuffer, para a tela de pânico (T-110; SDD v1.0, seção 6.5).
//!
//! Lógica portável: desenha caracteres da [`font`] numa superfície de pixels
//! de 32 bits (o framebuffer do GOP, ou um vetor nos testes). Nada aqui
//! aloca, porque o pânico pode vir do próprio alocador.

#![forbid(unsafe_code)]

use core::fmt;

use kabi::boot::PixelFormat;

pub mod font;

/// Cor de 32 bits no formato do framebuffer.
#[must_use]
pub const fn rgb(format: PixelFormat, r: u8, g: u8, b: u8) -> u32 {
    let (r, g, b) = (r as u32, g as u32, b as u32);
    match format {
        PixelFormat::Rgb => r | (g << 8) | (b << 16),
        PixelFormat::Bgr => b | (g << 8) | (r << 16),
    }
}

/// Letra ASCII mais próxima das acentuadas do português; o resto passa igual
/// (e vira `?` na fonte se não for ASCII).
#[must_use]
pub const fn fold(c: char) -> char {
    match c {
        'á' | 'à' | 'â' | 'ã' | 'ä' => 'a',
        'é' | 'ê' | 'è' => 'e',
        'í' | 'ì' => 'i',
        'ó' | 'ô' | 'õ' | 'ò' | 'ö' => 'o',
        'ú' | 'ù' | 'ü' => 'u',
        'ç' => 'c',
        'Á' | 'À' | 'Â' | 'Ã' | 'Ä' => 'A',
        'É' | 'Ê' | 'È' => 'E',
        'Í' | 'Ì' => 'I',
        'Ó' | 'Ô' | 'Õ' | 'Ò' | 'Ö' => 'O',
        'Ú' | 'Ù' | 'Ü' => 'U',
        'Ç' => 'C',
        other => other,
    }
}

/// Área de pixels `width` x `height`, com `stride` pixels por linha.
pub struct Surface<'a> {
    pixels: &'a mut [u32],
    width: usize,
    height: usize,
    stride: usize,
}

impl<'a> Surface<'a> {
    /// Superfície sobre `pixels`; `None` se as dimensões não couberem.
    #[must_use]
    pub fn new(pixels: &'a mut [u32], width: usize, height: usize, stride: usize) -> Option<Self> {
        let needed = stride.checked_mul(height)?;
        (width <= stride && needed <= pixels.len()).then_some(Self {
            pixels,
            width,
            height,
            stride,
        })
    }

    /// Colunas de texto que cabem.
    #[must_use]
    pub const fn columns(&self) -> usize {
        self.width / font::WIDTH
    }

    /// Linhas de texto que cabem.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.height / font::HEIGHT
    }

    /// Pinta a superfície inteira.
    pub fn clear(&mut self, color: u32) {
        for y in 0..self.height {
            let start = y * self.stride;
            self.pixels[start..start + self.width].fill(color);
        }
    }

    /// Desenha `c` na célula (`column`, `row`); fora da tela, nada.
    pub fn draw_char(&mut self, column: usize, row: usize, c: char, fg: u32, bg: u32) {
        if column >= self.columns() || row >= self.rows() {
            return;
        }
        for (dy, bits) in font::glyph(fold(c)).iter().enumerate() {
            let start = (row * font::HEIGHT + dy) * self.stride + column * font::WIDTH;
            for (dx, pixel) in self.pixels[start..start + font::WIDTH]
                .iter_mut()
                .enumerate()
            {
                *pixel = if bits & (0x80 >> dx) != 0 { fg } else { bg };
            }
        }
    }

    /// Escreve `text` a partir da linha `row`, quebrando no fim da linha e
    /// em `\n`; devolve a próxima linha livre.
    pub fn draw_text(&mut self, row: usize, text: &str, fg: u32, bg: u32) -> usize {
        self.draw_text_at(0, row, text, fg, bg)
    }

    /// Como [`Self::draw_text`], mas cada linha começa na coluna `indent`.
    pub fn draw_text_at(
        &mut self,
        indent: usize,
        mut row: usize,
        text: &str,
        fg: u32,
        bg: u32,
    ) -> usize {
        let mut column = indent;
        for c in text.chars() {
            if c == '\n' || column == self.columns() {
                row += 1;
                column = indent;
                if c == '\n' {
                    continue;
                }
            }
            self.draw_char(column, row, c, fg, bg);
            column += 1;
        }
        row + 1
    }
}

/// Texto formatado num buffer fixo, truncado se não couber (sem heap).
pub struct FixedBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuf<N> {
    /// Buffer vazio.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    /// O texto escrito até aqui.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Só entram caracteres inteiros (veja `write_str`), então sempre é UTF-8.
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl<const N: usize> Default for FixedBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for FixedBuf<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for c in text.chars() {
            let mut utf8 = [0; 4];
            let encoded = c.encode_utf8(&mut utf8).as_bytes();
            let Some(slot) = self.bytes.get_mut(self.len..self.len + encoded.len()) else {
                return Err(fmt::Error);
            };
            slot.copy_from_slice(encoded);
            self.len += encoded.len();
        }
        Ok(())
    }
}

/// Fundo da tela de pânico (vermelho escuro), em RGB.
pub const PANIC_BACKGROUND: (u8, u8, u8) = (0x80, 0x00, 0x00);

/// Desenha a tela de pânico: fundo vermelho, título, local e mensagem.
pub fn panic_screen(surface: &mut Surface<'_>, format: PixelFormat, location: &str, message: &str) {
    let (r, g, b) = PANIC_BACKGROUND;
    let bg = rgb(format, r, g, b);
    let fg = rgb(format, 0xff, 0xff, 0xff);
    surface.clear(bg);
    let mut row = 1;
    for line in [
        "  Optimus OS - PANICO DO KERNEL",
        "",
        "  O kernel parou para nao seguir em estado inconsistente.",
        "",
    ] {
        row = surface.draw_text(row, line, fg, bg);
    }
    row = surface.draw_text_at(2, row, location, fg, bg);
    surface.draw_text_at(2, row + 1, message, fg, bg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    #[test]
    fn fonte_cobre_o_ascii_imprimivel() {
        assert!(font::glyph(' ').iter().all(|&row| row == 0));
        // 'A': topo `.###.` nas linhas 1 e 2, com a coluna de margem.
        assert_eq!(font::glyph('A')[1], 0b0011_1000);
        assert_eq!(font::glyph('A')[2], 0b0011_1000);
        assert_eq!(font::glyph('A')[0], 0);
        assert_eq!(font::glyph('A')[15], 0);
        assert_eq!(font::glyph('Â'), font::glyph('?'));
        assert_eq!(font::glyph(fold('Â')), font::glyph('A'));
        assert_eq!(fold('ç'), 'c');
        assert_eq!(fold('ß'), 'ß');
        for c in '!'..='~' {
            assert!(font::glyph(c).iter().any(|&row| row != 0), "{c:?} vazio");
            assert!(font::glyph(c).iter().all(|&row| row.trailing_zeros() >= 2));
        }
    }

    #[test]
    fn desenha_e_quebra_linhas() {
        let mut pixels = vec![0u32; 40 * 36];
        let mut s = Surface::new(&mut pixels, 33, 36, 40).unwrap();
        assert_eq!((s.columns(), s.rows()), (4, 2));
        s.clear(1);
        let next = s.draw_text(0, "ABCDE\nZ", 7, 2);
        assert_eq!(next, 3);
        // 'A' na célula (0, 0): pixel (3, 1) aceso, (0, 0) apagado.
        assert_eq!(pixels[40 + 3], 7);
        assert_eq!(pixels[0], 2);
        // 'E' quebrou para a linha 1 (célula (0, 1)): topo `#####`.
        assert_eq!(pixels[(16 + 1) * 40 + 1], 7);
        // A coluna 32 (fora das células) mantém a cor do `clear`.
        assert_eq!(pixels[32], 1);
        // O fim do stride não é tocado.
        assert_eq!(pixels[35], 0);
    }

    #[test]
    fn superficie_invalida_e_cores() {
        let mut small = [0u32; 10];
        assert!(Surface::new(&mut small, 4, 4, 3).is_none());
        assert!(Surface::new(&mut small, 4, 3, 4).is_none());
        assert_eq!(rgb(PixelFormat::Rgb, 1, 2, 3), 0x0003_0201);
        assert_eq!(rgb(PixelFormat::Bgr, 1, 2, 3), 0x0001_0203);
    }

    #[test]
    fn buffer_fixo_trunca_sem_cortar_caractere() {
        let mut buf = FixedBuf::<6>::new();
        assert!(write!(buf, "pânico").is_err());
        assert_eq!(buf.as_str(), "pânic");
        let mut ok = FixedBuf::<16>::default();
        write!(ok, "{}:{}", ["a.rs"][0], 7).unwrap();
        assert_eq!(ok.as_str(), "a.rs:7");
    }

    #[test]
    fn tela_de_panico() {
        let mut pixels = vec![0u32; 320 * 200];
        let mut s = Surface::new(&mut pixels, 320, 200, 320).unwrap();
        panic_screen(&mut s, PixelFormat::Bgr, "em main.rs:1:1", "teste");
        let bg = rgb(PixelFormat::Bgr, 0x80, 0, 0);
        let white = rgb(PixelFormat::Bgr, 0xff, 0xff, 0xff);
        assert!(pixels.iter().all(|&p| p == bg || p == white));
        assert!(pixels.iter().filter(|&&p| p == white).count() > 500);
    }
}
