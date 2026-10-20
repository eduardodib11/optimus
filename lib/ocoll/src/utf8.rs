//! Utilitários UTF-8: validação estrita, decodificação incremental e cortes
//! em fronteira de caractere.
//!
//! A validação segue a Tabela 3-7 do Unicode (sem formas longas demais, sem
//! substitutos `U+D800..=U+DFFF`, nada acima de `U+10FFFF`), como o
//! `core::str::from_utf8`, contra o qual os testes comparam.

use alloc::string::String;
use core::fmt;

/// Erro de validação: onde começa a sequência inválida e quantos bytes ela
/// ocupa (`None` se o texto acaba no meio de um caractere).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utf8Error {
    /// Bytes válidos antes do erro.
    pub valid_up_to: usize,
    /// Tamanho da sequência inválida, ou `None` se faltam bytes no fim.
    pub error_len: Option<usize>,
}

impl fmt::Display for Utf8Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.error_len {
            Some(n) => write!(f, "UTF-8 inválido em {} ({n} bytes)", self.valid_up_to),
            None => write!(f, "UTF-8 incompleto em {}", self.valid_up_to),
        }
    }
}

/// Tamanho do caractere que começa com `first`, ou `None` se `first` não
/// pode abrir um (continuação solta, `C0`, `C1`, `F5..=FF`).
#[must_use]
pub const fn sequence_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

/// Faixa aceita para o 2º byte depois de `first`.
const fn second_range(first: u8) -> (u8, u8) {
    match first {
        0xE0 => (0xA0, 0xBF),
        0xED => (0x80, 0x9F),
        0xF0 => (0x90, 0xBF),
        0xF4 => (0x80, 0x8F),
        _ => (0x80, 0xBF),
    }
}

/// Valida `bytes` como UTF-8.
///
/// # Errors
///
/// Onde e como o texto deixa de ser UTF-8 válido.
pub fn validate(bytes: &[u8]) -> Result<&str, Utf8Error> {
    let mut i = 0;
    while i < bytes.len() {
        let first = bytes[i];
        let bad = |len| Utf8Error {
            valid_up_to: i,
            error_len: Some(len),
        };
        let Some(n) = sequence_len(first) else {
            return Err(bad(1));
        };
        if n == 1 {
            i += 1;
            continue;
        }
        let (lo, hi) = second_range(first);
        for k in 1..n {
            let Some(&b) = bytes.get(i + k) else {
                return Err(Utf8Error {
                    valid_up_to: i,
                    error_len: None,
                });
            };
            let (lo, hi) = if k == 1 { (lo, hi) } else { (0x80, 0xBF) };
            if !(lo..=hi).contains(&b) {
                return Err(bad(k));
            }
        }
        i += n;
    }
    // Já conferido byte a byte acima; a conversão só reconfere.
    core::str::from_utf8(bytes).map_err(|_| Utf8Error {
        valid_up_to: bytes.len(),
        error_len: Some(1),
    })
}

/// O maior índice `<= index` em fronteira de caractere de `s` (`index` além
/// do fim vale o fim).
#[must_use]
pub fn floor_boundary(s: &str, index: usize) -> usize {
    let mut i = index.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// O prefixo de `s` com no máximo `max` bytes, cortado em fronteira de
/// caractere.
#[must_use]
pub fn truncate(s: &str, max: usize) -> &str {
    &s[..floor_boundary(s, max)]
}

/// Decodificador incremental: recebe pedaços de bytes (de uma mensagem, de
/// uma leitura) em que um caractere pode ficar partido entre dois pedaços,
/// e entrega texto. Bytes inválidos viram `U+FFFD`, um por sequência
/// inválida, como `String::from_utf8_lossy`.
#[derive(Clone, Debug, Default)]
pub struct Decoder {
    /// Início de um caractere ainda incompleto.
    pending: [u8; 4],
    len: usize,
}

impl Decoder {
    /// Decodificador sem pendência.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: [0; 4],
            len: 0,
        }
    }

    /// Há um caractere pela metade?
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        self.len > 0
    }

    /// Consome `chunk`, acrescentando o texto a `out`.
    pub fn push(&mut self, chunk: &[u8], out: &mut String) {
        for &b in chunk {
            self.byte(b, out);
        }
    }

    /// Acaba o fluxo: um caractere incompleto vira `U+FFFD`.
    pub fn finish(&mut self, out: &mut String) {
        if self.len > 0 {
            out.push('\u{FFFD}');
            self.len = 0;
        }
    }

    fn byte(&mut self, b: u8, out: &mut String) {
        loop {
            if self.len == 0 {
                match sequence_len(b) {
                    Some(1) => out.push(char::from(b)),
                    Some(_) => {
                        self.pending[0] = b;
                        self.len = 1;
                    }
                    None => out.push('\u{FFFD}'),
                }
                return;
            }
            let first = self.pending[0];
            let (lo, hi) = if self.len == 1 {
                second_range(first)
            } else {
                (0x80, 0xBF)
            };
            if !(lo..=hi).contains(&b) {
                // A sequência pendente termina inválida; `b` recomeça.
                out.push('\u{FFFD}');
                self.len = 0;
                continue;
            }
            self.pending[self.len] = b;
            self.len += 1;
            if Some(self.len) == sequence_len(first) {
                if let Ok(s) = core::str::from_utf8(&self.pending[..self.len]) {
                    out.push_str(s);
                }
                self.len = 0;
            }
            return;
        }
    }
}
