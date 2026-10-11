//! Linhas de registro sem alocação: formata numa pilha de 64 bytes (o
//! limite de `DEBUG_PRINT`) e manda ao kernel.

use core::fmt;

/// Uma linha de até `kabi::DEBUG_PRINT_MAX` bytes; o que passa é cortado
/// em fronteira de caractere.
pub struct Line {
    buf: [u8; ostd::kabi::DEBUG_PRINT_MAX],
    len: usize,
}

impl Line {
    /// Linha vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; ostd::kabi::DEBUG_PRINT_MAX],
            len: 0,
        }
    }

    /// Manda a linha ao registro do kernel.
    pub fn print(&self) {
        let text = core::str::from_utf8(&self.buf[..self.len]).unwrap_or("okfuzz: ?");
        ostd::debug::print(text);
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - self.len;
        let mut n = s.len().min(room);
        while !s.is_char_boundary(n) {
            n -= 1;
        }
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Imprime uma linha formatada (`format_args!`) no registro do kernel.
#[macro_export]
macro_rules! say {
    ($($t:tt)*) => {{
        let mut line = $crate::out::Line::new();
        let _ = core::fmt::Write::write_fmt(&mut line, format_args!($($t)*));
        line.print();
    }};
}
