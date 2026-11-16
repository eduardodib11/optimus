//! Anel de bytes de capacidade fixa dos buffers de envio e de recepção.

use alloc::vec::Vec;

/// Fila de bytes com capacidade fixa.
#[derive(Debug)]
pub struct Buf {
    data: Vec<u8>,
    start: usize,
    len: usize,
}

impl Buf {
    /// Buffer de `cap` bytes.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            data: alloc::vec![0; cap],
            start: 0,
            len: 0,
        }
    }

    /// Bytes guardados.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Sem bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Espaço livre.
    #[must_use]
    pub fn free(&self) -> usize {
        self.data.len() - self.len
    }

    /// Acrescenta o que couber de `src`; devolve quantos bytes entraram.
    pub fn push(&mut self, src: &[u8]) -> usize {
        let n = src.len().min(self.free());
        let cap = self.data.len();
        let at = (self.start + self.len) % cap;
        let first = n.min(cap - at);
        self.data[at..at + first].copy_from_slice(&src[..first]);
        self.data[..n - first].copy_from_slice(&src[first..n]);
        self.len += n;
        n
    }

    /// Copia até `out.len()` bytes a partir do deslocamento `off`, sem tirá-los.
    pub fn peek(&self, off: usize, out: &mut [u8]) -> usize {
        if off >= self.len {
            return 0;
        }
        let n = out.len().min(self.len - off);
        let cap = self.data.len();
        let at = (self.start + off) % cap;
        let first = n.min(cap - at);
        out[..first].copy_from_slice(&self.data[at..at + first]);
        out[first..n].copy_from_slice(&self.data[..n - first]);
        n
    }

    /// Descarta `n` bytes do início (no máximo o que há).
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.start = (self.start + n) % self.data.len();
        self.len -= n;
    }

    /// Tira até `out.len()` bytes do início.
    pub fn pop(&mut self, out: &mut [u8]) -> usize {
        let n = self.peek(0, out);
        self.consume(n);
        n
    }
}
