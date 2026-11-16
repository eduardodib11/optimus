//! Anel de bytes dos buffers de envio e de recepção. O limite é fixo, mas a
//! memória cresce sob demanda (dobrando até o limite): conexão parada não
//! custa o buffer inteiro, e a soma dos limites é o que o `Tcp` contabiliza.

use alloc::vec::Vec;

/// Memória inicial de um buffer.
const INITIAL: usize = 4096;

/// Fila de bytes com limite fixo.
#[derive(Debug)]
pub struct Buf {
    data: Vec<u8>,
    start: usize,
    len: usize,
    limit: usize,
}

impl Buf {
    /// Buffer que guarda até `limit` bytes.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            data: Vec::new(),
            start: 0,
            len: 0,
            limit,
        }
    }

    /// O limite de bytes.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Garante memória física para `need` bytes (no máximo o limite): copia
    /// os dados para o início de um vetor maior.
    fn reserve(&mut self, need: usize) {
        let cap = self.data.len();
        if need <= cap {
            return;
        }
        let new_cap = need.max(cap * 2).max(INITIAL).min(self.limit);
        let mut v = alloc::vec![0u8; new_cap];
        let n = self.peek(0, &mut v);
        debug_assert_eq!(n, self.len);
        self.data = v;
        self.start = 0;
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
    pub const fn free(&self) -> usize {
        self.limit - self.len
    }

    /// Acrescenta o que couber de `src`; devolve quantos bytes entraram.
    pub fn push(&mut self, src: &[u8]) -> usize {
        let n = src.len().min(self.free());
        if n == 0 {
            return 0;
        }
        self.reserve(self.len + n);
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
        if off >= self.len || self.data.is_empty() {
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
        if n == 0 {
            return;
        }
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
