//! Anel de capacidade fixa.

use alloc::vec::Vec;

/// Anel (buffer circular) FIFO de capacidade fixa, alocada na criação.
///
/// [`push`](Self::push) recusa quando cheio (o produtor decide o que fazer);
/// [`push_overwrite`](Self::push_overwrite) descarta o mais antigo (registros
/// recentes).
#[derive(Clone, Debug)]
pub struct Ring<T> {
    buf: Vec<Option<T>>,
    /// Posição do elemento mais antigo.
    head: usize,
    len: usize,
}

impl<T> Ring<T> {
    /// Anel para até `capacity` elementos (`capacity = 0` recusa tudo).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let mut buf = Vec::with_capacity(capacity);
        buf.resize_with(capacity, || None);
        Self {
            buf,
            head: 0,
            len: 0,
        }
    }

    /// Capacidade.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Elementos guardados.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Vazio?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Cheio?
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == self.buf.len()
    }

    fn slot(&self, offset: usize) -> usize {
        (self.head + offset) % self.buf.len()
    }

    /// Põe no fim; cheio, devolve o valor em `Err`.
    ///
    /// # Errors
    ///
    /// O próprio `value`, se o anel está cheio.
    pub fn push(&mut self, value: T) -> Result<(), T> {
        if self.is_full() {
            return Err(value);
        }
        let at = self.slot(self.len);
        self.buf[at] = Some(value);
        self.len += 1;
        Ok(())
    }

    /// Põe no fim; cheio, descarta o mais antigo e o devolve.
    pub fn push_overwrite(&mut self, value: T) -> Option<T> {
        if self.buf.is_empty() {
            return Some(value);
        }
        let dropped = if self.is_full() { self.pop() } else { None };
        // Há espaço agora.
        let _ = self.push(value);
        dropped
    }

    /// Tira o mais antigo.
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let value = self.buf[self.head].take();
        self.head = self.slot(1);
        self.len -= 1;
        value
    }

    /// O mais antigo.
    #[must_use]
    pub fn front(&self) -> Option<&T> {
        self.get(0)
    }

    /// O mais novo.
    #[must_use]
    pub fn back(&self) -> Option<&T> {
        self.len.checked_sub(1).and_then(|i| self.get(i))
    }

    /// O `i`-ésimo, do mais antigo (0) ao mais novo.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&T> {
        if i < self.len {
            self.buf[self.slot(i)].as_ref()
        } else {
            None
        }
    }

    /// Do mais antigo ao mais novo.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        (0..self.len).filter_map(|i| self.get(i))
    }

    /// Esvazia.
    pub fn clear(&mut self) {
        while self.pop().is_some() {}
    }
}
