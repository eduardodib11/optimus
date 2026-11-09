//! Fila split (seção 2.7 da especificação). O dispositivo não é confiável.

use crate::{DmaBuf, Error};

const DESC_SIZE: usize = 16;
const F_NEXT: u16 = 1;
const F_WRITE: u16 = 2;

/// Um segmento de buffer de uma cadeia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seg {
    /// Endereço de DMA do buffer (o que o dispositivo enxerga).
    pub addr: u64,
    /// Tamanho em bytes.
    pub len: u32,
    /// `true` se o dispositivo escreve neste buffer.
    pub write: bool,
}

/// Uma cadeia devolvida pelo dispositivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    /// Cabeça, o valor que [`Queue::push`] devolveu.
    pub head: u16,
    /// Bytes que o dispositivo diz ter escrito (já limitado ao possível).
    pub len: u32,
}

/// Fila de `N` descritores (`N` potência de dois, de 1 a 32768).
pub struct Queue<D: DmaBuf, const N: usize> {
    dma: D,
    avail_off: usize,
    used_off: usize,
    free_head: u16,
    free: usize,
    avail_idx: u16,
    last_used: u16,
    next: [u16; N],
    /// Descritores da cadeia que começa aqui; 0 = não está em voo.
    count: [u16; N],
    /// Bytes que o dispositivo pode escrever na cadeia.
    wlen: [u32; N],
}

const fn align4(x: usize) -> usize {
    (x + 3) & !3
}

impl<D: DmaBuf, const N: usize> Queue<D, N> {
    /// Tamanho de DMA que uma fila de `N` entradas pede.
    #[must_use]
    pub const fn dma_len() -> usize {
        align4(align4(DESC_SIZE * N + 6 + 2 * N) + 6 + 8 * N)
    }

    /// Monta a fila e zera as três áreas.
    ///
    /// # Errors
    /// [`Error::BadQueue`] se `N` não for potência de dois em 1..=32768;
    /// [`Error::DmaTooSmall`] se `dma` não couber a fila.
    pub fn new(dma: D) -> Result<Self, Error> {
        if !N.is_power_of_two() || N > 32768 {
            return Err(Error::BadQueue);
        }
        if dma.len() < Self::dma_len() {
            return Err(Error::DmaTooSmall);
        }
        for off in (0..Self::dma_len()).step_by(4) {
            dma.write32(off, 0);
        }
        let avail_off = DESC_SIZE * N;
        let mut q = Self {
            dma,
            avail_off,
            used_off: align4(avail_off + 6 + 2 * N),
            free_head: 0,
            free: N,
            avail_idx: 0,
            last_used: 0,
            next: [0; N],
            count: [0; N],
            wlen: [0; N],
        };
        for i in 0..N {
            q.next[i] = ((i + 1) % N) as u16;
        }
        Ok(q)
    }

    /// Endereços de DMA de (descritores, `avail`, `used`).
    #[must_use]
    pub fn addrs(&self) -> (u64, u64, u64) {
        let base = self.dma.device_addr();
        (
            base,
            base + self.avail_off as u64,
            base + self.used_off as u64,
        )
    }

    /// Descritores livres.
    #[must_use]
    pub const fn free(&self) -> usize {
        self.free
    }

    /// Publica uma cadeia e devolve a cabeça. Depois é preciso notificar.
    ///
    /// # Errors
    /// [`Error::BadChain`] (vazia ou maior que `N`) ou [`Error::Full`].
    pub fn push(&mut self, segs: &[Seg]) -> Result<u16, Error> {
        if segs.is_empty() || segs.len() > N {
            return Err(Error::BadChain);
        }
        if segs.len() > self.free {
            return Err(Error::Full);
        }
        let head = self.free_head;
        let mut idx = head;
        let mut wlen = 0u32;
        for (i, s) in segs.iter().enumerate() {
            let last = i + 1 == segs.len();
            let at = usize::from(idx) * DESC_SIZE;
            let mut flags = if s.write { F_WRITE } else { 0 };
            if !last {
                flags |= F_NEXT;
            }
            if s.write {
                wlen = wlen.saturating_add(s.len);
            }
            self.dma.write64(at, s.addr);
            self.dma.write32(at + 8, s.len);
            self.dma.write16(at + 12, flags);
            self.dma.write16(at + 14, self.next[usize::from(idx)]);
            if last {
                self.free_head = self.next[usize::from(idx)];
            } else {
                idx = self.next[usize::from(idx)];
            }
        }
        self.free -= segs.len();
        self.count[usize::from(head)] = segs.len() as u16;
        self.wlen[usize::from(head)] = wlen;
        let slot = usize::from(self.avail_idx) % N;
        self.dma.write16(self.avail_off + 4 + 2 * slot, head);
        self.dma.barrier();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.dma.write16(self.avail_off + 2, self.avail_idx);
        self.dma.barrier();
        Ok(head)
    }

    /// Tira a próxima cadeia usada, se houver.
    ///
    /// # Errors
    /// [`Error::DeviceMisbehaved`] se o id não é uma cadeia em voo (a entrada
    /// é consumida e a fila continua utilizável).
    pub fn pop(&mut self) -> Result<Option<Chain>, Error> {
        self.dma.barrier();
        let used_idx = self.dma.read16(self.used_off + 2);
        if used_idx == self.last_used {
            return Ok(None);
        }
        let slot = usize::from(self.last_used) % N;
        let id = self.dma.read32(self.used_off + 4 + 8 * slot);
        let len = self.dma.read32(self.used_off + 8 + 8 * slot);
        self.last_used = self.last_used.wrapping_add(1);
        let head = usize::try_from(id)
            .ok()
            .filter(|&h| h < N)
            .ok_or(Error::DeviceMisbehaved)?;
        let n = self.count[head];
        if n == 0 {
            return Err(Error::DeviceMisbehaved);
        }
        let len = len.min(self.wlen[head]);
        let mut idx = head;
        for _ in 1..n {
            idx = usize::from(self.next[idx]);
        }
        self.next[idx] = self.free_head;
        self.free_head = head as u16;
        self.free += usize::from(n);
        self.count[head] = 0;
        Ok(Some(Chain {
            head: head as u16,
            len,
        }))
    }
}
