//! Alocador buddy de frames físicos de 4 KiB (T-106; SDD v1.0, seção 6.3).
//!
//! Blocos de ordem `k` têm `2^k` frames e são alinhados naturalmente no número
//! de frame físico (PFN), então o buddy de um bloco é `pfn ^ (1 << k)`.
//!
//! Metadados sem heap: o kernel ainda não tem heap, então quem chama fornece um
//! slice de [`FrameMeta`], um por frame da faixa física gerenciada (12 bytes por
//! frame, cerca de 0,3% da memória). As listas livres são duplamente encadeadas
//! por índice dentro desse slice: alocar, liberar e coalescer custam `O(MAX_ORDER)`,
//! sem ponteiros crus e sem `unsafe`.

use super::{FRAME_SIZE, PhysAddr};

/// Maior ordem: blocos de `2^18` frames, 1 GiB (SDD, seção 6.3).
pub const MAX_ORDER: usize = 18;
const ORDERS: usize = MAX_ORDER + 1;
/// Fim de lista.
const NIL: u32 = u32::MAX;

/// Estado de um frame da faixa gerenciada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Fora das regiões adicionadas (buraco, MMIO, firmware).
    Reserved,
    /// Frame interno de um bloco cuja cabeça está em outro frame.
    Tail,
    /// Cabeça de bloco livre da ordem dada, numa lista livre.
    Free(u8),
    /// Cabeça de bloco alocado da ordem dada.
    Used(u8),
}

/// Metadados de um frame. Opaco: quem chama só fornece o armazenamento.
#[derive(Clone, Copy, Debug)]
pub struct FrameMeta {
    next: u32,
    prev: u32,
    state: State,
}

impl FrameMeta {
    /// Valor inicial para preencher o armazenamento.
    pub const EMPTY: Self = Self {
        next: NIL,
        prev: NIL,
        state: State::Reserved,
    };
}

/// Erros do alocador. Nenhuma operação entra em pânico.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuddyError {
    /// Base da faixa não alinhada a 4 KiB, ou faixa com mais de `u32::MAX - 1` frames.
    BadSpan,
    /// Ordem maior que [`MAX_ORDER`].
    BadOrder,
    /// Endereço fora da faixa gerenciada ou não alinhado ao tamanho do bloco.
    BadAddress,
    /// Região sobrepõe frames que já são gerenciados.
    Overlap,
    /// O endereço não é cabeça de um bloco alocado: double free ou endereço inválido.
    NotAllocated,
    /// O bloco foi alocado com outra ordem.
    WrongOrder,
}

/// Alocador buddy sobre a faixa física `[base, base + meta.len() * 4 KiB)`.
pub struct FrameAllocator<'a> {
    meta: &'a mut [FrameMeta],
    base_pfn: u64,
    heads: [u32; ORDERS],
    free_blocks: [usize; ORDERS],
    used_blocks: [usize; ORDERS],
    managed: usize,
}

impl<'a> FrameAllocator<'a> {
    /// Cria o alocador vazio; nenhum frame fica disponível até [`Self::add_region`].
    ///
    /// # Errors
    ///
    /// [`BuddyError::BadSpan`] se `base` não for alinhado a 4 KiB ou `meta` for grande demais.
    pub fn new(base: PhysAddr, meta: &'a mut [FrameMeta]) -> Result<Self, BuddyError> {
        if !base.0.is_multiple_of(FRAME_SIZE) || meta.len() >= NIL as usize {
            return Err(BuddyError::BadSpan);
        }
        meta.fill(FrameMeta::EMPTY);
        Ok(Self {
            meta,
            base_pfn: base.0 / FRAME_SIZE,
            heads: [NIL; ORDERS],
            free_blocks: [0; ORDERS],
            used_blocks: [0; ORDERS],
            managed: 0,
        })
    }

    /// Entrega ao alocador a memória em `[base, base + len)`. As bordas não alinhadas
    /// a 4 KiB e o que cair fora da faixa gerenciada são descartados. Devolve o
    /// número de frames adicionados.
    ///
    /// # Errors
    ///
    /// [`BuddyError::Overlap`] se algum frame já for gerenciado; nada muda nesse caso.
    pub fn add_region(&mut self, base: PhysAddr, len: u64) -> Result<usize, BuddyError> {
        let span_end = self.base_pfn + self.meta.len() as u64;
        let start = base.0.div_ceil(FRAME_SIZE).max(self.base_pfn);
        let end = (base.0.saturating_add(len) / FRAME_SIZE).min(span_end);
        if start >= end {
            return Ok(0);
        }
        let (first, last) = (self.index(start), self.index(end));
        if self.meta[first..last]
            .iter()
            .any(|m| m.state != State::Reserved)
        {
            return Err(BuddyError::Overlap);
        }
        let mut pfn = start;
        while pfn < end {
            let mut order = (pfn.trailing_zeros() as usize).min(MAX_ORDER);
            while pfn + (1 << order) > end {
                order -= 1;
            }
            let idx = self.index(pfn);
            for m in &mut self.meta[idx..idx + (1 << order)] {
                m.state = State::Tail;
            }
            self.release(idx, order);
            pfn += 1 << order;
        }
        self.managed += last - first;
        Ok(last - first)
    }

    /// Aloca um bloco de `2^order` frames, alinhado ao seu tamanho.
    pub fn alloc(&mut self, order: usize) -> Option<PhysAddr> {
        let mut k = (order..ORDERS).find(|&k| self.heads[k] != NIL)?;
        let idx = self.heads[k] as usize;
        self.unlink(idx, k);
        while k > order {
            k -= 1;
            self.push(idx + (1 << k), k);
        }
        self.meta[idx].state = State::Used(tag(order));
        self.used_blocks[order] += 1;
        Some(PhysAddr((self.base_pfn + idx as u64) * FRAME_SIZE))
    }

    /// Devolve um bloco obtido com [`Self::alloc`] da mesma ordem, coalescendo buddies.
    ///
    /// # Errors
    ///
    /// Ordem ou endereço inválidos, double free ou ordem diferente da alocada;
    /// o estado não muda em nenhum desses casos.
    pub fn free(&mut self, addr: PhysAddr, order: usize) -> Result<(), BuddyError> {
        if order > MAX_ORDER {
            return Err(BuddyError::BadOrder);
        }
        let pfn = addr.0 / FRAME_SIZE;
        let in_span = pfn >= self.base_pfn && pfn - self.base_pfn < self.meta.len() as u64;
        if !addr.0.is_multiple_of(FRAME_SIZE << order) || !in_span {
            return Err(BuddyError::BadAddress);
        }
        let idx = self.index(pfn);
        match self.meta[idx].state {
            State::Used(k) if usize::from(k) == order => {}
            State::Used(_) => return Err(BuddyError::WrongOrder),
            _ => return Err(BuddyError::NotAllocated),
        }
        self.used_blocks[order] -= 1;
        self.release(idx, order);
        Ok(())
    }

    /// Blocos livres de cada ordem.
    #[must_use]
    pub fn free_blocks(&self) -> [usize; ORDERS] {
        self.free_blocks
    }

    /// Blocos alocados de cada ordem.
    #[must_use]
    pub fn used_blocks(&self) -> [usize; ORDERS] {
        self.used_blocks
    }

    /// Total de frames livres.
    #[must_use]
    pub fn free_frames(&self) -> usize {
        frames(&self.free_blocks)
    }

    /// Total de frames alocados.
    #[must_use]
    pub fn used_frames(&self) -> usize {
        frames(&self.used_blocks)
    }

    /// Total de frames entregues por [`Self::add_region`].
    #[must_use]
    pub fn managed_frames(&self) -> usize {
        self.managed
    }

    /// Índice no slice de metadados; `pfn` já foi validado contra a faixa.
    fn index(&self, pfn: u64) -> usize {
        usize::try_from(pfn - self.base_pfn).unwrap_or(usize::MAX)
    }

    /// Insere o bloco `idx` de ordem `order` como livre, unindo-o aos buddies livres.
    fn release(&mut self, mut idx: usize, mut order: usize) {
        let base = usize::try_from(self.base_pfn % (1 << MAX_ORDER)).unwrap_or(0);
        while order < MAX_ORDER {
            // Buddy calculado no PFN físico, depois convertido de volta para índice.
            let Some(buddy) = ((base + idx) ^ (1 << order)).checked_sub(base) else {
                break;
            };
            if self.meta.get(buddy).map(|m| m.state) != Some(State::Free(tag(order))) {
                break;
            }
            self.unlink(buddy, order);
            self.meta[idx.max(buddy)].state = State::Tail;
            idx = idx.min(buddy);
            order += 1;
        }
        self.push(idx, order);
    }

    fn push(&mut self, idx: usize, order: usize) {
        let head = self.heads[order];
        if head != NIL {
            self.meta[head as usize].prev = link(idx);
        }
        self.meta[idx] = FrameMeta {
            next: head,
            prev: NIL,
            state: State::Free(tag(order)),
        };
        self.heads[order] = link(idx);
        self.free_blocks[order] += 1;
    }

    fn unlink(&mut self, idx: usize, order: usize) {
        let FrameMeta { next, prev, .. } = self.meta[idx];
        if prev == NIL {
            self.heads[order] = next;
        } else {
            self.meta[prev as usize].next = next;
        }
        if next != NIL {
            self.meta[next as usize].prev = prev;
        }
        self.meta[idx].state = State::Tail;
        self.free_blocks[order] -= 1;
    }
}

/// Ordens cabem em `u8` porque `MAX_ORDER < 256`.
fn tag(order: usize) -> u8 {
    u8::try_from(order).unwrap_or(u8::MAX)
}

/// Índices cabem em `u32` porque `new` limita o slice a `NIL - 1` frames.
fn link(idx: usize) -> u32 {
    u32::try_from(idx).unwrap_or(NIL)
}

fn frames(blocks: &[usize; ORDERS]) -> usize {
    blocks.iter().enumerate().map(|(k, n)| n << k).sum()
}

#[cfg(test)]
mod tests;
