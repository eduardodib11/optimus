//! Alocador slab e heap do kernel com limite (T-108; SDD v1.0, seção 6.3).
//!
//! Oito caches de objetos de 16 a 2048 bytes (potências de dois). Cada slab
//! é um bloco do buddy alinhado ao próprio tamanho (4 KiB até 512 bytes,
//! 16 KiB acima), com um cabeçalho de 4 palavras no começo; o endereço do
//! slab de um objeto sai do próprio endereço, por máscara. Objetos livres
//! formam uma lista encadeada pela primeira palavra de cada um. Cada cache
//! mantém a lista dos slabs com espaço e guarda no máximo um slab vazio; os
//! outros voltam ao buddy. Pedidos maiores que 2048 bytes (ou com alinhamento
//! maior) vão direto ao buddy.
//!
//! O limite conta os bytes de páginas que o heap segura; passar dele dá
//! [`HeapError::LimitExceeded`], nunca pânico. A memória em si fica atrás de
//! [`PageSource`]: o kernel a lê e escreve pelo mapa direto, os testes no
//! host por um mapa de palavras.
//!
//! Limitações: uma liberação dupla só é detectada quando zera a contagem do
//! slab; não há proteção contra uso depois de liberar (envenenamento e
//! páginas de guarda ficam para quando houver orçamento de desempenho).

#![forbid(unsafe_code)]

use core::alloc::Layout;

use super::FRAME_SIZE;
use super::buddy::MAX_ORDER;

/// Tamanhos de objeto de cada cache.
pub const CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

/// Palavras do cabeçalho do slab.
const NEXT: u64 = 0;
const PREV: u64 = 8;
const FREE: u64 = 16;
const COUNT: u64 = 24;
const HEADER: u64 = 32;
/// "SLAB" nos 32 bits altos da palavra de contagem.
const MAGIC: u64 = 0x534c_4142 << 32;
/// Slabs vazios guardados por cache.
const KEEP_EMPTY: usize = 1;

/// De onde vêm as páginas e como ler e escrever palavras nelas.
pub trait PageSource {
    /// Bloco de `2^order` páginas alinhado ao seu tamanho; devolve o endereço.
    fn alloc_pages(&mut self, order: usize) -> Option<u64>;
    /// Devolve um bloco de [`Self::alloc_pages`].
    fn free_pages(&mut self, addr: u64, order: usize);
    /// Lê a palavra em `addr` (alinhado a 8).
    fn read(&mut self, addr: u64) -> u64;
    /// Escreve a palavra em `addr` (alinhado a 8).
    fn write(&mut self, addr: u64, value: u64);
}

/// Erros do heap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeapError {
    /// O pedido passaria do limite do heap.
    LimitExceeded,
    /// O buddy não tem bloco do tamanho necessário.
    OutOfMemory,
    /// Tamanho ou alinhamento maiores que o maior bloco do buddy.
    TooLarge,
    /// O endereço não é um objeto alocado deste heap.
    BadFree,
}

/// Estatísticas de um cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Tamanho do objeto.
    pub size: usize,
    /// Objetos por slab.
    pub per_slab: usize,
    /// Slabs em uso (incluindo o vazio guardado).
    pub slabs: usize,
    /// Objetos alocados agora.
    pub in_use: usize,
    /// Alocações bem-sucedidas desde o início.
    pub allocs: u64,
    /// Liberações desde o início.
    pub frees: u64,
}

/// Estatísticas das alocações grandes, direto do buddy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LargeStats {
    /// Bytes de páginas em uso.
    pub bytes: u64,
    /// Alocações desde o início.
    pub allocs: u64,
    /// Liberações desde o início.
    pub frees: u64,
}

#[derive(Clone, Copy)]
struct Cache {
    size: u64,
    order: usize,
    /// Primeiro slab com objeto livre, ou zero.
    partial: u64,
    empty: usize,
    stats: CacheStats,
}

impl Cache {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "slabs têm no máximo 16 KiB"
    )]
    const fn new(size: usize) -> Self {
        let order = if size <= 512 { 0 } else { 2 };
        let bytes = (FRAME_SIZE << order) as usize;
        let first = HEADER.next_multiple_of(size as u64) as usize;
        Self {
            size: size as u64,
            order,
            partial: 0,
            empty: 0,
            stats: CacheStats {
                size,
                per_slab: (bytes - first) / size,
                slabs: 0,
                in_use: 0,
                allocs: 0,
                frees: 0,
            },
        }
    }

    const fn bytes(&self) -> u64 {
        FRAME_SIZE << self.order
    }

    const fn first(&self) -> u64 {
        HEADER.next_multiple_of(self.size)
    }
}

/// Heap do kernel sobre `M`, com limite em bytes de páginas.
pub struct Heap<M> {
    caches: [Cache; CLASSES.len()],
    large: LargeStats,
    mem: M,
    limit: u64,
    used: u64,
    failures: u64,
}

/// Classe (índice em [`CLASSES`]) que atende `layout`, ou `None` se for
/// grande demais para slab. Todo objeto da classe `i` serve a qualquer
/// `layout` dela: tem `CLASSES[i]` bytes e alinhamento `CLASSES[i]`.
#[must_use]
pub fn class(layout: Layout) -> Option<usize> {
    let need = layout.size().max(layout.align());
    CLASSES.iter().position(|&c| c >= need)
}

/// `addr` tem a posição de um objeto da classe `i` dentro de um slab (só
/// aritmética, sem ler o slab nem tomar trava).
#[must_use]
pub fn plausible(i: usize, addr: u64) -> bool {
    let Some(&size) = CLASSES.get(i) else {
        return false;
    };
    let cache = Cache::new(size);
    let offset = addr & (cache.bytes() - 1);
    offset >= cache.first() && (offset - cache.first()).is_multiple_of(cache.size)
}

/// Ordem do bloco do buddy para uma alocação grande.
fn large_order(layout: Layout) -> Option<usize> {
    let need = layout.size().max(layout.align()) as u64;
    (0..=MAX_ORDER).find(|&k| FRAME_SIZE << k >= need)
}

impl<M: PageSource> Heap<M> {
    /// Heap vazio com `limit` bytes de páginas.
    pub const fn new(mem: M, limit: u64) -> Self {
        let mut caches = [Cache::new(16); CLASSES.len()];
        let mut i = 0;
        while i < CLASSES.len() {
            caches[i] = Cache::new(CLASSES[i]);
            i += 1;
        }
        Self {
            caches,
            large: LargeStats {
                bytes: 0,
                allocs: 0,
                frees: 0,
            },
            mem,
            limit,
            used: 0,
            failures: 0,
        }
    }

    /// Troca o limite; não libera nada que já esteja acima dele.
    pub fn set_limit(&mut self, limit: u64) {
        self.limit = limit;
    }

    /// Limite em bytes.
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes de páginas que o heap segura.
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Alocações recusadas desde o início.
    pub const fn failures(&self) -> u64 {
        self.failures
    }

    /// Estatísticas de cada cache, do menor para o maior.
    pub fn cache_stats(&self) -> [CacheStats; CLASSES.len()] {
        self.caches.map(|c| c.stats)
    }

    /// Estatísticas das alocações grandes.
    pub const fn large_stats(&self) -> LargeStats {
        self.large
    }

    /// Aloca um objeto para `layout`; devolve o endereço.
    ///
    /// # Errors
    ///
    /// Limite, falta de memória no buddy ou pedido grande demais.
    pub fn alloc(&mut self, layout: Layout) -> Result<u64, HeapError> {
        let result = match class(layout) {
            Some(i) => self.alloc_small(i),
            None => self.alloc_large(layout),
        };
        if result.is_err() {
            self.failures += 1;
        }
        result
    }

    /// Um objeto da classe `i` para um cache por CPU, ou `None` (o cache só
    /// tenta encher: a recusa não conta como falha).
    pub fn alloc_class(&mut self, i: usize) -> Option<u64> {
        if i >= CLASSES.len() {
            return None;
        }
        self.alloc_small(i).ok()
    }

    /// Devolve um objeto da classe `i`, vindo de um cache por CPU.
    ///
    /// # Errors
    ///
    /// [`HeapError::BadFree`] se o endereço não for um objeto alocado de um
    /// slab da classe; nada muda nesse caso.
    pub fn free_class(&mut self, i: usize, addr: u64) -> Result<(), HeapError> {
        if i >= CLASSES.len() {
            return Err(HeapError::BadFree);
        }
        self.free_small(i, addr)
    }

    /// Libera um objeto alocado com o mesmo `layout`.
    ///
    /// # Errors
    ///
    /// [`HeapError::BadFree`] se o endereço não for um objeto alocado de um
    /// slab; nada muda nesse caso.
    pub fn free(&mut self, addr: u64, layout: Layout) -> Result<(), HeapError> {
        if let Some(i) = class(layout) {
            return self.free_small(i, addr);
        }
        let order = large_order(layout).ok_or(HeapError::BadFree)?;
        self.mem.free_pages(addr, order);
        self.used -= FRAME_SIZE << order;
        self.large.bytes -= FRAME_SIZE << order;
        self.large.frees += 1;
        Ok(())
    }

    fn reserve(&mut self, bytes: u64) -> Result<(), HeapError> {
        if self.used + bytes > self.limit {
            return Err(HeapError::LimitExceeded);
        }
        self.used += bytes;
        Ok(())
    }

    fn alloc_large(&mut self, layout: Layout) -> Result<u64, HeapError> {
        let order = large_order(layout).ok_or(HeapError::TooLarge)?;
        self.reserve(FRAME_SIZE << order)?;
        let Some(addr) = self.mem.alloc_pages(order) else {
            self.used -= FRAME_SIZE << order;
            return Err(HeapError::OutOfMemory);
        };
        self.large.bytes += FRAME_SIZE << order;
        self.large.allocs += 1;
        Ok(addr)
    }

    fn alloc_small(&mut self, i: usize) -> Result<u64, HeapError> {
        let mut slab = self.caches[i].partial;
        if slab == 0 {
            slab = self.new_slab(i)?;
        }
        let obj = self.mem.read(slab + FREE);
        let next = self.mem.read(obj);
        self.mem.write(slab + FREE, next);
        let count = self.mem.read(slab + COUNT) & 0xffff_ffff;
        self.mem.write(slab + COUNT, MAGIC | (count + 1));
        let cache = &mut self.caches[i];
        if count == 0 {
            cache.empty -= 1;
        }
        cache.stats.in_use += 1;
        cache.stats.allocs += 1;
        if next == 0 {
            self.unlink(i, slab);
        }
        Ok(obj)
    }

    fn new_slab(&mut self, i: usize) -> Result<u64, HeapError> {
        let Cache { size, order, .. } = self.caches[i];
        let (bytes, first) = (self.caches[i].bytes(), self.caches[i].first());
        self.reserve(bytes)?;
        let Some(slab) = self.mem.alloc_pages(order) else {
            self.used -= bytes;
            return Err(HeapError::OutOfMemory);
        };
        let mut free = 0;
        let mut obj = slab + bytes - size;
        while obj >= slab + first {
            self.mem.write(obj, free);
            free = obj;
            obj -= size;
        }
        self.mem.write(slab + FREE, free);
        self.mem.write(slab + COUNT, MAGIC);
        self.push(i, slab);
        let cache = &mut self.caches[i];
        cache.empty += 1;
        cache.stats.slabs += 1;
        Ok(slab)
    }

    fn free_small(&mut self, i: usize, addr: u64) -> Result<(), HeapError> {
        let cache = self.caches[i];
        let slab = addr & !(cache.bytes() - 1);
        let offset = addr - slab;
        if offset < cache.first() || !(offset - cache.first()).is_multiple_of(cache.size) {
            return Err(HeapError::BadFree);
        }
        let header = self.mem.read(slab + COUNT);
        let count = header & 0xffff_ffff;
        if header & !0xffff_ffff != MAGIC || count == 0 {
            return Err(HeapError::BadFree);
        }
        let head = self.mem.read(slab + FREE);
        self.mem.write(addr, head);
        self.mem.write(slab + FREE, addr);
        self.mem.write(slab + COUNT, MAGIC | (count - 1));
        if head == 0 {
            self.push(i, slab);
        }
        let stats = &mut self.caches[i].stats;
        stats.in_use -= 1;
        stats.frees += 1;
        if count == 1 {
            if self.caches[i].empty >= KEEP_EMPTY {
                self.unlink(i, slab);
                self.mem.write(slab + COUNT, 0);
                self.mem.free_pages(slab, cache.order);
                self.used -= cache.bytes();
                self.caches[i].stats.slabs -= 1;
            } else {
                self.caches[i].empty += 1;
            }
        }
        Ok(())
    }

    fn push(&mut self, i: usize, slab: u64) {
        let head = self.caches[i].partial;
        self.mem.write(slab + NEXT, head);
        self.mem.write(slab + PREV, 0);
        if head != 0 {
            self.mem.write(head + PREV, slab);
        }
        self.caches[i].partial = slab;
    }

    fn unlink(&mut self, i: usize, slab: u64) {
        let next = self.mem.read(slab + NEXT);
        let prev = self.mem.read(slab + PREV);
        if prev == 0 {
            self.caches[i].partial = next;
        } else {
            self.mem.write(prev + NEXT, next);
        }
        if next != 0 {
            self.mem.write(next + PREV, prev);
        }
    }
}

#[cfg(test)]
mod tests;
