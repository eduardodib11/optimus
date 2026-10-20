//! Segmentos, páginas e o [`Heap`]. As invariantes INV-S, INV-R, INV-B e
//! INV-F estão na documentação da crate.

use core::mem::{offset_of, size_of};
use core::ptr::null_mut;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use crate::class::{NUM_CLASSES, Plan, class_size, plan};
use crate::{Fault, PAGE_SIZE, PAGES_PER_SEGMENT, PageSource, SEGMENT_SIZE};

/// Palavras de 64 bits do bitmap de uma página: um bit por bloco de 8 bytes.
const BITS_WORDS: usize = PAGE_SIZE / 8 / 64;
/// Identifica um cabeçalho de segmento (`"OALLOCSG"`).
const MAGIC: u64 = 0x4f41_4c4c_4f43_5347;

/// Página livre no segmento.
const KIND_FREE: u8 = 0;
/// Página dividida em blocos de uma classe.
const KIND_SMALL: u8 = 1;
/// Primeira página de um bloco de várias páginas (um bloco só).
const KIND_LARGE: u8 = 2;
/// Página 1 de um segmento próprio de um bloco enorme (um bloco só).
const KIND_HUGE: u8 = 3;
/// Página que continua um bloco grande (ou lixo do segmento enorme).
const KIND_CONT: u8 = 4;

/// Índice das listas dos blocos grandes e dos enormes (depois das classes).
const LARGE_LIST: usize = NUM_CLASSES;
const HUGE_LIST: usize = NUM_CLASSES + 1;
const NUM_LISTS: usize = NUM_CLASSES + 2;

/// Quantas páginas cheias o dono examina por vez atrás de blocos que outras
/// threads liberaram.
const RECLAIM_SCAN: usize = 16;

/// Metadados de uma página (ou de um bloco grande ou enorme).
///
/// `thread_free` é o único campo que outras threads escrevem; `kind`,
/// `bsize`, `recip`, `cap` e `key` só mudam quando a página não tem blocos
/// entregues (INV-R). O resto é só do dono.
#[repr(C)]
struct Page {
    /// Topo da pilha dos blocos que outras threads liberaram (endereço, 0 =
    /// vazia); o elo de cada bloco é `próximo ^ key`.
    thread_free: AtomicUsize,
    key: usize,
    /// Lista de onde a alocação tira (endereço do primeiro bloco, 0 = vazia).
    free: usize,
    /// Blocos que o dono liberou.
    local_free: usize,
    prev: *mut Page,
    next: *mut Page,
    /// Bytes do bloco.
    bsize: u32,
    /// `ceil(2^32 / bsize)`: o índice do bloco é `(deslocamento * recip) >> 32`.
    recip: u32,
    /// Blocos entregues e ainda não devolvidos ao dono.
    used: u32,
    /// Blocos já carvados da página (os de índice maior nunca foram dados).
    bump: u32,
    /// Blocos que cabem.
    cap: u32,
    kind: u8,
    class: u8,
    /// Páginas do bloco grande.
    npages: u8,
    /// Está na lista `full` (sem espaço quando foi vista pela última vez).
    full: bool,
}

impl Page {
    const fn new() -> Self {
        Self {
            thread_free: AtomicUsize::new(0),
            key: 0,
            free: 0,
            local_free: 0,
            prev: null_mut(),
            next: null_mut(),
            bsize: 0,
            recip: 0,
            used: 0,
            bump: 0,
            cap: 0,
            kind: KIND_FREE,
            class: 0,
            npages: 0,
            full: false,
        }
    }
}

/// Cabeçalho de um segmento, na página 0 dele.
#[repr(C)]
struct Segment {
    magic: u64,
    canary: u64,
    /// Id do heap dono; 0 = abandonado.
    owner: AtomicUsize,
    prev: *mut Segment,
    next: *mut Segment,
    abandoned_next: *mut Segment,
    /// Segmentos contíguos (mais de um só no bloco enorme).
    count: usize,
    /// Bit `i` ligado = página `i` livre (o bit 0 nunca liga).
    free_pages: u32,
    used_pages: u32,
    pages: [Page; PAGES_PER_SEGMENT],
    /// Bitmap dos blocos livres de cada página (dono apenas).
    bits: [[u64; BITS_WORDS]; PAGES_PER_SEGMENT],
}

const _: () = assert!(size_of::<Segment>() <= PAGE_SIZE);
const _: () = assert!(PAGES_PER_SEGMENT == 32);

/// Ponteiro para `addr`, com a procedência exposta por [`Heap::new_segment`].
///
/// Todo ponteiro que o alocador usa (cabeçalhos, páginas, blocos) nasce
/// assim a partir de um endereço, porque o ponteiro que o usuário devolve em
/// `free` pode ter perdido a procedência sobre o resto do segmento (um
/// `Box` o restringe ao próprio bloco no modelo de empréstimos do Rust).
fn ptr_at<T>(addr: usize) -> *mut T {
    core::ptr::with_exposed_provenance_mut(addr)
}

fn seg_of<T>(p: *mut T) -> *mut Segment {
    ptr_at(p.addr() & !(SEGMENT_SIZE - 1))
}

fn page_at(seg: *mut Segment, i: usize) -> *mut Page {
    ptr_at(seg.addr() + offset_of!(Segment, pages) + i * size_of::<Page>())
}

/// Índice (0..32) da página `page` no segmento dela.
fn page_index(page: *mut Page) -> usize {
    let first = seg_of(page).addr() + offset_of!(Segment, pages);
    (page.addr() - first) / size_of::<Page>()
}

/// Endereço do primeiro byte de dados da página.
fn page_start(page: *mut Page) -> usize {
    seg_of(page).addr() + page_index(page) * PAGE_SIZE
}

/// Palavra do bitmap da página que cobre o bloco `idx`.
fn bit_word(page: *mut Page, idx: usize) -> *mut u64 {
    let words = page_index(page) * BITS_WORDS + idx / 64;
    ptr_at(seg_of(page).addr() + offset_of!(Segment, bits) + words * size_of::<u64>())
}

/// Embaralhador de 64 bits (final do `SplitMix64`).
const fn mix(x: usize) -> usize {
    let mut z = (x as u64).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    (z ^ (z >> 31)) as usize
}

fn canary_for(segment_addr: usize, secret: usize) -> u64 {
    mix(segment_addr ^ secret) as u64
}

/// Índice do bloco que começa em `addr` na página, ou `None` se `addr` não
/// for início de bloco dela. Só lê campos que valem para qualquer thread
/// (INV-R).
fn block_index(page: *mut Page, addr: usize) -> Option<usize> {
    // SAFETY: INV-R: `page` está num segmento vivo (conferido por `locate`
    // ou vindo das listas do dono) e esses campos não mudam com blocos
    // entregues.
    let (kind, bsize, recip, cap) =
        unsafe { ((*page).kind, (*page).bsize, (*page).recip, (*page).cap) };
    let off = addr.wrapping_sub(page_start(page));
    if kind != KIND_SMALL {
        return (off == 0).then_some(0);
    }
    if off >= PAGE_SIZE {
        return None;
    }
    let idx = ((off as u64 * u64::from(recip)) >> 32) as usize;
    (idx < cap as usize && idx * bsize as usize == off).then_some(idx)
}

/// Lista dupla intrusiva de páginas.
#[derive(Clone, Copy)]
struct List {
    head: *mut Page,
    tail: *mut Page,
}

impl List {
    const EMPTY: Self = Self {
        head: null_mut(),
        tail: null_mut(),
    };

    fn push_front(&mut self, page: *mut Page) {
        // SAFETY: INV-S: `page` e os vizinhos são páginas do dono; a
        // página não estava em lista nenhuma.
        unsafe {
            (*page).prev = null_mut();
            (*page).next = self.head;
            if self.head.is_null() {
                self.tail = page;
            } else {
                (*self.head).prev = page;
            }
            self.head = page;
        }
    }

    fn unlink(&mut self, page: *mut Page) {
        // SAFETY: INV-S: `page` está nesta lista, e os vizinhos também.
        unsafe {
            let (prev, next) = ((*page).prev, (*page).next);
            if prev.is_null() {
                self.head = next;
            } else {
                (*prev).next = next;
            }
            if next.is_null() {
                self.tail = prev;
            } else {
                (*next).prev = prev;
            }
            (*page).prev = null_mut();
            (*page).next = null_mut();
        }
    }
}

/// As duas listas de páginas de uma classe.
#[derive(Clone, Copy)]
struct Lists {
    /// Páginas com espaço (ou que ainda podem ter): a primeira é a atual.
    avail: List,
    /// Páginas que estavam sem espaço quando foram vistas.
    full: List,
}

impl Lists {
    const EMPTY: Self = Self {
        avail: List::EMPTY,
        full: List::EMPTY,
    };
}

/// Estado compartilhado por todos os heaps de uma fonte: a fonte, a pilha de
/// segmentos abandonados, o gerador de ids e o segredo do endurecimento.
pub struct Global<S: PageSource> {
    source: S,
    abandoned: AtomicPtr<Segment>,
    next_id: AtomicUsize,
    secret: AtomicUsize,
    mapped: AtomicUsize,
}

impl<S: PageSource> Global<S> {
    /// Estado novo sobre `source`.
    #[must_use]
    pub const fn new(source: S) -> Self {
        Self {
            source,
            abandoned: AtomicPtr::new(null_mut()),
            next_id: AtomicUsize::new(0),
            secret: AtomicUsize::new(0),
            mapped: AtomicUsize::new(0),
        }
    }

    /// A fonte de páginas.
    #[must_use]
    pub const fn source(&self) -> &S {
        &self.source
    }

    /// Segmentos que os heaps desta fonte têm mapeados agora (inclui os
    /// abandonados que ninguém adotou).
    #[must_use]
    pub fn mapped_segments(&self) -> usize {
        self.mapped.load(Relaxed)
    }
}

/// Contagens de um heap (percorre os segmentos dele; não é caminho quente).
///
/// Os blocos que outras threads liberaram só saem da conta quando o dono os
/// recolhe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Segmentos do heap.
    pub segments: usize,
    /// Bytes mapeados nesses segmentos.
    pub mapped_bytes: usize,
    /// Páginas de 64 KiB em uso (uma por classe, várias nos blocos grandes).
    pub pages: usize,
    /// Blocos entregues.
    pub live_blocks: usize,
    /// Bytes desses blocos, com o arredondamento da classe.
    pub live_bytes: usize,
}

/// O heap de uma thread. Não é `Send`: nasce e morre na thread que o usa.
/// Liberar um bloco de outro heap da mesma [`Global`] é permitido
/// ([`Heap::free`]).
pub struct Heap<'g, S: PageSource> {
    global: &'g Global<S>,
    id: usize,
    key: usize,
    /// Lista dos segmentos do heap.
    segments: *mut Segment,
    /// Segmentos da lista sem página em uso (no máximo um, fora o `trim`).
    empty_segments: usize,
    lists: [Lists; NUM_LISTS],
}

impl<'g, S: PageSource> Heap<'g, S> {
    /// Heap novo, sem memória ainda.
    #[must_use]
    pub fn new(global: &'g Global<S>) -> Self {
        let id = global.next_id.fetch_add(1, Relaxed) + 1;
        if global.secret.load(Relaxed) == 0 {
            let s = mix(global.source.seed() as usize ^ 0x5eed) | 1;
            // Se outra thread chegou antes, vale o segredo dela.
            let _ = global.secret.compare_exchange(0, s, Relaxed, Relaxed);
        }
        let key = mix(global.secret.load(Relaxed) ^ id.rotate_left(32));
        Self {
            global,
            id,
            key,
            segments: null_mut(),
            empty_segments: 0,
            lists: [Lists::EMPTY; NUM_LISTS],
        }
    }

    fn fault(&self, fault: Fault) -> ! {
        self.global.source.fault(fault)
    }

    /// Aloca `size` bytes alinhados a `align` (potência de dois até 64 KiB).
    /// Devolve nulo se a memória acabou ou se o pedido não é atendido. O
    /// conteúdo é indefinido.
    pub fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        match plan(size, align) {
            Plan::Small(c) => self.alloc_small(c),
            Plan::Large(n) => self.alloc_large(n),
            Plan::Huge(n) => self.alloc_huge(n),
            Plan::Fail => null_mut(),
        }
    }

    /// Devolve o bloco `ptr`, que pode ter vindo de outro heap da mesma
    /// [`Global`] (nesse caso ele entra na `thread_free` da página e o dono
    /// o recolhe). Ponteiro nulo não faz nada. Liberação dupla e ponteiro
    /// que não é início de bloco chamam [`PageSource::fault`].
    ///
    /// # Safety
    ///
    /// `ptr` é nulo ou veio de [`alloc`](Self::alloc) de um heap desta
    /// [`Global`], ainda não foi liberado, e ninguém mais o usa (INV-B).
    pub unsafe fn free(&mut self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }
        let page = self.locate(ptr);
        // SAFETY: `locate` conferiu que o segmento é nosso e está vivo.
        let mine = unsafe { (*seg_of(page)).owner.load(Relaxed) } == self.id;
        if mine {
            self.free_local(page, ptr.addr());
        } else {
            self.free_remote(page, ptr.addr());
        }
    }

    /// Recolhe o que outras threads liberaram, devolve páginas ociosas e
    /// deixa no máximo um segmento vazio.
    pub fn collect(&mut self) {
        for li in 0..NUM_LISTS {
            for full in [false, true] {
                let mut page = self.list(li, full).head;
                while !page.is_null() {
                    // SAFETY: INV-S.
                    let next = unsafe { (*page).next };
                    self.collect_page(page);
                    // SAFETY: INV-S.
                    let (used, space) = unsafe { ((*page).used, has_space(page)) };
                    if used == 0 {
                        self.list(li, full).unlink(page);
                        self.retire_page(page);
                    } else if full && li < NUM_CLASSES && space {
                        self.list(li, true).unlink(page);
                        // SAFETY: INV-S.
                        unsafe { (*page).full = false };
                        self.lists[li].avail.push_front(page);
                    }
                    page = next;
                }
            }
        }
    }

    /// [`collect`](Self::collect) e devolve à fonte todos os segmentos vazios.
    pub fn trim(&mut self) {
        self.collect();
        let mut seg = self.segments;
        while !seg.is_null() {
            // SAFETY: INV-S.
            let (next, used) = unsafe { ((*seg).next, (*seg).used_pages) };
            if used == 0 {
                self.free_segment(seg);
                self.empty_segments -= 1;
            }
            seg = next;
        }
    }

    /// Adota os segmentos que heaps encerrados abandonaram com blocos
    /// vivos; devolve quantos. Os blocos liberados desde então são
    /// recolhidos, e o que ficou ocioso volta à fonte.
    pub fn adopt(&mut self) -> usize {
        let mut seg = self.global.abandoned.swap(null_mut(), Acquire);
        let mut n = 0;
        while !seg.is_null() {
            // SAFETY: o `swap` deu o segmento a este heap sozinho; o
            // `Release` de quem abandonou publicou os campos.
            let next = unsafe { (*seg).abandoned_next };
            self.adopt_segment(seg);
            n += 1;
            seg = next;
        }
        n
    }

    /// Contagens do heap.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let mut st = Stats::default();
        let mut seg = self.segments;
        while !seg.is_null() {
            // SAFETY: INV-S.
            unsafe {
                st.segments += (*seg).count;
                st.mapped_bytes += (*seg).count * SEGMENT_SIZE;
                for i in 1..PAGES_PER_SEGMENT {
                    let p = page_at(seg, i);
                    match (*p).kind {
                        KIND_SMALL => {
                            st.pages += 1;
                            st.live_blocks += (*p).used as usize;
                            st.live_bytes += (*p).used as usize * (*p).bsize as usize;
                        }
                        KIND_LARGE => {
                            st.pages += usize::from((*p).npages);
                            st.live_blocks += (*p).used as usize;
                            st.live_bytes += (*p).used as usize * (*p).bsize as usize;
                        }
                        KIND_HUGE => {
                            st.live_blocks += (*p).used as usize;
                            st.live_bytes +=
                                (*p).used as usize * ((*seg).count * SEGMENT_SIZE - PAGE_SIZE);
                        }
                        _ => {}
                    }
                }
                seg = (*seg).next;
            }
        }
        st
    }

    fn list(&mut self, li: usize, full: bool) -> &mut List {
        if full {
            &mut self.lists[li].full
        } else {
            &mut self.lists[li].avail
        }
    }

    // ---- alocação ----

    fn alloc_small(&mut self, c: usize) -> *mut u8 {
        let page = self.lists[c].avail.head;
        if !page.is_null() {
            let block = self.pop_block(page);
            if !block.is_null() {
                return block;
            }
        }
        self.alloc_small_slow(c)
    }

    fn alloc_small_slow(&mut self, c: usize) -> *mut u8 {
        let mut adopted = false;
        loop {
            let page = self.lists[c].avail.head;
            if !page.is_null() {
                self.collect_page(page);
                let block = self.pop_block(page);
                if !block.is_null() {
                    return block;
                }
                // Sem espaço: sai da lista dos disponíveis.
                self.lists[c].avail.unlink(page);
                // SAFETY: INV-S.
                unsafe { (*page).full = true };
                self.lists[c].full.push_front(page);
                continue;
            }
            if self.reclaim(c) {
                continue;
            }
            if !adopted {
                adopted = true;
                if self.adopt() > 0 {
                    continue;
                }
            }
            let page = self.new_small_page(c);
            if page.is_null() {
                return null_mut();
            }
            self.lists[c].avail.push_front(page);
        }
    }

    /// Tira um bloco da página; nulo se ela não tem (depois de recolher, o
    /// chamador decide).
    fn pop_block(&self, page: *mut Page) -> *mut u8 {
        // SAFETY: INV-S, INV-B: `page` é do dono; o bloco da lista livre é
        // dele (os blocos livres pertencem ao alocador) e está no
        // intervalo da página, o que `block_index` confere antes de usar.
        unsafe {
            let free = (*page).free;
            if free != 0 {
                let idx = match block_index(page, free) {
                    Some(idx) if idx < (*page).bump as usize => idx,
                    _ => self.fault(Fault::Corrupted),
                };
                let block = ptr_at::<u8>(free);
                let next = ptr_at::<usize>(free).read() ^ (*page).key;
                if next != 0 && block_index(page, next).is_none_or(|i| i >= (*page).bump as usize) {
                    self.fault(Fault::Corrupted);
                }
                let (word, mask) = (bit_word(page, idx), 1u64 << (idx % 64));
                if *word & mask == 0 || (*page).used >= (*page).cap {
                    self.fault(Fault::Corrupted);
                }
                *word &= !mask;
                (*page).free = next;
                (*page).used += 1;
                // Não deixa o elo (endereço codificado) com quem recebe.
                ptr_at::<usize>(free).write(0);
                return block;
            }
            if (*page).bump < (*page).cap {
                let addr = page_start(page) + (*page).bump as usize * (*page).bsize as usize;
                (*page).bump += 1;
                (*page).used += 1;
                return ptr_at::<u8>(addr);
            }
        }
        null_mut()
    }

    fn new_small_page(&mut self, c: usize) -> *mut Page {
        let page = self.take_pages(1);
        if page.is_null() {
            return page;
        }
        let bsize = class_size(c);
        let key = mix(self.key ^ page.addr());
        // SAFETY: INV-S: `take_pages` deu uma página livre deste heap; as
        // palavras do bitmap que o `cap` usa são do dono.
        unsafe {
            let cap = PAGE_SIZE / bsize;
            *page = Page::new();
            (*page).key = key;
            (*page).kind = KIND_SMALL;
            (*page).class = c as u8;
            (*page).bsize = bsize as u32;
            (*page).recip = (u64::from(u32::MAX) / bsize as u64 + 1) as u32;
            (*page).cap = cap as u32;
            for w in 0..cap.div_ceil(64) {
                bit_word(page, w * 64).write(0);
            }
        }
        page
    }

    fn alloc_large(&mut self, n: usize) -> *mut u8 {
        let page = self.take_pages(n);
        if page.is_null() {
            return null_mut();
        }
        let key = mix(self.key ^ page.addr());
        let seg = seg_of(page);
        let first = page_index(page);
        // SAFETY: INV-S: as `n` páginas são livres e contíguas, do dono.
        unsafe {
            *page = Page::new();
            (*page).key = key;
            (*page).kind = KIND_LARGE;
            (*page).npages = n as u8;
            (*page).bsize = (n * PAGE_SIZE) as u32;
            (*page).cap = 1;
            (*page).bump = 1;
            (*page).used = 1;
            (*page).full = true;
            for i in first + 1..first + n {
                (*page_at(seg, i)).kind = KIND_CONT;
            }
        }
        self.lists[LARGE_LIST].full.push_front(page);
        ptr_at::<u8>(page_start(page))
    }

    fn alloc_huge(&mut self, count: usize) -> *mut u8 {
        // Blocos enormes que outras threads liberaram só voltam quando o
        // dono os recolhe; faz isso antes de mapear mais.
        self.reclaim(HUGE_LIST);
        // Adotar segmentos abandonados devolve à fonte os que ficaram
        // ociosos, o que pode abrir espaço para este.
        self.adopt();
        let mut seg = self.new_segment(count);
        if seg.is_null() && self.reclaim(HUGE_LIST) {
            seg = self.new_segment(count);
        }
        if seg.is_null() {
            return null_mut();
        }
        let page = page_at(seg, 1);
        let key = mix(self.key ^ page.addr());
        // SAFETY: INV-S: segmento novo, do dono.
        unsafe {
            *page = Page::new();
            (*page).key = key;
            (*page).kind = KIND_HUGE;
            (*page).cap = 1;
            (*page).bump = 1;
            (*page).used = 1;
            (*page).full = true;
            for i in 2..PAGES_PER_SEGMENT {
                (*page_at(seg, i)).kind = KIND_CONT;
            }
            (*seg).free_pages = 0;
            (*seg).used_pages = 1;
        }
        self.lists[HUGE_LIST].full.push_front(page);
        ptr_at::<u8>(page_start(page))
    }
}

// ---- liberação, recolhimento e devolução de páginas ----
impl<S: PageSource> Heap<'_, S> {
    /// Acha a página do bloco `ptr` e confere que ele pode ser liberado
    /// (segmento nosso, página em uso); senão chama a falha.
    fn locate(&self, ptr: *mut u8) -> *mut Page {
        let addr = ptr.addr();
        if !addr.is_multiple_of(8) || !self.global.source.owns(addr) {
            self.fault(Fault::ForeignPointer);
        }
        let seg = seg_of(ptr);
        let index = (addr - seg.addr()) / PAGE_SIZE;
        if index == 0 {
            self.fault(Fault::ForeignPointer);
        }
        let expected = canary_for(seg.addr(), self.global.secret.load(Relaxed));
        // SAFETY: `owns` garante que `addr` está num segmento vivo (INV-F),
        // então o início do segmento, que é o cabeçalho ou, no meio de um
        // bloco enorme, um pedaço dele, é legível; só lemos campos que não
        // mudam (INV-R).
        unsafe {
            if (*seg).magic != MAGIC || (*seg).canary != expected {
                self.fault(Fault::ForeignPointer);
            }
            let page = page_at(seg, index);
            match (*page).kind {
                KIND_SMALL | KIND_LARGE | KIND_HUGE => page,
                KIND_FREE => self.fault(Fault::DoubleFree),
                _ => self.fault(Fault::ForeignPointer),
            }
        }
    }

    fn free_local(&mut self, page: *mut Page, addr: usize) {
        // SAFETY: INV-S: `locate` achou a página num segmento do dono.
        if unsafe { (*page).kind } == KIND_SMALL {
            self.free_small(page, addr);
        } else {
            self.free_big(page, addr);
        }
    }

    fn free_small(&mut self, page: *mut Page, addr: usize) {
        let Some(idx) = block_index(page, addr) else {
            self.fault(Fault::ForeignPointer)
        };
        // SAFETY: INV-S, INV-B: página do dono; o bloco foi entregue e agora
        // volta, então o alocador pode gravar o elo nele.
        let (class, full, used, alone) = unsafe {
            if idx >= (*page).bump as usize {
                self.fault(Fault::ForeignPointer);
            }
            let (word, mask) = (bit_word(page, idx), 1u64 << (idx % 64));
            if *word & mask != 0 {
                self.fault(Fault::DoubleFree);
            }
            if (*page).used == 0 {
                self.fault(Fault::Corrupted);
            }
            *word |= mask;
            ptr_at::<usize>(addr).write((*page).local_free ^ (*page).key);
            (*page).local_free = addr;
            (*page).used -= 1;
            (
                usize::from((*page).class),
                (*page).full,
                (*page).used,
                (*page).prev.is_null() && (*page).next.is_null(),
            )
        };
        if full {
            // Voltou a ter espaço.
            self.lists[class].full.unlink(page);
            // SAFETY: INV-S.
            unsafe { (*page).full = false };
            self.lists[class].avail.push_front(page);
        } else if used == 0 && !alone {
            // Ociosa, e há outra página da classe: devolve ao segmento. A
            // última fica, para não alternar entre pedir e devolver.
            self.lists[class].avail.unlink(page);
            self.retire_page(page);
        }
    }

    fn free_big(&mut self, page: *mut Page, addr: usize) {
        if block_index(page, addr).is_none() {
            self.fault(Fault::ForeignPointer);
        }
        // SAFETY: INV-S: página do dono.
        let li = unsafe {
            // Uma liberação remota já empilhada também conta como dupla.
            if (*page).used != 1 || (*page).thread_free.load(Relaxed) != 0 {
                self.fault(Fault::DoubleFree);
            }
            (*page).used = 0;
            (*page).full = false;
            if (*page).kind == KIND_LARGE {
                LARGE_LIST
            } else {
                HUGE_LIST
            }
        };
        self.lists[li].full.unlink(page);
        self.retire_page(page);
    }

    /// Liberação por quem não é dono: empilha o bloco na `thread_free`.
    fn free_remote(&self, page: *mut Page, addr: usize) {
        if block_index(page, addr).is_none() {
            self.fault(Fault::ForeignPointer);
        }
        // SAFETY: INV-R, INV-B: só escreve no bloco, que é de quem libera, e
        // na pilha atômica; a `key` não muda com blocos entregues.
        unsafe {
            let key = (*page).key;
            let head = &(*page).thread_free;
            let mut old = head.load(Relaxed);
            loop {
                ptr_at::<usize>(addr).write(old ^ key);
                match head.compare_exchange_weak(old, addr, Release, Relaxed) {
                    Ok(_) => break,
                    Err(seen) => old = seen,
                }
            }
        }
    }

    /// Passa os blocos de `thread_free` para `local_free` (conferindo cada
    /// um) e, se `free` estiver vazia, a promove.
    fn collect_page(&self, page: *mut Page) {
        // SAFETY: INV-S, INV-B: página do dono; o `Acquire` do `swap` vê os
        // elos que os `Release` das outras threads gravaram; cada bloco da
        // pilha foi liberado (é do alocador).
        unsafe {
            let mut head = (*page).thread_free.swap(0, Acquire);
            let key = (*page).key;
            let small = (*page).kind == KIND_SMALL;
            while head != 0 {
                let Some(idx) = block_index(page, head) else {
                    self.fault(Fault::Corrupted)
                };
                if idx >= (*page).bump as usize {
                    self.fault(Fault::ForeignPointer);
                }
                if small {
                    let (word, mask) = (bit_word(page, idx), 1u64 << (idx % 64));
                    if *word & mask != 0 {
                        self.fault(Fault::DoubleFree);
                    }
                    *word |= mask;
                }
                if (*page).used == 0 {
                    self.fault(Fault::Corrupted);
                }
                let block = ptr_at::<usize>(head);
                let next = block.read() ^ key;
                block.write((*page).local_free ^ key);
                (*page).local_free = head;
                (*page).used -= 1;
                head = next;
            }
            if (*page).free == 0 {
                (*page).free = (*page).local_free;
                (*page).local_free = 0;
            }
        }
    }

    /// Examina páginas cheias da lista `li` atrás de blocos que outras
    /// threads liberaram. Nas classes olha só algumas (`RECLAIM_SCAN`) e
    /// devolve `true` se uma página voltou a ter espaço; nas listas de
    /// blocos grandes e enormes, que só são consultadas antes de mapear
    /// memória nova, olha todas e devolve `true` se algo foi devolvido.
    fn reclaim(&mut self, li: usize) -> bool {
        let big = li >= NUM_CLASSES;
        let mut found = false;
        let mut stop = null_mut::<Page>();
        let mut budget = if big { usize::MAX } else { RECLAIM_SCAN };
        while budget > 0 {
            budget -= 1;
            let page = self.lists[li].full.tail;
            if page.is_null() || page == stop {
                break;
            }
            self.lists[li].full.unlink(page);
            self.collect_page(page);
            // SAFETY: INV-S.
            let (used, space) = unsafe { ((*page).used, has_space(page)) };
            if used == 0 {
                self.retire_page(page);
                found |= big;
            } else if !big && space {
                // SAFETY: INV-S.
                unsafe { (*page).full = false };
                self.lists[li].avail.push_front(page);
                return true;
            } else {
                // Volta para a frente da fila; `stop` marca a primeira, para
                // não dar a volta completa.
                self.lists[li].full.push_front(page);
                if stop.is_null() {
                    stop = page;
                }
            }
        }
        found
    }

    // ---- páginas e segmentos ----

    /// Devolve a página (ou as páginas do bloco grande) ao segmento. A
    /// página já saiu das listas e não tem blocos entregues.
    fn retire_page(&mut self, page: *mut Page) {
        let seg = seg_of(page);
        // SAFETY: INV-S.
        let (kind, npages) = unsafe { ((*page).kind, usize::from((*page).npages)) };
        if kind == KIND_HUGE {
            self.free_segment(seg);
            return;
        }
        Self::release_pages(
            seg,
            page_index(page),
            if kind == KIND_LARGE { npages } else { 1 },
        );
        self.settle(seg);
    }

    fn release_pages(seg: *mut Segment, first: usize, n: usize) {
        // SAFETY: INV-S: as `n` páginas são do segmento do dono e estão sem
        // blocos entregues.
        unsafe {
            for i in first..first + n {
                let p = page_at(seg, i);
                (*p).kind = KIND_FREE;
                (*p).npages = 0;
                (*p).full = false;
            }
            (*seg).free_pages |= ((1u32 << n) - 1) << first;
            (*seg).used_pages -= n as u32;
        }
    }

    /// Segmento que ficou sem página em uso: guarda um, devolve os demais.
    fn settle(&mut self, seg: *mut Segment) {
        // SAFETY: INV-S.
        if unsafe { (*seg).used_pages } != 0 {
            return;
        }
        if self.empty_segments >= 1 {
            self.free_segment(seg);
        } else {
            self.empty_segments = 1;
        }
    }

    /// Procura `n` páginas contíguas livres nos segmentos do heap.
    fn find_pages(&mut self, n: usize) -> *mut Page {
        let want = (1u32 << n) - 1;
        let mut seg = self.segments;
        while !seg.is_null() {
            // SAFETY: INV-S.
            let (free, next) = unsafe { ((*seg).free_pages, (*seg).next) };
            if free.count_ones() as usize >= n {
                for first in 1..=PAGES_PER_SEGMENT - n {
                    if (free >> first) & want == want {
                        return self.claim(seg, first, n);
                    }
                }
            }
            seg = next;
        }
        null_mut()
    }

    fn claim(&mut self, seg: *mut Segment, first: usize, n: usize) -> *mut Page {
        // SAFETY: INV-S.
        unsafe {
            if (*seg).used_pages == 0 {
                self.empty_segments -= 1;
            }
            (*seg).free_pages &= !(((1u32 << n) - 1) << first);
            (*seg).used_pages += n as u32;
        }
        page_at(seg, first)
    }

    /// `n` páginas contíguas (`1 <= n <= 8`), de um segmento do heap ou de
    /// um segmento novo.
    fn take_pages(&mut self, n: usize) -> *mut Page {
        let mut page = self.find_pages(n);
        if page.is_null() {
            // Antes de pedir memória nova, recolhe os blocos grandes e
            // enormes que outras threads liberaram.
            self.reclaim(LARGE_LIST);
            self.reclaim(HUGE_LIST);
            page = self.find_pages(n);
        }
        if page.is_null() && self.adopt() > 0 {
            // Segmentos abandonados por heaps encerrados podem ter espaço.
            page = self.find_pages(n);
        }
        if page.is_null() {
            let seg = self.new_segment(1);
            if seg.is_null() {
                return null_mut();
            }
            self.empty_segments += 1;
            page = self.claim(seg, 1, n);
        }
        page
    }

    /// Pede `count` segmentos à fonte e põe a lista de segmentos do heap.
    fn new_segment(&mut self, count: usize) -> *mut Segment {
        let base = self.global.source.alloc_segments(count);
        if base.is_null() {
            return null_mut();
        }
        // Daqui em diante, todo acesso ao segmento parte do endereço (ver
        // `ptr_at`).
        let _ = base.expose_provenance();
        self.global.mapped.fetch_add(count, Relaxed);
        let seg = ptr_at::<Segment>(base.addr());
        let canary = canary_for(base.addr(), self.global.secret.load(Relaxed));
        // SAFETY: INV-F: a faixa é nossa, gravável e alinhada; só gravamos
        // (campo a campo, sem criar referência para o cabeçalho, que ainda
        // não está inicializado).
        unsafe {
            (&raw mut (*seg).magic).write(MAGIC);
            (&raw mut (*seg).canary).write(canary);
            (&raw mut (*seg).owner).write(AtomicUsize::new(self.id));
            (&raw mut (*seg).prev).write(null_mut());
            (&raw mut (*seg).next).write(self.segments);
            (&raw mut (*seg).abandoned_next).write(null_mut());
            (&raw mut (*seg).count).write(count);
            (&raw mut (*seg).free_pages).write(!1u32);
            (&raw mut (*seg).used_pages).write(0);
            for i in 0..PAGES_PER_SEGMENT {
                page_at(seg, i).write(Page::new());
            }
            if !self.segments.is_null() {
                (*self.segments).prev = seg;
            }
        }
        self.segments = seg;
        seg
    }

    /// Tira o segmento da lista e o devolve à fonte.
    fn free_segment(&mut self, seg: *mut Segment) {
        // SAFETY: INV-S: o segmento é do dono e não tem página em uso; o
        // `count` e os vizinhos são lidos antes de devolver a faixa.
        let (prev, next, count) = unsafe { ((*seg).prev, (*seg).next, (*seg).count) };
        // SAFETY: INV-S: os vizinhos são segmentos do dono.
        unsafe {
            if prev.is_null() {
                self.segments = next;
            } else {
                (*prev).next = next;
            }
            if !next.is_null() {
                (*next).prev = prev;
            }
        }
        self.global.mapped.fetch_sub(count, Relaxed);
        // SAFETY: `seg` veio de `alloc_segments(count)` e nada mais o usa:
        // as páginas estão livres e o segmento saiu da lista.
        unsafe {
            self.global
                .source
                .free_segments(ptr_at::<u8>(seg.addr()), count);
        }
    }

    // ---- threads que saem e adoção ----

    /// Entrega à pilha de abandonados os segmentos que ainda têm blocos.
    fn abandon(&mut self) {
        self.lists = [Lists::EMPTY; NUM_LISTS];
        self.empty_segments = 0;
        let mut seg = core::mem::replace(&mut self.segments, null_mut());
        while !seg.is_null() {
            // SAFETY: INV-S até o `owner = 0`; depois do `compare_exchange`
            // o segmento é de quem adotar e não o tocamos mais.
            unsafe {
                let next = (*seg).next;
                (*seg).prev = null_mut();
                (*seg).next = null_mut();
                (*seg).owner.store(0, Release);
                let mut head = self.global.abandoned.load(Relaxed);
                loop {
                    (*seg).abandoned_next = head;
                    match self
                        .global
                        .abandoned
                        .compare_exchange_weak(head, seg, Release, Relaxed)
                    {
                        Ok(_) => break,
                        Err(seen) => head = seen,
                    }
                }
                seg = next;
            }
        }
    }

    fn adopt_segment(&mut self, seg: *mut Segment) {
        // SAFETY: o segmento acaba de sair da pilha, sem dono; passa a ser
        // deste heap (INV-S).
        unsafe {
            (*seg).owner.store(self.id, Relaxed);
            (*seg).abandoned_next = null_mut();
            (*seg).prev = null_mut();
            (*seg).next = self.segments;
            if !self.segments.is_null() {
                (*self.segments).prev = seg;
            }
        }
        self.segments = seg;
        let mut i = 1;
        while i < PAGES_PER_SEGMENT {
            let page = page_at(seg, i);
            // SAFETY: INV-S.
            let (kind, npages) = unsafe { ((*page).kind, usize::from((*page).npages)) };
            i += 1;
            if !matches!(kind, KIND_SMALL | KIND_LARGE | KIND_HUGE) {
                continue;
            }
            if kind == KIND_LARGE {
                i += npages - 1;
            }
            // SAFETY: INV-S.
            unsafe {
                (*page).prev = null_mut();
                (*page).next = null_mut();
            }
            self.collect_page(page);
            // SAFETY: INV-S.
            let (used, space, class) =
                unsafe { ((*page).used, has_space(page), usize::from((*page).class)) };
            if used == 0 {
                if kind == KIND_HUGE {
                    self.free_segment(seg);
                    return;
                }
                Self::release_pages(
                    seg,
                    page_index(page),
                    if kind == KIND_LARGE { npages } else { 1 },
                );
            } else if kind == KIND_SMALL && space {
                // SAFETY: INV-S.
                unsafe { (*page).full = false };
                self.lists[class].avail.push_front(page);
            } else {
                let li = match kind {
                    KIND_SMALL => class,
                    KIND_LARGE => LARGE_LIST,
                    _ => HUGE_LIST,
                };
                // SAFETY: INV-S.
                unsafe { (*page).full = true };
                self.lists[li].full.push_front(page);
            }
        }
        self.settle(seg);
    }
}

impl<S: PageSource> Drop for Heap<'_, S> {
    /// Devolve o que está ocioso e abandona os segmentos com blocos vivos
    /// (outro heap os adota; ver [`Heap::adopt`]).
    fn drop(&mut self) {
        self.trim();
        self.abandon();
    }
}

/// A página ainda tem como entregar um bloco (depois de `collect_page`).
fn has_space(page: *mut Page) -> bool {
    // SAFETY: INV-S: quem chama passa uma página do dono.
    unsafe { (*page).free != 0 || (*page).bump < (*page).cap }
}
