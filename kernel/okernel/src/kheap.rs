//! Heap do kernel (T-108): o slab de `okernel::mm::slab` sobre frames do
//! buddy, como `GlobalAlloc` da crate `alloc`.
//!
//! As páginas do heap ficam na faixa de objetos e slabs do kernel da seção
//! 6.4 do SDD (`0xFFFF_C000_0000_0000`), não no mapa direto: cada bloco do
//! buddy é mapeado em `janela + físico` (o alinhamento do bloco vale nos
//! dois) e desmapeado quando volta, então um ponteiro do heap não revela a
//! base do mapa direto (ADR 0026) e um bloco solto deixa de ser acessível
//! pela janela. A janela é sorteada no boot em passos de 1 GiB, como o mapa
//! direto: cerca de 15 bits em 32 TiB.
//!
//! Mapear toma `KernelPageTables`, que vem **antes** de `Heap` na ordem de
//! travas (ADR 0031): nada se mapeia com o heap trancado. Sem bloco
//! mapeado, a fonte recusa o pedido e anota a ordem ([`PageSource::deferred`]);
//! [`with_growth`] solta a trava, mapeia um bloco e tenta de novo. Os blocos
//! soltos com a trava na mão vão para uma lista e são desmapeados (com
//! shootdown) e devolvidos ao buddy por [`with_heap`], já sem ela. O último
//! bloco solto de cada ordem até [`KEEP_ORDER`] fica mapeado para o próximo
//! pedido. As tabelas de página da janela não voltam ao buddy.
//!
//! O limite vem de `kheap=<MiB>` na linha de comando (padrão
//! [`DEFAULT_LIMIT_MIB`]). Acima dele, `alloc` devolve nulo; as coleções da
//! `alloc` transformam isso em pânico, então o código que pode esbarrar no
//! limite usa as APIs falíveis (`try_reserve`, [`try_alloc`]). Tratadores de
//! interrupção não alocam: a trava do heap não desliga interrupções.
//!
//! Objetos de até 2048 bytes passam pelo cache de objetos da CPU (T-328,
//! `okernel::mm::cache`): sem trava, uma pilha por classe do slab, e a
//! trava do heap só para trazer ou devolver um lote. Um objeto parado no
//! cache conta como alocado para o slab; [`live_blocks`] o desconta. Na
//! liberação, o cache só confere a posição do objeto no slab; a conferência
//! completa (cabeçalho e contagem) acontece quando o lote volta ao slab.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use okernel::mm::PhysAddr;
use okernel::mm::buddy::MAX_ORDER;
use okernel::mm::cache::OBJECT_BATCH;
use okernel::mm::paging::Flags;
use okernel::mm::slab::{CLASSES, Heap, HeapError, PageSource, class, plausible};
use okernel::sync::{LockClass, SpinLock};

use crate::arch::x86_64::percpu;
use crate::{kmem, krand, ksmp};

mod tests;
pub use tests::TESTS;

/// Limite padrão do heap, em MiB.
pub const DEFAULT_LIMIT_MIB: u64 = 32;

/// Faixa de objetos e slabs do kernel (SDD v1.0, seção 6.4), até a de
/// áreas por CPU e pilhas.
pub const WINDOW_START: u64 = 0xffff_c000_0000_0000;
pub const WINDOW_END: u64 = 0xffff_e000_0000_0000;
const GIB: u64 = 1 << 30;
/// Ordens cujo último bloco solto fica mapeado (as dos slabs e a de 8 KiB).
const KEEP_ORDER: usize = 2;
/// Frames que podem ficar mapeados e livres na fonte: um bloco por ordem
/// até [`KEEP_ORDER`].
pub const KEPT_FRAMES: u64 = (2 << KEEP_ORDER) - 1;
/// Tentativas de mapear e repetir antes de desistir (outra CPU pode levar
/// o bloco preparado).
const GROW_TRIES: usize = 4;

/// Endereço virtual do físico 0 na janela; zero antes de [`init`].
static WINDOW_BASE: AtomicU64 = AtomicU64::new(0);
/// Tabelas de página criadas para a janela (não voltam ao buddy).
static WINDOW_TABLES: AtomicU64 = AtomicU64::new(0);

/// Blocos do buddy mapeados na janela.
struct WindowPages {
    /// Um bloco mapeado e livre por ordem, ou zero.
    ready: [u64; MAX_ORDER + 1],
    /// Ordem do último pedido recusado por falta de bloco mapeado.
    want: Option<usize>,
    /// Blocos a desmapear depois de soltar a trava, encadeados pela
    /// primeira palavra; a segunda guarda a ordem.
    retired: u64,
}

impl WindowPages {
    fn retire(&mut self, addr: u64, order: usize) {
        self.write(addr, self.retired);
        self.write(addr + 8, order as u64);
        self.retired = addr;
    }

    /// Manda desmapear os blocos prontos que não são de ordem guardada (um
    /// pedido grande que mudou de ideia não segura memória fora do limite).
    fn trim(&mut self) {
        for order in KEEP_ORDER + 1..=MAX_ORDER {
            let addr = core::mem::take(&mut self.ready[order]);
            if addr != 0 {
                self.retire(addr, order);
            }
        }
    }
}

impl PageSource for WindowPages {
    fn alloc_pages(&mut self, order: usize) -> Option<u64> {
        let addr = core::mem::take(self.ready.get_mut(order)?);
        if addr == 0 {
            self.want = Some(order);
            return None;
        }
        // Zeradas como as pilhas de kernel (`kvm::zero_frame`): no TCG, uma
        // tradução velha que sobrasse na página deixaria lenta toda escrita
        // nos objetos dela.
        // SAFETY: bloco mapeado RW na janela por `grow` (ou guardado por
        // `free_pages`), `4096 << order` bytes, só do heap, sob a trava.
        unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096 << order) };
        Some(addr)
    }

    fn free_pages(&mut self, addr: u64, order: usize) {
        match self.ready.get_mut(order) {
            Some(slot) if order <= KEEP_ORDER && *slot == 0 => *slot = addr,
            _ => self.retire(addr, order),
        }
    }

    fn read(&mut self, addr: u64) -> u64 {
        // SAFETY: o slab só lê palavras alinhadas dentro de blocos que pegou
        // da fonte, mapeados RW na janela até voltarem ao buddy.
        unsafe { (addr as *const u64).read() }
    }

    fn write(&mut self, addr: u64, value: u64) {
        // SAFETY: idem; os blocos são do heap (ou da lista de soltos, ainda
        // mapeados), sob a trava `HEAP`.
        unsafe { (addr as *mut u64).write(value) }
    }

    fn deferred(&self) -> bool {
        self.want.is_some()
    }
}

static HEAP: SpinLock<Heap<WindowPages>> = SpinLock::with_class(
    LockClass::Heap,
    Heap::new(
        WindowPages {
            ready: [0; MAX_ORDER + 1],
            want: None,
            retired: 0,
        },
        0,
    ),
);
/// Cache de objetos por CPU ligado; desligar serve só para medir o ganho.
static CACHE_ON: AtomicBool = AtomicBool::new(true);

/// Alocador global do kernel.
struct KernelAllocator;

// SAFETY: devolve blocos alinhados a `layout`, de pelo menos `layout.size()`
// bytes, que não se sobrepõem a nenhum outro bloco vivo (garantia do slab e
// do buddy), ou nulo; `dealloc` só recebe o que `alloc` deu.
unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        try_alloc(layout).map_or(core::ptr::null_mut(), NonNull::as_ptr)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let addr = ptr.addr() as u64;
        let result = match class(layout) {
            Some(i) if CACHE_ON.load(Ordering::Relaxed) => free_cached(i, addr),
            _ => with_heap(|h| h.free(addr, layout)),
        };
        if let Err(e) = result {
            error!("okernel: heap: liberação inválida de {ptr:p}: {e:?}");
        }
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

/// Aloca sem pânico.
///
/// # Errors
///
/// Limite do heap, falta de memória ou pedido grande demais.
pub fn try_alloc(layout: Layout) -> Result<NonNull<u8>, HeapError> {
    let addr = with_growth(|| match class(layout) {
        Some(i) if CACHE_ON.load(Ordering::Relaxed) => alloc_cached(i, layout),
        _ => with_heap(|h| h.alloc(layout)),
    })?;
    NonNull::new(core::ptr::with_exposed_provenance_mut(
        usize::try_from(addr).unwrap_or(0),
    ))
    .ok_or(HeapError::OutOfMemory)
}

/// Um objeto da classe `i` pelo cache desta CPU; vazio, traz um lote do
/// slab (o primeiro pelo caminho normal, que dá o erro se não houver).
fn alloc_cached(i: usize, layout: Layout) -> Result<u64, HeapError> {
    percpu::with_object_cache(|c| {
        let m = &mut c[i];
        if let Some(addr) = m.pop() {
            return Ok(addr);
        }
        with_heap(|heap| {
            let first = heap.alloc(layout)?;
            m.refill(OBJECT_BATCH - 1, &mut || heap.alloc_class(i));
            Ok(first)
        })
    })
}

/// Devolve um objeto da classe `i` ao cache desta CPU; cheio, um lote volta
/// ao slab.
fn free_cached(i: usize, addr: u64) -> Result<(), HeapError> {
    if !plausible(i, addr) {
        return Err(HeapError::BadFree);
    }
    percpu::with_object_cache(|c| {
        let m = &mut c[i];
        if m.contains(addr) {
            return Err(HeapError::BadFree);
        }
        if m.push(addr) {
            return Ok(());
        }
        with_heap(|heap| {
            m.spill(OBJECT_BATCH, &mut |a| spill_one(heap, i, a));
            if m.push(addr) {
                Ok(())
            } else {
                heap.free_class(i, addr)
            }
        })
    })
}

/// Devolve ao slab todos os objetos do cache desta CPU.
pub fn drain_object_cache() {
    percpu::with_object_cache(|c| {
        if c.iter().all(okernel::mm::cache::Magazine::is_empty) {
            return;
        }
        with_heap(|heap| {
            for (i, m) in c.iter_mut().enumerate() {
                m.spill(usize::MAX, &mut |a| spill_one(heap, i, a));
            }
        });
    });
}

/// Devolve ao slab um objeto que estava no cache; aqui a liberação
/// inválida (que o cache não pega) aparece.
fn spill_one(heap: &mut Heap<WindowPages>, i: usize, addr: u64) {
    if let Err(e) = heap.free_class(i, addr) {
        error!("okernel: heap: liberação inválida de {addr:#x}: {e:?}");
    }
}

/// Roda `f` com o heap trancado e, já sem a trava, desmapeia e devolve ao
/// buddy os blocos que ele soltou.
fn with_heap<T>(f: impl FnOnce(&mut Heap<WindowPages>) -> T) -> T {
    let (out, retired) = {
        let mut heap = HEAP.lock();
        let out = f(&mut heap);
        (out, core::mem::take(&mut heap.pages().retired))
    };
    release(retired);
    out
}

/// Desmapeia (um shootdown por bloco) e devolve ao buddy a lista de
/// blocos soltos que começa em `block`.
fn release(mut block: u64) {
    let base = WINDOW_BASE.load(Ordering::Relaxed);
    while block != 0 {
        // SAFETY: a lista saiu da fonte sob a trava e agora é só nossa; o
        // bloco continua mapeado RW na janela até o `unmap_range`.
        let (next, order) = unsafe {
            let p = block as *const u64;
            (p.read(), p.add(1).read())
        };
        kmem::unmap_range(block, 1 << order);
        #[allow(clippy::cast_possible_truncation, reason = "ordem até MAX_ORDER")]
        kmem::free_frames(PhysAddr(block - base), order as usize);
        block = next;
    }
}

/// Repete `f` enquanto ele for recusado só por falta de bloco mapeado e a
/// janela conseguir crescer. A recusa adiada não foi contada pelo heap;
/// se o crescimento desiste, ela conta aqui, uma vez.
fn with_growth(mut f: impl FnMut() -> Result<u64, HeapError>) -> Result<u64, HeapError> {
    let mut grows = 0;
    for _ in 0..GROW_TRIES * 4 {
        let result = f();
        if !matches!(result, Err(HeapError::OutOfMemory)) {
            if grows != 0 {
                with_heap(|h| h.pages().trim());
            }
            return result;
        }
        // Sem pedido guardado, outra CPU que também faltou o levou e está
        // crescendo a janela: tentar de novo, em vez de dar a falta (o
        // `OutOfMemory` só vem da fonte vazia, que sempre deixa o pedido).
        let Some(order) = with_heap(|h| h.pages().want.take()) else {
            core::hint::spin_loop();
            continue;
        };
        if grows == GROW_TRIES || !grow(order) {
            break;
        }
        grows += 1;
    }
    with_heap(|h| {
        h.pages().want = None;
        h.pages().trim();
        h.count_failure();
    });
    Err(HeapError::OutOfMemory)
}

/// Mapeia na janela um bloco novo de `2^order` páginas e o deixa pronto
/// na fonte; `false` sem frames, sem tabela ou antes de [`init`].
fn grow(order: usize) -> bool {
    let base = WINDOW_BASE.load(Ordering::Relaxed);
    let Some(frame) = kmem::alloc_frames(order).filter(|_| base != 0) else {
        return false;
    };
    let (virt, pages) = (base + frame.0, 1 << order);
    let tables = kmem::map_range(virt, frame, pages, Flags::RW).inspect_err(|e| {
        error!("okernel: heap: mapeando {virt:#x}: {e:?}");
        kmem::unmap_range(virt, pages);
        kmem::free_frames(frame, order);
    });
    let Ok(tables) = tables else {
        return false;
    };
    WINDOW_TABLES.fetch_add(tables, Ordering::Relaxed);
    with_heap(|h| {
        let src = h.pages();
        match src.ready.get_mut(order) {
            Some(slot) if *slot == 0 => *slot = virt,
            _ => src.retire(virt, order),
        }
    });
    true
}

/// Base da janela do heap (o endereço do físico 0 nela).
pub fn window_base() -> u64 {
    WINDOW_BASE.load(Ordering::Relaxed)
}

/// Tabelas de página que a janela já criou.
pub fn window_tables() -> u64 {
    WINDOW_TABLES.load(Ordering::Relaxed)
}

/// Base da janela para o sorteio `r`, com RAM até `span` bytes; `None` se
/// ela não couber na faixa.
pub fn choose_window_base(r: u64, span: u64) -> Option<u64> {
    let room = (WINDOW_END - WINDOW_START).checked_sub(span.next_multiple_of(GIB))?;
    Some(WINDOW_START + r % (room / GIB + 1) * GIB)
}

/// Liga ou desliga o cache de objetos por CPU (para medir); devolve o
/// estado anterior. Desligado, os objetos que já estão nos caches ficam lá
/// até ele voltar.
pub fn set_object_cache(on: bool) -> bool {
    CACHE_ON.swap(on, Ordering::AcqRel)
}

/// Objetos parados nos caches de todas as CPUs (pode estar mudando).
pub fn cached_objects() -> u64 {
    let aps = (1..ksmp::count()).filter_map(ksmp::start::percpu_of);
    let n = percpu::bsp().objects_cached() + aps.map(percpu::PerCpu::objects_cached).sum::<usize>();
    n as u64
}

/// Define o limite do heap, em bytes.
pub fn set_limit(bytes: u64) {
    HEAP.lock().set_limit(bytes);
}

/// Limite e bytes em uso.
pub fn usage() -> (u64, u64) {
    let heap = HEAP.lock();
    (heap.limit(), heap.used())
}

/// Blocos vivos no heap: objetos nos slabs (menos os parados nos caches
/// por CPU) mais alocações grandes.
pub fn live_blocks() -> u64 {
    let heap = HEAP.lock();
    let large = heap.large_stats();
    heap.cache_stats()
        .iter()
        .map(|s| s.in_use as u64)
        .sum::<u64>()
        + large.allocs
        - large.frees
        - cached_objects()
}

/// Sorteia a janela e liga o heap com o limite de `kheap=` (MiB) ou o
/// padrão. Chamar uma vez, depois de `kmem::init` e `krand::init`.
pub fn init(cmdline: &str) {
    let mut seed = [0; 8];
    if krand::fill(&mut seed).is_err() {
        warn!("okernel: heap: sem DRBG, janela no começo da faixa");
    }
    let Some(base) = choose_window_base(u64::from_le_bytes(seed), kmem::managed_end()) else {
        error!("okernel: heap: a RAM não cabe na faixa de objetos; heap desligado");
        return;
    };
    WINDOW_BASE.store(base, Ordering::Relaxed);
    info!("okernel: heap na janela {base:#x}");
    let mib = okernel::log::option(cmdline, "kheap")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LIMIT_MIB);
    set_limit(mib << 20);
    info!("okernel: heap com limite de {mib} MiB");
}

/// Escreve no log as estatísticas de cada cache e das alocações grandes.
pub fn log_stats() {
    let (caches, large, used, limit, failures) = {
        let heap = HEAP.lock();
        (
            heap.cache_stats(),
            heap.large_stats(),
            heap.used(),
            heap.limit(),
            heap.failures(),
        )
    };
    info!(
        "okernel: heap: {} KiB de {} KiB, {failures} falhas, {} objetos nos caches por CPU",
        used >> 10,
        limit >> 10,
        cached_objects()
    );
    for (s, size) in caches.iter().zip(CLASSES) {
        info!(
            "okernel: heap: slab {size:4} B: {} slabs, {}/{} objetos, {} alocações, {} liberações",
            s.slabs,
            s.in_use,
            s.slabs * s.per_slab,
            s.allocs,
            s.frees
        );
    }
    info!(
        "okernel: heap: grandes: {} KiB, {} alocações, {} liberações",
        large.bytes >> 10,
        large.allocs,
        large.frees
    );
}
