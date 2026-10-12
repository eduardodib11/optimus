//! Heap do kernel (T-108): o slab de `okernel::mm::slab` sobre frames do
//! buddy, acessados pelo mapa direto, como `GlobalAlloc` da crate `alloc`.
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
use core::sync::atomic::{AtomicBool, Ordering};

use okernel::mm::PhysAddr;
use okernel::mm::cache::OBJECT_BATCH;
use okernel::mm::slab::{CLASSES, Heap, HeapError, PageSource, class, plausible};
use okernel::sync::{LockClass, SpinLock};

use crate::arch::x86_64::percpu;
use crate::{kmem, ksmp};

mod tests;
pub use tests::TESTS;

/// Limite padrão do heap, em MiB.
pub const DEFAULT_LIMIT_MIB: u64 = 32;

/// Páginas do buddy vistas pelo mapa direto.
struct DirectPages;

impl PageSource for DirectPages {
    fn alloc_pages(&mut self, order: usize) -> Option<u64> {
        kmem::alloc_frames(order).map(kmem::direct)
    }

    fn free_pages(&mut self, addr: u64, order: usize) {
        kmem::free_frames(PhysAddr(addr - kmem::direct_base()), order);
    }

    fn read(&mut self, addr: u64) -> u64 {
        // SAFETY: o slab só lê palavras alinhadas dentro de páginas que pegou
        // do buddy, todas no mapa direto (RW).
        unsafe { (addr as *const u64).read() }
    }

    fn write(&mut self, addr: u64, value: u64) {
        // SAFETY: idem; as páginas são do heap, sob a trava `HEAP`.
        unsafe { (addr as *mut u64).write(value) }
    }
}

static HEAP: SpinLock<Heap<DirectPages>> =
    SpinLock::with_class(LockClass::Heap, Heap::new(DirectPages, 0));
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
            _ => HEAP.lock().free(addr, layout),
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
    let addr = match class(layout) {
        Some(i) if CACHE_ON.load(Ordering::Relaxed) => alloc_cached(i, layout)?,
        _ => HEAP.lock().alloc(layout)?,
    };
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
        let mut heap = HEAP.lock();
        let first = heap.alloc(layout)?;
        m.refill(OBJECT_BATCH - 1, &mut || heap.alloc_class(i));
        Ok(first)
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
        let mut heap = HEAP.lock();
        m.spill(OBJECT_BATCH, &mut |a| spill_one(&mut heap, i, a));
        if m.push(addr) {
            Ok(())
        } else {
            heap.free_class(i, addr)
        }
    })
}

/// Devolve ao slab todos os objetos do cache desta CPU.
pub fn drain_object_cache() {
    percpu::with_object_cache(|c| {
        if c.iter().all(okernel::mm::cache::Magazine::is_empty) {
            return;
        }
        let mut heap = HEAP.lock();
        for (i, m) in c.iter_mut().enumerate() {
            m.spill(usize::MAX, &mut |a| spill_one(&mut heap, i, a));
        }
    });
}

/// Devolve ao slab um objeto que estava no cache; aqui a liberação
/// inválida (que o cache não pega) aparece.
fn spill_one(heap: &mut Heap<DirectPages>, i: usize, addr: u64) {
    if let Err(e) = heap.free_class(i, addr) {
        error!("okernel: heap: liberação inválida de {addr:#x}: {e:?}");
    }
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

/// Liga o heap com o limite de `kheap=` (MiB) ou o padrão.
pub fn init(cmdline: &str) {
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
