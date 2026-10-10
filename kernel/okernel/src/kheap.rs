//! Heap do kernel (T-108): o slab de `okernel::mm::slab` sobre frames do
//! buddy, acessados pelo mapa direto, como `GlobalAlloc` da crate `alloc`.
//!
//! O limite vem de `kheap=<MiB>` na linha de comando (padrão
//! [`DEFAULT_LIMIT_MIB`]). Acima dele, `alloc` devolve nulo; as coleções da
//! `alloc` transformam isso em pânico, então o código que pode esbarrar no
//! limite usa as APIs falíveis (`try_reserve`, [`try_alloc`]). Tratadores de
//! interrupção não alocam: a trava do heap não desliga interrupções.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;

use kabi::boot::DIRECT_MAP_BASE;
use okernel::mm::PhysAddr;
use okernel::mm::slab::{CLASSES, Heap, HeapError, PageSource};
use okernel::sync::SpinLock;

use crate::kmem;

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
        kmem::free_frames(PhysAddr(addr - DIRECT_MAP_BASE), order);
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

static HEAP: SpinLock<Heap<DirectPages>> = SpinLock::new(Heap::new(DirectPages, 0));

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
        if let Err(e) = HEAP.lock().free(ptr.addr() as u64, layout) {
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
    let addr = HEAP.lock().alloc(layout)?;
    NonNull::new(core::ptr::with_exposed_provenance_mut(
        usize::try_from(addr).unwrap_or(0),
    ))
    .ok_or(HeapError::OutOfMemory)
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
        "okernel: heap: {} KiB de {} KiB, {failures} falhas",
        used >> 10,
        limit >> 10
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
