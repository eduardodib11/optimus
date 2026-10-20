//! Alocador global do `ostd` (T-334; ADR 0039, item 2): a cola entre o
//! núcleo [`oalloc`] e o kernel.
//!
//! - [`KernelSource`] é o [`PageSource`] real: cada segmento de 2 MiB é um
//!   `MemoryObject` criado da cota do processo (`obj_create`) e mapeado com
//!   `vm_map` no espaço de endereços dele, numa janela de 16 TiB da metade
//!   baixa; devolvê-lo é `vm_unmap` (o objeto não tem outro dono, então a
//!   cota volta junto).
//! - [`Allocator`] implementa `GlobalAlloc` e é o `#[global_allocator]` de
//!   todo binário que usa o `ostd`.
//!
//! Por ora existe **um heap só** do processo, atrás de um spinlock simples:
//! o heap por thread precisa do `FS_BASE` por thread (T-333) e das threads do
//! `ostd` (T-335), que o ligam ao bloco da thread. O núcleo já é por thread
//! (listas locais, `thread_free` para liberação entre threads, adoção de
//! segmentos de quem sai); a T-335 troca o `HEAP` global por um `Heap` por
//! thread e o spinlock desaparece do caminho comum. Enquanto isso, o spinlock
//! só protege contra threads do mesmo processo criadas com as syscalls cruas
//! (hoje só o `root` e o `hello`, que não alocam em paralelo), e uma thread
//! de prioridade maior que gira esperando uma menor que segura a trava não
//! avança: por isso o alocador não deve ser usado em paralelo antes da T-335.
//!
//! Alocar antes de [`crate::rt::init`] é erro de programação e aborta o
//! processo (hoje, encerra a thread, com uma linha no registro de depuração;
//! o `abort` do processo vem com o `EXIT_GROUP` da T-333, ADR 0039 item 5).
//! O mesmo vale para as falhas do endurecimento do `oalloc` (liberação
//! dupla, ponteiro alheio, lista livre corrompida). Memória esgotada
//! devolve nulo, e o `alloc` chama `handle_alloc_error`.
//!
//! # Unsafe
//!
//! Este módulo tem `unsafe` em quatro lugares, todos pequenos:
//!
//! - `unsafe impl PageSource`: o contrato é o do `oalloc` (INV-F); a
//!   [`KernelSource`] o cumpre porque `vm_map` só aceita faixa livre (nada
//!   mais usa o segmento), o kernel zera e entrega páginas graváveis, o
//!   endereço é múltiplo de 2 MiB (a janela e o tamanho são) e o segmento
//!   fica mapeado até o `vm_unmap` de `free_segments`.
//! - `unsafe fn free_segments`: o contrato da própria trait.
//! - `unsafe impl GlobalAlloc` e a chamada de `Heap::free` em `dealloc`: o
//!   contrato de `GlobalAlloc::dealloc` é o de `Heap::free` (o ponteiro veio
//!   de `alloc` e é liberado uma vez).
//! - `unsafe impl Sync` e o acesso ao `UnsafeCell` do [`Locked`]: o valor só
//!   é tocado com a trava tomada.

#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kabi::ObjectType;
use kabi::vm::WRITE;
use oalloc::{Fault, Global, Heap, PageSource, SEGMENT_SIZE};

pub use oalloc::Stats;

use crate::{cap, rt, vm};

/// Início da janela dos segmentos (16 TiB), na metade baixa, longe do
/// executável (`0x20_0000`), do buffer de IPC e dos mapeamentos do `root`
/// (abaixo de 4 GiB) e da pilha (`0x7fff_ffff_0000`).
const WINDOW_BASE: u64 = 0x0000_1000_0000_0000;
/// Tamanho da janela: 16 TiB.
const WINDOW_SIZE: u64 = 1 << 44;

/// De onde o alocador tira segmentos: `MemoryObject` mapeado numa janela.
///
/// Os endereços saem em ordem, de `WINDOW_BASE` para cima, sem reuso: o
/// sorteio com 23 bits de entropia (ADR 0039, item 2) precisa do `sys_info`
/// de entropia da T-337, que ainda não existe. Quando existir, o sorteio
/// troca o contador, com nova tentativa se `vm_map` achar a faixa ocupada, e
/// a janela volta a poder ser reaproveitada. Até lá, a janela dá 8 milhões de
/// mapeamentos de 2 MiB por processo.
pub struct KernelSource {
    next: AtomicU64,
}

impl KernelSource {
    const fn new() -> Self {
        Self {
            next: AtomicU64::new(WINDOW_BASE),
        }
    }
}

// SAFETY: ver a seção `# Unsafe` do módulo: faixa nova de `vm_map`, endereço
// alinhado a 2 MiB, gravável, mapeada até o `vm_unmap`.
unsafe impl PageSource for KernelSource {
    fn alloc_segments(&self, count: usize) -> *mut u8 {
        let Some(env) = rt::env() else {
            return null_mut();
        };
        let Some(len) = count.checked_mul(SEGMENT_SIZE) else {
            return null_mut();
        };
        let len = len as u64;
        let reserved = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_add(len)
                    .filter(|&end| end <= WINDOW_BASE + WINDOW_SIZE)
            });
        let Ok(va) = reserved else {
            return null_mut();
        };
        let mapped = cap::create(env.quota, ObjectType::MemoryObject, len).and_then(|object| {
            let mapped = vm::map(env.aspace, object, va, 0, len, WRITE);
            // A região guarda o objeto; sem ela o `vm_unmap` o destrói e
            // devolve a cota, então o handle não faz mais falta.
            let _ = cap::delete(object);
            mapped
        });
        if mapped.is_err() {
            // Devolve a faixa reservada se ninguém reservou depois dela, para
            // que pedidos que falham (cota) não gastem a janela.
            let _ = self
                .next
                .compare_exchange(va + len, va, Ordering::Relaxed, Ordering::Relaxed);
            return null_mut();
        }
        core::ptr::with_exposed_provenance_mut(usize::try_from(va).unwrap_or(0))
    }

    unsafe fn free_segments(&self, base: *mut u8, count: usize) {
        if let Some(env) = rt::env() {
            let _ = vm::unmap(
                env.aspace,
                base.addr() as u64,
                (count * SEGMENT_SIZE) as u64,
            );
        }
    }

    fn owns(&self, addr: usize) -> bool {
        (WINDOW_BASE..self.next.load(Ordering::Relaxed)).contains(&(addr as u64))
    }

    /// Sem a entropia do kernel (T-337), o relógio dá uma semente fraca: o
    /// endurecimento do `oalloc` fica fraco, mas nunca zero.
    fn seed(&self) -> u64 {
        crate::time::now_ns()
    }

    fn fault(&self, fault: Fault) -> ! {
        crate::debug::print_fmt(format_args!("ostd: alocador: {fault}"));
        crate::thread::exit()
    }
}

/// Valor protegido por um spinlock.
struct Locked<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: o valor só é tocado com a trava tomada (`with`), então no máximo
// uma thread o usa por vez; o `Heap` não tem afinidade com thread além disso.
unsafe impl<T> Sync for Locked<T> {}

impl<T> Locked<T> {
    const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: a trava está tomada até o `store` abaixo.
        let result = f(unsafe { &mut *self.value.get() });
        self.locked.store(false, Ordering::Release);
        result
    }
}

static GLOBAL: Global<KernelSource> = Global::new(KernelSource::new());
/// O heap do processo (T-335: um por thread). Nasce na primeira alocação.
static HEAP: Locked<Option<Heap<'static, KernelSource>>> = Locked::new(None);

fn with_heap<R>(f: impl FnOnce(&mut Heap<'static, KernelSource>) -> R) -> R {
    HEAP.with(|slot| f(slot.get_or_insert_with(|| Heap::new(&GLOBAL))))
}

/// Contagens do heap do processo (blocos e bytes vivos, segmentos).
#[must_use]
pub fn stats() -> Stats {
    with_heap(|heap| heap.stats())
}

/// O alocador global.
pub struct Allocator;

// SAFETY: `alloc` devolve blocos do `oalloc` (alinhados e disjuntos) ou nulo,
// e `dealloc` os devolve ao mesmo heap, com a trava tomada.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if rt::env().is_none() {
            crate::debug::print("ostd: alocação antes de rt::init");
            crate::thread::exit();
        }
        with_heap(|heap| heap.alloc(layout.size(), layout.align()))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: o contrato de `GlobalAlloc::dealloc` é o de `Heap::free`.
        with_heap(|heap| unsafe { heap.free(ptr) });
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
