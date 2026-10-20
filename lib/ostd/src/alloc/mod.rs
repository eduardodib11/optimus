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
//! Cada thread tem o seu [`Heap`] do `oalloc`, guardado no bloco da thread
//! ([`crate::tls`], T-335): o caminho comum não toma trava. Ele nasce na
//! primeira alocação da thread e é devolvido (`Drop`) na saída dela, quando os
//! segmentos com blocos vivos viram "abandonados" e outro heap os adota;
//! liberar um bloco de outra thread já funcionava (`thread_free`). A única
//! trava que sobra é a da [`KernelSource`], que reparte endereços da janela
//! de segmentos entre todas as threads (só ao mapear ou desmapear um
//! segmento de 2 MiB, não por alocação).
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
//! - `unsafe impl Sync` e o acesso ao `UnsafeCell` do [`Locked`] (a lista de
//!   endereços da janela): o valor só é tocado com a trava tomada.

#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

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

/// Quantas faixas devolvidas a [`KernelSource`] guarda para reaproveitar.
const FREE_RANGES: usize = 64;

/// Estado dos endereços da janela, sempre sob a trava da [`KernelSource`].
struct Ranges {
    /// Primeiro endereço nunca entregue: tudo de `WINDOW_BASE` até aqui já
    /// foi reservado alguma vez.
    next: u64,
    /// Faixas `(início, tamanho)` devolvidas e ainda sem dono, prontas para
    /// reaproveitar. As `len` primeiras entradas valem.
    free: [(u64, u64); FREE_RANGES],
    len: usize,
}

impl Ranges {
    const fn new() -> Self {
        Self {
            next: WINDOW_BASE,
            free: [(0, 0); FREE_RANGES],
            len: 0,
        }
    }

    /// Reserva `len` bytes: primeiro numa faixa devolvida (a primeira que
    /// couber), senão avançando `next`. `None` se a janela acabou.
    fn reserve(&mut self, len: u64) -> Option<u64> {
        for i in 0..self.len {
            let (start, size) = self.free[i];
            if size >= len {
                if size == len {
                    self.len -= 1;
                    self.free[i] = self.free[self.len];
                } else {
                    self.free[i] = (start + len, size - len);
                }
                return Some(start);
            }
        }
        let end = self
            .next
            .checked_add(len)
            .filter(|&e| e <= WINDOW_BASE + WINDOW_SIZE)?;
        let start = self.next;
        self.next = end;
        Some(start)
    }

    /// Devolve a faixa `[start, start + len)`: junta com a vizinha livre, ou
    /// recua `next` se ela é a última da janela, ou ocupa uma entrada livre.
    /// Com a lista cheia a faixa se perde (o endereço não volta a ser
    /// entregue), e `owns` continua a dar `true` para ela; é o caso aceito
    /// de esgotar a janela mais cedo, só depois de 64 faixas soltas e
    /// separadas ao mesmo tempo.
    fn release(&mut self, start: u64, len: u64) {
        let end = start + len;
        if end == self.next {
            self.next = start;
            // A faixa livre que agora toca `next` também recua.
            while let Some(i) =
                (0..self.len).find(|&i| self.free[i].0 + self.free[i].1 == self.next)
            {
                self.next = self.free[i].0;
                self.len -= 1;
                self.free[i] = self.free[self.len];
            }
            return;
        }
        for i in 0..self.len {
            let (s, l) = self.free[i];
            if s + l == start {
                self.free[i].1 += len;
                self.merge_after(i);
                return;
            }
            if end == s {
                self.free[i] = (start, l + len);
                self.merge_before(i);
                return;
            }
        }
        if self.len < FREE_RANGES {
            self.free[self.len] = (start, len);
            self.len += 1;
        }
    }

    /// Depois de crescer a entrada `i` para a direita, absorve a que começa
    /// onde ela termina.
    fn merge_after(&mut self, i: usize) {
        let end = self.free[i].0 + self.free[i].1;
        if let Some(j) = (0..self.len).find(|&j| j != i && self.free[j].0 == end) {
            self.free[i].1 += self.free[j].1;
            self.len -= 1;
            self.free[j] = self.free[self.len];
        }
    }

    /// Depois de crescer a entrada `i` para a esquerda, absorve a que termina
    /// onde ela começa.
    fn merge_before(&mut self, i: usize) {
        let start = self.free[i].0;
        if let Some(j) = (0..self.len).find(|&j| j != i && self.free[j].0 + self.free[j].1 == start)
        {
            self.free[j].1 += self.free[i].1;
            self.len -= 1;
            self.free[i] = self.free[self.len];
        }
    }

    /// `addr` está numa faixa entregue e ainda não devolvida?
    fn owns(&self, addr: u64) -> bool {
        (WINDOW_BASE..self.next).contains(&addr)
            && !self.free[..self.len]
                .iter()
                .any(|&(s, l)| (s..s + l).contains(&addr))
    }
}

/// De onde o alocador tira segmentos: `MemoryObject` mapeado numa janela.
///
/// Os endereços saem de `WINDOW_BASE` para cima, mas as faixas devolvidas por
/// `free_segments` são reaproveitadas antes de avançar (uma lista de
/// `FREE_RANGES` faixas, sem alocar), então um serviço que aloca e libera um
/// bloco enorme em laço não gasta a janela. O sorteio com 23 bits de
/// entropia (ADR 0039, item 2) precisa do `sys_info` de entropia da T-337,
/// que ainda não existe; quando existir, o sorteio troca a escolha da faixa,
/// com nova tentativa se `vm_map` achar a faixa ocupada. Até lá, a janela dá
/// 8 milhões de mapeamentos de 2 MiB por processo; se a lista de faixas
/// livres lotar, a faixa devolvida se perde e a janela gasta mais depressa.
///
/// A trava cobre a reserva, o mapeamento e a devolução inteiros, então
/// `owns` nunca vê uma faixa reservada e ainda não mapeada: ela só conta como
/// "do alocador" depois de mapeada e até o `free_segments`.
pub struct KernelSource {
    ranges: Locked<Ranges>,
}

impl KernelSource {
    const fn new() -> Self {
        Self {
            ranges: Locked::new(Ranges::new()),
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
        self.ranges.with(|ranges| {
            let Some(va) = ranges.reserve(len) else {
                return null_mut();
            };
            let mapped = cap::create(env.quota, ObjectType::MemoryObject, len).and_then(|object| {
                let mapped = vm::map(vm::SELF, object, va, 0, len, WRITE);
                // A região guarda o objeto; sem ela o `vm_unmap` o destrói e
                // devolve a cota, então o handle não faz mais falta.
                let _ = cap::delete(object);
                mapped
            });
            if mapped.is_err() {
                // Devolve a faixa se o mapeamento falhou (cota), para que
                // pedidos que falham não gastem a janela.
                ranges.release(va, len);
                return null_mut();
            }
            core::ptr::with_exposed_provenance_mut(usize::try_from(va).unwrap_or(0))
        })
    }

    unsafe fn free_segments(&self, base: *mut u8, count: usize) {
        if rt::env().is_some() {
            let start = base.addr() as u64;
            let len = (count * SEGMENT_SIZE) as u64;
            self.ranges.with(|ranges| {
                let _ = vm::unmap(vm::SELF, start, len);
                ranges.release(start, len);
            });
        }
    }

    fn owns(&self, addr: usize) -> bool {
        self.ranges.with(|ranges| ranges.owns(addr as u64))
    }

    /// Sem a entropia do kernel (T-337), o relógio dá uma semente fraca: o
    /// endurecimento do `oalloc` fica fraco, mas nunca zero.
    fn seed(&self) -> u64 {
        crate::time::now_ns()
    }

    fn fault(&self, fault: Fault) -> ! {
        // A thread morre possivelmente com a trava da janela tomada. Sem isto,
        // as outras girariam para sempre nela: `Locked::with` encerra quem
        // achar o alocador envenenado. O `abort` do processo todo vem com o
        // `EXIT_GROUP` (T-333, ADR 0039 item 5).
        POISONED.store(true, Ordering::Release);
        crate::debug::print_fmt(format_args!("ostd: alocador: {fault}"));
        crate::thread::exit_raw(kabi::exit::PANIC_CODE)
    }
}

/// Ligado por `fault` antes de a thread morrer com a trava tomada: quem
/// encontrar o alocador envenenado em `Locked::with` encerra a thread.
static POISONED: AtomicBool = AtomicBool::new(false);

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
        if POISONED.load(Ordering::Acquire) {
            crate::thread::exit_raw(kabi::exit::PANIC_CODE);
        }
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            if POISONED.load(Ordering::Acquire) {
                crate::thread::exit_raw(kabi::exit::PANIC_CODE);
            }
            core::hint::spin_loop();
        }
        // SAFETY: a trava está tomada até o `store` abaixo.
        let result = f(unsafe { &mut *self.value.get() });
        self.locked.store(false, Ordering::Release);
        result
    }
}

static GLOBAL: Global<KernelSource> = Global::new(KernelSource::new());

/// O heap de uma thread (guardado no bloco dela).
pub(crate) type LocalHeap = Heap<'static, KernelSource>;

/// Heap novo para uma thread.
pub(crate) fn new_heap() -> LocalHeap {
    Heap::new(&GLOBAL)
}

/// Contagens do heap da thread que chama (blocos e bytes vivos, segmentos).
#[must_use]
pub fn stats() -> Stats {
    crate::tls::current().with_heap(|heap| heap.stats())
}

/// Segmentos de 2 MiB mapeados pelo processo todo (de todas as threads,
/// inclusive os abandonados por quem saiu e ainda não adotados).
#[must_use]
pub fn mapped_segments() -> usize {
    GLOBAL.mapped_segments()
}

/// O alocador global.
pub struct Allocator;

// SAFETY: `alloc` devolve blocos do `oalloc` (alinhados e disjuntos) ou nulo,
// e `dealloc` os devolve ao mesmo heap, com a trava tomada.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if rt::env().is_none() {
            crate::debug::print("ostd: alocação antes de rt::init");
            crate::thread::exit_raw(kabi::exit::PANIC_CODE);
        }
        crate::tls::current().with_heap(|heap| heap.alloc(layout.size(), layout.align()))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        // SAFETY: o contrato de `GlobalAlloc::dealloc` é o de `Heap::free`.
        crate::tls::current().with_heap(|heap| unsafe { heap.free(ptr) });
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;
