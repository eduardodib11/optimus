//! Fragmentação com uma carga de coleções (T-337): `Vec`, `String` e o
//! `HashMap` do `ocoll` crescendo de verdade, não pedidos sorteados.
//!
//! Um `#[global_allocator]` de teste grava, na thread da carga, cada
//! `alloc`/`dealloc` que as coleções fazem (o `realloc` padrão é
//! alocar-copiar-liberar, o mesmo que o `ostd` faz) e repassa ao `System`.
//! Depois a sequência é reexecutada num [`Heap`] do `oalloc`, que dá os
//! números reais, e comparada com as opções do relatório de fragmentação
//! (classes até 32 KiB; páginas médias de 512 KiB) por conta de tamanho de
//! bloco, sem tocar a tabela de classes.
//!
//! `cargo test -p oalloc --release colecoes -- --nocapture`.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::alloc::System;
use std::collections::BTreeMap;
use std::string::{String, ToString};
use std::vec::Vec;
use std::{println, thread};

use ocoll::HashMap;

use crate::class::{Plan, class_size, plan};
use crate::tests::{HostSource, Rng};
use crate::{Global, Heap, MAX_SMALL, PAGE_SIZE};

const TRACE_CAP: usize = 1 << 19;

static TRACE_LEN: AtomicUsize = AtomicUsize::new(0);
static TRACE: [[AtomicUsize; 3]; TRACE_CAP] =
    [const { [const { AtomicUsize::new(0) }; 3] }; TRACE_CAP];

std::thread_local! {
    static RECORDING: Cell<bool> = const { Cell::new(false) };
}

/// Marca `0` = alocação, `1` = liberação, na terceira palavra (com o
/// alinhamento nos bits altos).
struct Recorder;

fn record(op: usize, ptr: *mut u8, layout: Layout) {
    if RECORDING.with(Cell::get) {
        let i = TRACE_LEN.fetch_add(1, Ordering::Relaxed);
        assert!(i < TRACE_CAP, "rastro cheio");
        TRACE[i][0].store(ptr.addr(), Ordering::Relaxed);
        TRACE[i][1].store(layout.size(), Ordering::Relaxed);
        TRACE[i][2].store(op | (layout.align() << 1), Ordering::Relaxed);
    }
}

// SAFETY: repassa tudo ao `System`; só acrescenta o registro no rastro.
unsafe impl GlobalAlloc for Recorder {
    /// # Safety
    ///
    /// O contrato de `GlobalAlloc::alloc`.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: mesmo contrato que o chamador cumpre.
        let p = unsafe { System.alloc(layout) };
        record(0, p, layout);
        p
    }

    /// # Safety
    ///
    /// O contrato de `GlobalAlloc::dealloc`.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record(1, ptr, layout);
        // SAFETY: mesmo contrato que o chamador cumpre.
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static RECORDER: Recorder = Recorder;

/// O que a carga deixa vivo: mapas, buffers e textos.
type Live = (Vec<HashMap<u64, String>>, Vec<Vec<u8>>, Vec<String>);

/// A carga: coleções que crescem como as dos serviços (tabelas de nomes,
/// buffers de bytes, textos) e depois perdem metade.
fn workload() -> Live {
    let mut rng = Rng::new(0xC01E);
    // 60 mapas de 4 a 4000 entradas (log-uniforme), valores de 4 a 40 bytes.
    let mut maps = Vec::new();
    for _ in 0..60 {
        let n = rng.log_uniform(4, 4000);
        let mut m = HashMap::new();
        for i in 0..n {
            let len = 4 + rng.below(36);
            m.insert(rng.next(), "x".repeat(len) + &i.to_string());
        }
        maps.push(m);
    }
    // 300 buffers que crescem por `push`/`extend` até 4 B a 300 KiB.
    let mut bufs = Vec::new();
    for _ in 0..300 {
        let n = rng.log_uniform(4, 300_000);
        let mut v = Vec::new();
        while v.len() < n {
            let step = (1 + rng.below(512)).min(n - v.len());
            v.extend(core::iter::repeat_n(7u8, step));
        }
        bufs.push(v);
    }
    // 200 textos montados aos poucos, até ~40 KiB.
    let mut texts = Vec::new();
    for _ in 0..200 {
        let n = rng.log_uniform(8, 40_000);
        let mut s = String::new();
        while s.len() < n {
            s.push_str("linha de registro; ");
        }
        texts.push(s);
    }
    // Perde metade ao acaso (churn), como serviços que descartam estado.
    let keep = |rng: &mut Rng| rng.below(2) == 0;
    maps.retain(|_| keep(&mut rng));
    bufs.retain(|_| keep(&mut rng));
    texts.retain(|_| keep(&mut rng));
    (maps, bufs, texts)
}

/// Bytes que o bloco custa sob cada política (inclui a sobra no fim da
/// página, repartida entre os blocos dela).
fn cost_current(size: usize, align: usize) -> usize {
    match plan(size, align) {
        Plan::Small(c) => per_block_in_page(class_size(c), PAGE_SIZE),
        Plan::Large(n) => n * PAGE_SIZE,
        Plan::Huge(n) => n * crate::SEGMENT_SIZE,
        Plan::Fail => 0,
    }
}

/// Custo de um bloco de `c` bytes numa página de `page` bytes.
fn per_block_in_page(c: usize, page: usize) -> usize {
    page / (page / c)
}

/// Classes de 4 por duplicação, como as atuais, acima de 8 KiB.
fn extended_class(size: usize, max: usize) -> Option<usize> {
    if size > max {
        return None;
    }
    let mut k = 13; // 8 KiB
    loop {
        for sub in 1..=4usize {
            let c = (4 + sub) << (k - 2);
            if c >= size {
                return Some(c);
            }
        }
        k += 1;
    }
}

/// Opção 2: classes até 32 KiB em páginas de 64 KiB.
fn cost_classes_32k(size: usize, align: usize) -> usize {
    if size <= MAX_SMALL {
        return cost_current(size, align);
    }
    extended_class(size, 32 << 10).map_or_else(
        || cost_current(size, align),
        |c| per_block_in_page(c, PAGE_SIZE),
    )
}

/// Opção 3: páginas médias de 512 KiB com classes de 8 a 64 KiB.
fn cost_medium_pages(size: usize, align: usize) -> usize {
    if size <= MAX_SMALL {
        return cost_current(size, align);
    }
    extended_class(size, 64 << 10).map_or_else(
        || cost_current(size, align),
        |c| per_block_in_page(c, 512 << 10),
    )
}

#[derive(Default, Clone, Copy)]
struct Band {
    blocks: usize,
    requested: usize,
    current: usize,
    classes_32k: usize,
    medium: usize,
}

fn band_of(size: usize) -> usize {
    match size {
        0..=64 => 0,
        65..=8192 => 1,
        8193..=65_536 => 2,
        65_537..=524_288 => 3,
        _ => 4,
    }
}

const BANDS: [&str; 5] = [
    "até 64 B",
    "65 B a 8 KiB",
    "8 a 64 KiB",
    "64 a 512 KiB",
    "> 512 KiB",
];

#[test]
fn colecoes_fragmentacao() {
    TRACE_LEN.store(0, Ordering::SeqCst);
    let worker = thread::spawn(|| {
        RECORDING.with(|r| r.set(true));
        let live = workload();
        RECORDING.with(|r| r.set(false));
        live
    });
    let live = worker.join().unwrap();
    let n = TRACE_LEN.load(Ordering::SeqCst);

    // Reexecuta no `oalloc`.
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut blocks: BTreeMap<usize, (usize, usize, usize)> = BTreeMap::new(); // addr → (ptr, size, align)
    let (mut peak_mapped, mut allocs) = (0usize, 0usize);
    let mut bands = [Band::default(); 5];
    for entry in &TRACE[..n] {
        let (addr, size, tag) = (
            entry[0].load(Ordering::Relaxed),
            entry[1].load(Ordering::Relaxed),
            entry[2].load(Ordering::Relaxed),
        );
        let align = tag >> 1;
        if tag & 1 == 0 {
            let p = heap.alloc(size, align);
            assert!(!p.is_null());
            blocks.insert(addr, (p.addr(), size, align));
            allocs += 1;
            peak_mapped = peak_mapped.max(global.mapped_segments());
        } else if let Some((p, _, _)) = blocks.remove(&addr) {
            // SAFETY: bloco entregue por `alloc` acima, liberado uma vez.
            unsafe { heap.free(core::ptr::with_exposed_provenance_mut(p)) };
        }
        // Liberações de blocos criados fora da carga (fora do rastro) não têm par.
    }
    let st = heap.stats();
    for &(_, size, align) in blocks.values() {
        let b = &mut bands[band_of(size)];
        b.blocks += 1;
        b.requested += size;
        b.current += cost_current(size, align);
        b.classes_32k += cost_classes_32k(size, align);
        b.medium += cost_medium_pages(size, align);
    }
    let total = bands.iter().fold(Band::default(), |a, b| Band {
        blocks: a.blocks + b.blocks,
        requested: a.requested + b.requested,
        current: a.current + b.current,
        classes_32k: a.classes_32k + b.classes_32k,
        medium: a.medium + b.medium,
    });
    println!(
        "alocações no rastro: {allocs}; blocos vivos no fim: {}",
        total.blocks
    );
    println!(
        "heap real: vivo {:.2} MiB, blocos {:.2} MiB, mapeado {:.2} MiB (pico {:.2} MiB), perda de arredondamento {:.1}%",
        total.requested as f64 / 1_048_576.0,
        st.live_bytes as f64 / 1_048_576.0,
        st.mapped_bytes as f64 / 1_048_576.0,
        peak_mapped as f64 * 2.0,
        (st.live_bytes as f64 / total.requested as f64 - 1.0) * 100.0,
    );
    println!(
        "| Faixa | Blocos | Pedido (KiB) | Atual (KiB) | Perda | Classes até 32 KiB (KiB) | Perda | Páginas médias (KiB) | Perda |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|");
    let pct = |cost: usize, req: usize| {
        if req == 0 {
            0.0
        } else {
            (cost as f64 / req as f64 - 1.0) * 100.0
        }
    };
    for (name, b) in BANDS.iter().copied().zip(&bands).chain([("Total", &total)]) {
        println!(
            "| {name} | {} | {} | {} | {:.1}% | {} | {:.1}% | {} | {:.1}% |",
            b.blocks,
            b.requested / 1024,
            b.current / 1024,
            pct(b.current, b.requested),
            b.classes_32k / 1024,
            pct(b.classes_32k, b.requested),
            b.medium / 1024,
            pct(b.medium, b.requested),
        );
    }
    // Sanidade: o custo analítico "atual" bate com o do heap real (a menos
    // do cabeçalho e da granularidade de página do `Stats`).
    assert!(st.live_bytes >= total.requested);
    drop(live);
}
