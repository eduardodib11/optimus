//! Testes de kernel do cache de frames por CPU (T-328): várias CPUs alocam
//! e liberam frames ao mesmo tempo, trocando frames entre si, sem perder nem
//! entregar o mesmo frame a dois donos; e a medida de escala de 1 a 4 CPUs,
//! com e sem o cache, e a do heap.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use okernel::mm::PhysAddr;
use okernel::mm::cache::FRAME_CAPACITY;

use super::super::{alloc_frames, direct, frame_stats, free_frames, set_frame_cache};
use crate::arch::x86_64::percpu;
use crate::ktest::Outcome;
use crate::{ksmp, ktime};

/// Marca dos frames com dono no teste (16 bits de cima da 1ª palavra); o
/// resto é a CPU e o número da operação.
const MAGIC: u64 = 0x7a6b << 48;
const MAGIC_MASK: u64 = 0xffff << 48;
/// Frames que cada CPU segura no máximo: mais que o cache, para que ele
/// encha e esvazie.
const HOLD: usize = FRAME_CAPACITY + FRAME_CAPACITY / 2;
/// Vagas de troca entre CPUs.
const SLOTS: usize = 64;
/// Operações (alocar ou liberar) somadas de todas as CPUs no teste de
/// estresse sem `mm.frames_ops`; o aceite do T-328 pede 10⁶.
const DEFAULT_STRESS_OPS: u64 = 1_000_000;
/// Operações por CPU em cada rodada da medida sem `mm.bench_ops`.
const DEFAULT_BENCH_OPS: u64 = 40_000;
/// Rajada da medida: aloca tantos e libera tantos.
const BURST: usize = 8;
const MS: u64 = 1_000_000;

/// O que as CPUs rodam.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Stress = 0,
    Frames = 1,
    Heap = 2,
}

static MODE: AtomicUsize = AtomicUsize::new(0);
/// CPUs que participam (ids `0..K`).
static PARTICIPANTS: AtomicUsize = AtomicUsize::new(0);
/// Operações de cada participante.
static OPS: AtomicU64 = AtomicU64::new(0);
/// APs participantes prontos, e APs que terminaram (participando ou não).
static READY: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static GO: AtomicBool = AtomicBool::new(false);
static T0: AtomicU64 = AtomicU64::new(0);
/// Fim mais tardio entre os participantes.
static LAST_END: AtomicU64 = AtomicU64::new(0);
/// Frames vistos com dois donos, e alocações que falharam.
static DUPLICATES: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
/// Frames de passagem entre CPUs (zero: vaga livre).
static EXCHANGE: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

/// A 1ª palavra de um frame que o teste segura.
fn word(frame: u64) -> &'static AtomicU64 {
    // SAFETY: o frame está alocado e é deste teste enquanto a referência é
    // usada; mapa direto (RW), alinhado a 4 KiB.
    unsafe { &*(direct(PhysAddr(frame)) as *const AtomicU64) }
}

/// Gerador xorshift (sem estado global).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Os frames que uma CPU segura, com a marca de cada um.
struct Held {
    frames: [(u64, u64); HOLD],
    len: usize,
}

impl Held {
    /// Libera o `i`-ésimo, conferindo que a marca é a dele.
    fn release(&mut self, i: usize) {
        self.len -= 1;
        let (frame, tag) = self.frames[i];
        self.frames[i] = self.frames[self.len];
        if word(frame).swap(0, Ordering::Relaxed) != tag {
            DUPLICATES.fetch_add(1, Ordering::Relaxed);
        }
        free_frames(PhysAddr(frame), 0);
    }

    /// Passa a segurar `frame` com a marca `tag`.
    fn keep(&mut self, frame: u64, tag: u64) {
        word(frame).store(tag, Ordering::Relaxed);
        self.frames[self.len] = (frame, tag);
        self.len += 1;
    }
}

/// Estresse: `ops` alocações, liberações e trocas, em fases que enchem e
/// esvaziam o cache; no fim, libera tudo.
fn stress(me: u64, ops: u64) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ ((me + 1) * 0x1000_0001));
    let mut held = Held {
        frames: [(0, 0); HOLD],
        len: 0,
    };
    for i in 0..ops {
        let r = rng.next();
        // Fases de 128 operações: na de alocar, 3 de 4 alocam.
        let alloc_phase = (i / 128) % 2 == 0;
        let alloc = held.len == 0 || (held.len < HOLD && r.is_multiple_of(4) != alloc_phase);
        let tag = MAGIC | me << 40 | i;
        if alloc {
            let Some(frame) = alloc_frames(0) else {
                FAILED.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // Liberado pelo teste, um frame volta zerado: a marca aqui é
            // de um dono vivo.
            if word(frame.0).load(Ordering::Relaxed) & MAGIC_MASK == MAGIC {
                DUPLICATES.fetch_add(1, Ordering::Relaxed);
            }
            held.keep(frame.0, tag);
        } else if r % 16 == 1 {
            // Troca com outra CPU: entrega um, talvez receba outro.
            let i = (r >> 8) as usize % held.len;
            let (frame, mine) = held.frames[i];
            if word(frame).load(Ordering::Relaxed) != mine {
                DUPLICATES.fetch_add(1, Ordering::Relaxed);
            }
            held.len -= 1;
            held.frames[i] = held.frames[held.len];
            let got = EXCHANGE[(r >> 20) as usize % SLOTS].swap(frame, Ordering::AcqRel);
            if got != 0 {
                if word(got).load(Ordering::Relaxed) & MAGIC_MASK != MAGIC {
                    DUPLICATES.fetch_add(1, Ordering::Relaxed);
                }
                held.keep(got, tag);
            }
        } else {
            held.release((r >> 8) as usize % held.len);
        }
        if i % 64 == 0 {
            ksmp::ipi::poll();
        }
    }
    while held.len > 0 {
        held.release(held.len - 1);
    }
}

/// Medida dos frames: rajadas de [`BURST`] alocações e liberações.
fn frames_bench(ops: u64) {
    let mut frames = [PhysAddr(0); BURST];
    for _ in 0..ops / (2 * BURST as u64) {
        for f in &mut frames {
            *f = alloc_frames(0).unwrap_or_else(|| {
                FAILED.fetch_add(1, Ordering::Relaxed);
                PhysAddr(0)
            });
        }
        for &f in &frames {
            if f.0 != 0 {
                free_frames(f, 0);
            }
        }
    }
}

/// Medida do heap: rajadas de [`BURST`] blocos de 64 bytes.
fn heap_bench(ops: u64) {
    for _ in 0..ops / (2 * BURST as u64) {
        let boxes: [Box<[u64; 8]>; BURST] = core::array::from_fn(|i| Box::new([i as u64; 8]));
        core::hint::black_box(&boxes);
    }
}

/// A parte de uma CPU: espera a largada, roda e anota o fim.
fn body(me: u64) {
    while !GO.load(Ordering::Acquire) {
        ksmp::ipi::poll();
        core::hint::spin_loop();
    }
    let ops = OPS.load(Ordering::Relaxed);
    match MODE.load(Ordering::Relaxed) {
        0 => stress(me, ops),
        1 => frames_bench(ops),
        _ => heap_bench(ops),
    }
    LAST_END.fetch_max(ktime::now_ns(), Ordering::AcqRel);
}

/// Trabalho dos APs ([`ksmp::start::post_ap_job`]).
fn ap_job() {
    let me = percpu::cpu_id();
    if (me as usize) < PARTICIPANTS.load(Ordering::Acquire) {
        READY.fetch_add(1, Ordering::AcqRel);
        body(u64::from(me));
    }
    DONE.fetch_add(1, Ordering::AcqRel);
}

/// Roda `mode` em `k` CPUs (o BSP e os APs `1..k`), `ops` operações em
/// cada; devolve o tempo da largada ao último fim.
fn run(mode: Mode, k: usize, ops: u64) -> Result<u64, &'static str> {
    let aps = ksmp::start::online_count() - 1;
    MODE.store(mode as usize, Ordering::Relaxed);
    OPS.store(ops, Ordering::Relaxed);
    PARTICIPANTS.store(k, Ordering::Release);
    for a in [&READY, &DONE] {
        a.store(0, Ordering::Relaxed);
    }
    for a in [&T0, &LAST_END] {
        a.store(0, Ordering::Relaxed);
    }
    GO.store(false, Ordering::Release);
    if aps > 0 {
        ksmp::start::post_ap_job(ap_job);
    }
    let limit = ktime::now_ns() + 10_000 * MS;
    while READY.load(Ordering::Acquire) < k - 1 {
        ensure!(ktime::now_ns() < limit);
        ksmp::ipi::poll();
        core::hint::spin_loop();
    }
    let t0 = ktime::now_ns();
    T0.store(t0, Ordering::Relaxed);
    GO.store(true, Ordering::Release);
    body(0);
    let limit = ktime::now_ns() + 600_000 * MS;
    while DONE.load(Ordering::Acquire) < aps {
        ensure!(ktime::now_ns() < limit);
        ksmp::ipi::poll();
        core::hint::spin_loop();
    }
    Ok(LAST_END.load(Ordering::Acquire) - t0)
}

/// Valor de uma opção `nome=N` da linha de comando, ou `default`.
fn option(name: &str, default: u64) -> u64 {
    crate::bootinfo::get()
        .and_then(|i| i.cmdline())
        .and_then(|c| okernel::log::option(c, name))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Aceite do T-328: `mm.frames_ops` (10⁶) alocações e liberações somadas,
/// em todas as CPUs ao mesmo tempo, com frames passando de uma CPU para
/// outra: nenhum frame com dois donos e, no fim, todos de volta.
pub fn frames_concorrentes() -> Outcome {
    let n = ksmp::start::online_count();
    let total = option("mm.frames_ops", DEFAULT_STRESS_OPS);
    let before = frame_stats();
    DUPLICATES.store(0, Ordering::Relaxed);
    FAILED.store(0, Ordering::Relaxed);
    let ns = run(Mode::Stress, n, total / n as u64)?;
    for slot in &EXCHANGE {
        let frame = slot.swap(0, Ordering::AcqRel);
        if frame != 0 {
            if word(frame).swap(0, Ordering::Relaxed) & MAGIC_MASK != MAGIC {
                DUPLICATES.fetch_add(1, Ordering::Relaxed);
            }
            free_frames(PhysAddr(frame), 0);
        }
    }
    let after = frame_stats();
    let dup = DUPLICATES.load(Ordering::Relaxed);
    let failed = FAILED.load(Ordering::Relaxed);
    info!(
        "ktest: · {n} CPU(s), {total} operações em {} ms; {dup} frames com dois donos, \
         {failed} alocações falharam, livres {} → {}",
        ns / MS,
        before.0,
        after.0
    );
    ensure!(dup == 0 && failed == 0);
    ensure!(after == before);
    Ok(())
}

/// Medida do T-328 (sem limite de tempo; os números vão para
/// `docs/kernel/caches-por-cpu.md`): `mm.bench_ops` operações por CPU com
/// 1 a 4 CPUs, nos frames e no heap, com e sem os caches por CPU.
pub fn escala() -> Outcome {
    let n = ksmp::start::online_count().min(4);
    let ops = option("mm.bench_ops", DEFAULT_BENCH_OPS);
    let frames_before = frame_stats();
    let live_before = crate::kheap::live_blocks();
    FAILED.store(0, Ordering::Relaxed);
    for (name, mode, cache) in [
        ("frames com cache", Mode::Frames, true),
        ("frames sem cache", Mode::Frames, false),
        ("heap (64 B) com cache", Mode::Heap, true),
        ("heap (64 B) sem cache", Mode::Heap, false),
    ] {
        let was = if mode == Mode::Heap {
            crate::kheap::set_object_cache(cache)
        } else {
            set_frame_cache(cache)
        };
        for k in 1..=n {
            let ns = run(mode, k, ops)?;
            let total = ops * k as u64;
            info!(
                "ktest: · {name}, {k} CPU(s): {total} operações em {} µs, {} ns por operação, \
                 {} operações/ms",
                ns / 1000,
                ns / total.max(1),
                total * MS / ns.max(1)
            );
        }
        if mode == Mode::Heap {
            crate::kheap::set_object_cache(was);
        } else {
            set_frame_cache(was);
            // Os frames voltam todos; depois do heap, não: objetos parados
            // nos caches dos APs seguram os slabs deles.
            ensure!(frame_stats() == frames_before);
        }
    }
    ensure!(FAILED.load(Ordering::Relaxed) == 0);
    ensure!(crate::kheap::live_blocks() == live_before);
    Ok(())
}
