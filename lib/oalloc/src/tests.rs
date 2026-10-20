//! Testes do alocador no host: fonte de páginas sobre o `std::alloc`, PRNG
//! próprio (ADR 0003, sem crates externas) e a carga de aceite da T-334: 10⁶
//! alocações aleatórias em 4 threads, com liberações cruzadas, sem vazamento
//! nem corrupção. Sob Miri (`cfg(miri)`) as contagens caem para o que cabe
//! no tempo.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::similar_names
)]

extern crate std;

use std::alloc::{Layout, alloc, dealloc};
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind, panic_any};
use std::string::String;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Barrier, Mutex};
use std::vec::Vec;
use std::{format, println, thread};

use crate::class::{NUM_CLASSES, Plan, class_of, class_size, plan};
use crate::{
    Fault, Global, Heap, MAX_LARGE, MAX_SMALL, PAGE_SIZE, PageSource, SEGMENT_SIZE, Stats,
};

/// Fonte de páginas do host: segmentos de 2 MiB alinhados, com limite e
/// contagem de segmentos vivos. Fora do Miri o conteúdo vem sujo
/// (0xA5), para que nenhum teste dependa de memória zerada; no Miri fica
/// por inicializar, e o Miri acusa qualquer leitura antes da escrita.
struct HostSource {
    /// Endereço do início da faixa → (segmentos, ponteiro original).
    spans: Mutex<BTreeMap<usize, (usize, SendPtr)>>,
    live: AtomicUsize,
    peak: AtomicUsize,
    limit: usize,
}

impl HostSource {
    fn new() -> Self {
        Self::with_limit(usize::MAX)
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            spans: Mutex::new(BTreeMap::new()),
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            limit,
        }
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

fn layout(count: usize) -> Layout {
    Layout::from_size_align(count * SEGMENT_SIZE, SEGMENT_SIZE).unwrap()
}

// SAFETY: `alloc` do std dá memória gravável com o alinhamento pedido e a
// faixa só volta pelo `free_segments`; `owns` consulta o registro das faixas.
unsafe impl PageSource for HostSource {
    fn alloc_segments(&self, count: usize) -> *mut u8 {
        let reserved = self
            .live
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                n.checked_add(count).filter(|&m| m <= self.limit)
            });
        let Ok(before) = reserved else {
            return core::ptr::null_mut();
        };
        self.peak.fetch_max(before + count, Ordering::SeqCst);
        // SAFETY: o layout tem tamanho não nulo.
        let base = unsafe { alloc(layout(count)) };
        assert!(!base.is_null(), "o host ficou sem memória");
        #[cfg(not(miri))]
        // SAFETY: `base` tem `count * SEGMENT_SIZE` bytes graváveis.
        unsafe {
            base.write_bytes(0xA5, count * SEGMENT_SIZE);
        }
        self.spans
            .lock()
            .unwrap()
            .insert(base.expose_provenance(), (count, SendPtr(base)));
        base
    }

    unsafe fn free_segments(&self, base: *mut u8, count: usize) {
        let was = self.spans.lock().unwrap().remove(&base.addr());
        let Some((n, original)) = was else {
            panic!("faixa devolvida que a fonte não deu");
        };
        assert_eq!(n, count, "faixa devolvida com outro tamanho");
        self.live.fetch_sub(count, Ordering::SeqCst);
        // SAFETY: `original` veio de `alloc(layout(count))` e é devolvido uma
        // vez (saiu do registro).
        unsafe { dealloc(original.0, layout(count)) };
    }

    fn owns(&self, addr: usize) -> bool {
        let spans = self.spans.lock().unwrap();
        spans
            .range(..=addr)
            .next_back()
            .is_some_and(|(&base, &(count, _))| addr < base + count * SEGMENT_SIZE)
    }

    fn seed(&self) -> u64 {
        0x0123_4567_89ab_cdef
    }

    fn fault(&self, fault: Fault) -> ! {
        panic_any(fault)
    }
}

impl Drop for HostSource {
    /// Devolve ao host o que os heaps abandonaram (testes que terminam em
    /// falha provocada, por exemplo), para o Miri não acusar vazamento.
    fn drop(&mut self) {
        let spans = core::mem::take(&mut *self.spans.lock().unwrap());
        for (_, (count, original)) in spans {
            // SAFETY: a faixa nunca voltou à fonte, então ainda é dela.
            unsafe { dealloc(original.0, layout(count)) };
        }
    }
}

/// xorshift64*: bom o bastante para carga de teste.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }

    /// Tamanho com distribuição log-uniforme em `[lo, hi]`.
    fn log_uniform(&mut self, lo: usize, hi: usize) -> usize {
        let (a, b) = ((lo as f64).ln(), (hi as f64).ln());
        let u = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        ((a + (b - a) * u).exp() as usize).clamp(lo, hi)
    }
}

/// Ponteiro que pode mudar de thread: o bloco é de quem o recebe.
struct SendPtr(*mut u8);

// SAFETY: o ponteiro é só um endereço de bloco entregue; quem o recebe passa
// a ser o único a usá-lo (INV-B).
unsafe impl Send for SendPtr {}

/// Um bloco vivo do teste: onde, quantos bytes foram pedidos e a marca do
/// padrão gravado.
struct Block {
    ptr: SendPtr,
    size: usize,
    tag: u8,
}

/// Passo da amostragem do padrão: bytes até 1 KiB são conferidos todos; nos
/// maiores, as pontas e um byte a cada 61 (a cada 4099 sob o Miri).
fn stride(size: usize) -> usize {
    match size {
        0..=1024 => 1,
        _ if cfg!(miri) => 4099,
        _ => 61,
    }
}

fn pattern(tag: u8, j: usize) -> u8 {
    tag ^ (j as u8).wrapping_mul(31)
}

fn fill(ptr: *mut u8, size: usize, tag: u8) {
    let mut j = 0;
    while j < size {
        // SAFETY: `j < size` e o bloco tem pelo menos `size` bytes, só nossos.
        unsafe { ptr.add(j).write(pattern(tag, j)) };
        j += stride(size);
    }
    // SAFETY: como acima.
    unsafe { ptr.add(size - 1).write(pattern(tag, size - 1)) };
}

fn check(b: &Block) {
    let ptr = b.ptr.0;
    let mut j = 0;
    while j < b.size {
        // SAFETY: bloco vivo de `b.size` bytes, só nosso.
        let got = unsafe { ptr.add(j).read() };
        assert_eq!(
            got,
            pattern(b.tag, j),
            "bloco corrompido no byte {j} de {}",
            b.size
        );
        j += stride(b.size);
    }
    // SAFETY: como acima.
    let last = unsafe { ptr.add(b.size - 1).read() };
    assert_eq!(
        last,
        pattern(b.tag, b.size - 1),
        "última posição corrompida"
    );
}

fn block(heap: &mut Heap<'_, HostSource>, rng: &mut Rng, size: usize, align: usize) -> Block {
    let p = heap.alloc(size, align);
    assert!(!p.is_null(), "alloc({size}, {align}) devolveu nulo");
    assert_eq!(p.addr() % align, 0, "alinhamento {align} não respeitado");
    let tag = rng.next() as u8;
    fill(p, size, tag);
    Block {
        ptr: SendPtr(p),
        size,
        tag,
    }
}

fn release(heap: &mut Heap<'_, HostSource>, b: &Block) {
    check(b);
    // SAFETY: o bloco foi entregue por `alloc` e é liberado uma vez.
    unsafe { heap.free(b.ptr.0) };
}

/// Executa `f` esperando a falha `expected` do alocador.
fn expect_fault(expected: Fault, f: impl FnOnce()) {
    let err = catch_unwind(AssertUnwindSafe(f)).expect_err("devia detectar a falha");
    let got = err.downcast_ref::<Fault>().expect("pânico que não é Fault");
    assert_eq!(*got, expected);
}

// ---- classes e plano ----

#[test]
fn classes_cobrem_de_8_bytes_a_8_kib() {
    assert_eq!(NUM_CLASSES, class_of(MAX_SMALL) + 1);
    assert_eq!(class_size(0), 8);
    assert_eq!(class_size(7), 64);
    assert_eq!(class_size(8), 80);
    assert_eq!(class_size(NUM_CLASSES - 1), MAX_SMALL);
    for c in 1..NUM_CLASSES {
        assert!(class_size(c) > class_size(c - 1));
        assert_eq!(class_size(c) % 8, 0);
    }
    for size in 1..=MAX_SMALL {
        let c = class_of(size);
        let block = class_size(c);
        assert!(block >= size, "classe {c} não comporta {size}");
        assert!(
            c == 0 || class_size(c - 1) < size,
            "classe {c} não é a menor para {size}"
        );
        if size > 64 {
            // Perda de no máximo 20% do bloco (ADR 0039).
            assert!(
                (block - size) * 5 <= block,
                "perda de {size} em {block} passa de 20%"
            );
        } else {
            assert!(block - size < 8);
        }
    }
}

#[test]
fn plano_do_pedido() {
    assert_eq!(plan(0, 1), Plan::Small(0));
    assert_eq!(plan(1, 8), Plan::Small(0));
    assert_eq!(plan(9, 8), Plan::Small(1));
    assert_eq!(plan(24, 8), Plan::Small(2));
    assert_eq!(plan(MAX_SMALL, 8), Plan::Small(NUM_CLASSES - 1));
    assert_eq!(plan(MAX_SMALL + 1, 8), Plan::Large(1));
    assert_eq!(plan(PAGE_SIZE + 1, 8), Plan::Large(2));
    assert_eq!(plan(MAX_LARGE, 8), Plan::Large(8));
    assert_eq!(plan(MAX_LARGE + 1, 8), Plan::Huge(1));
    assert_eq!(plan(SEGMENT_SIZE - PAGE_SIZE, 8), Plan::Huge(1));
    assert_eq!(plan(SEGMENT_SIZE - PAGE_SIZE + 1, 8), Plan::Huge(2));
    // Alinhamento: o tamanho sobe até um múltiplo, e a classe tem de ser
    // múltipla do alinhamento.
    assert_eq!(
        class_size(match plan(24, 16) {
            Plan::Small(c) => c,
            _ => panic!(),
        }),
        32
    );
    assert_eq!(
        class_size(match plan(100, 64) {
            Plan::Small(c) => c,
            _ => panic!(),
        }),
        128
    );
    assert_eq!(plan(1, 16384), Plan::Large(1));
    assert_eq!(plan(1, PAGE_SIZE), Plan::Large(1));
    assert_eq!(plan(1, 2 * PAGE_SIZE), Plan::Fail);
    assert_eq!(plan(1, 3), Plan::Fail);
    assert_eq!(plan(usize::MAX, 8), Plan::Fail);
    assert_eq!(plan(usize::MAX - 4096, 8), Plan::Fail);
    assert_eq!(plan(isize::MAX as usize, 8), Plan::Fail);
    assert!(matches!(plan(isize::MAX as usize / 2, 8), Plan::Huge(_)));
}

#[test]
fn indice_por_reciproco_e_exato() {
    // `idx = (off * recip) >> 32` tem de ser `off / bsize` para todo
    // deslocamento da página.
    for c in 0..NUM_CLASSES {
        let bsize = class_size(c);
        let recip = u64::from(u32::MAX) / bsize as u64 + 1;
        for off in (0..PAGE_SIZE).step_by(if cfg!(miri) { 97 } else { 1 }) {
            assert_eq!(
                ((off as u64 * recip) >> 32) as usize,
                off / bsize,
                "classe {c}, off {off}"
            );
        }
    }
}

// ---- um heap ----

#[test]
fn blocos_vivos_nao_se_sobrepoem_e_guardam_o_padrao() {
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(1);
    let mut live = Vec::new();
    for size in (1..=300).chain([511, 512, 513, 1000, 4096, 8191, 8192, 8193, 70_000, 524_288]) {
        live.push(block(&mut heap, &mut rng, size, 8));
    }
    let mut ranges: Vec<(usize, usize)> = live
        .iter()
        .map(|b| (b.ptr.0.addr(), b.ptr.0.addr() + b.size))
        .collect();
    ranges.sort_unstable();
    for w in ranges.windows(2) {
        assert!(w[0].1 <= w[1].0, "blocos sobrepostos");
    }
    for b in &live {
        release(&mut heap, b);
    }
    heap.trim();
    assert_eq!(heap.stats(), Stats::default());
    drop(heap);
    assert_eq!(global.source().live(), 0);
}

#[test]
fn alinhamentos() {
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(2);
    let mut live = Vec::new();
    for align in [1, 2, 4, 8, 16, 32, 64, 128, 4096, 8192, 16384, PAGE_SIZE] {
        for size in [1, 7, 8, 24, 100, 5000, 8192, 9000, 600_000] {
            live.push(block(&mut heap, &mut rng, size, align));
        }
    }
    assert!(heap.alloc(8, 2 * PAGE_SIZE).is_null());
    assert!(heap.alloc(8, 3).is_null());
    assert!(heap.alloc(usize::MAX, 8).is_null());
    for b in &live {
        release(&mut heap, b);
    }
}

#[test]
fn blocos_grandes_e_enormes_voltam_ao_segmento_e_a_fonte() {
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(3);
    let large = block(&mut heap, &mut rng, MAX_LARGE, 8);
    let huge = block(&mut heap, &mut rng, 3 * SEGMENT_SIZE - PAGE_SIZE, 8);
    assert_eq!(global.source().live(), 1 + 3);
    assert_eq!(heap.stats().live_blocks, 2);
    release(&mut heap, &huge);
    assert_eq!(
        global.source().live(),
        1,
        "o bloco enorme devolve os 3 segmentos"
    );
    release(&mut heap, &large);
    heap.trim();
    assert_eq!(global.source().live(), 0);
}

#[test]
fn memoria_esgotada_devolve_nulo_e_o_heap_continua_valido() {
    let global = Global::new(HostSource::with_limit(2));
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(4);
    let mut live = Vec::new();
    // Cada segmento tem 31 páginas: 3 blocos de 8 páginas (as páginas livres
    // não bastam para um quarto) em dois segmentos dão 6.
    while live.len() < 100 {
        let p = heap.alloc(MAX_LARGE, 8);
        if p.is_null() {
            break;
        }
        fill(p, MAX_LARGE, 7);
        live.push(Block {
            ptr: SendPtr(p),
            size: MAX_LARGE,
            tag: 7,
        });
    }
    assert_eq!(live.len(), 6);
    assert!(heap.alloc(SEGMENT_SIZE, 8).is_null(), "enorme sem segmento");
    // Sobram 7 páginas em cada segmento: um bloco pequeno ainda cabe.
    let small = block(&mut heap, &mut rng, 100, 8);
    let freed = live.pop().unwrap();
    release(&mut heap, &freed);
    let again = block(&mut heap, &mut rng, MAX_LARGE, 8);
    release(&mut heap, &again);
    release(&mut heap, &small);
    for b in &live {
        release(&mut heap, b);
    }
    heap.trim();
    drop(heap);
    assert_eq!(global.source().live(), 0);
}

#[test]
fn bloco_liberado_e_reaproveitado_sem_pedir_memoria() {
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(5);
    let first = block(&mut heap, &mut rng, 100, 8);
    let after_first = heap.stats();
    for _ in 0..10_000 {
        let b = block(&mut heap, &mut rng, 100, 8);
        release(&mut heap, &b);
    }
    assert_eq!(heap.stats().pages, after_first.pages);
    assert_eq!(global.source().peak(), 1);
    release(&mut heap, &first);
}

// ---- endurecimento ----

#[test]
fn liberacao_dupla_e_detectada() {
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(6);
    // Pequeno, grande e enorme. O enorme volta inteiro à fonte, então o
    // segundo `free` já cai fora de qualquer segmento do heap.
    for (size, fault) in [
        (40, Fault::DoubleFree),
        (20_000, Fault::DoubleFree),
        (3 * SEGMENT_SIZE, Fault::ForeignPointer),
    ] {
        let a = block(&mut heap, &mut rng, size, 8);
        let keep = block(&mut heap, &mut rng, size, 8);
        release(&mut heap, &a);
        expect_fault(fault, || {
            // SAFETY: a liberação dupla é a que o teste provoca.
            unsafe { heap.free(a.ptr.0) };
        });
        release(&mut heap, &keep);
    }
}

#[test]
fn ponteiro_alheio_e_detectado() {
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(7);
    let a = block(&mut heap, &mut rng, 48, 8);
    let mut on_stack = [0u64; 4];
    let outside = on_stack.as_mut_ptr().cast::<u8>();
    let interior = a.ptr.0.wrapping_add(8);
    let header = a.ptr.0.map_addr(|x| (x & !(SEGMENT_SIZE - 1)) + 64);
    // Início de bloco válido da classe, mas que nunca foi entregue.
    let uncarved = a.ptr.0.wrapping_add(48 * 100);
    for (ptr, why) in [
        (outside, "fora do heap"),
        (interior, "no meio de um bloco"),
        (header, "no cabeçalho do segmento"),
        (uncarved, "bloco que nunca foi entregue"),
    ] {
        let r = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: o ponteiro inválido é o que o teste provoca.
            unsafe { heap.free(ptr) };
        }));
        let err = r.expect_err(why);
        assert_eq!(
            err.downcast_ref::<Fault>(),
            Some(&Fault::ForeignPointer),
            "{why}"
        );
    }
    release(&mut heap, &a);
}

#[test]
fn elo_adulterado_da_lista_livre_e_detectado() {
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(8);
    // Enche a página da classe de 64 B (1024 blocos) para que a próxima
    // alocação recolha a `local_free`.
    let mut live: Vec<Block> = (0..PAGE_SIZE / 64)
        .map(|_| block(&mut heap, &mut rng, 64, 8))
        .collect();
    let a = live.pop().unwrap();
    release(&mut heap, &a);
    // Uso depois da liberação: o elo codificado vira um valor qualquer.
    // SAFETY: o teste grava num bloco livre de propósito, em memória do
    // segmento (fonte do host), para simular o erro do usuário.
    unsafe { a.ptr.0.cast::<u64>().write_unaligned(0x0bad_cafe) };
    expect_fault(Fault::Corrupted, || {
        let _ = heap.alloc(64, 8);
    });
    for b in &live {
        release(&mut heap, b);
    }
}

// ---- vários heaps ----

#[test]
fn liberacao_por_outro_heap_volta_ao_dono() {
    let global = Global::new(HostSource::new());
    let mut owner = Heap::new(&global);
    let mut other = Heap::new(&global);
    let mut rng = Rng::new(9);
    let blocks: Vec<Block> = (0..2000)
        .map(|_| block(&mut owner, &mut rng, 64, 8))
        .collect();
    let pages = owner.stats().pages;
    for b in &blocks {
        // Quem libera é o outro heap: vai para a `thread_free` da página.
        release(&mut other, b);
    }
    assert_eq!(other.stats().live_blocks, 0, "o outro heap não possui nada");
    // O dono recolhe ao precisar e reaproveita as mesmas páginas.
    let again: Vec<Block> = (0..2000)
        .map(|_| block(&mut owner, &mut rng, 64, 8))
        .collect();
    assert_eq!(owner.stats().pages, pages, "reaproveitou as páginas");
    for b in &again {
        release(&mut owner, b);
    }
    owner.collect();
    assert_eq!(owner.stats().live_blocks, 0);
}

#[test]
fn liberacao_dupla_remota_e_detectada_ao_recolher() {
    let global = Global::new(HostSource::new());
    let mut owner = Heap::new(&global);
    let mut other = Heap::new(&global);
    let mut rng = Rng::new(10);
    let a = block(&mut owner, &mut rng, 64, 8);
    let keep = block(&mut owner, &mut rng, 64, 8);
    release(&mut other, &a);
    // SAFETY: a segunda liberação do mesmo bloco é o que o teste provoca.
    unsafe { other.free(a.ptr.0) };
    expect_fault(Fault::DoubleFree, || owner.collect());
    let _ = keep;
}

#[test]
fn heap_que_sai_abandona_e_outro_adota() {
    let global = Global::new(HostSource::new());
    let mut rng = Rng::new(11);
    let mut first = Heap::new(&global);
    let blocks: Vec<Block> = (0..500)
        .map(|i| block(&mut first, &mut rng, [24, 300, 9000, 70_000][i % 4], 8))
        .collect();
    drop(first);
    assert!(global.mapped_segments() >= 1, "o segmento ficou abandonado");
    let mut second = Heap::new(&global);
    // Libera os blocos do heap que saiu (segmento sem dono).
    for b in &blocks {
        release(&mut second, b);
    }
    assert!(second.adopt() >= 1);
    assert_eq!(second.stats().live_blocks, 0);
    second.trim();
    drop(second);
    assert_eq!(global.mapped_segments(), 0);
    assert_eq!(global.source().live(), 0);
}

#[test]
fn adocao_reaproveita_o_segmento_abandonado() {
    let global = Global::new(HostSource::new());
    let mut rng = Rng::new(12);
    let mut first = Heap::new(&global);
    let kept = block(&mut first, &mut rng, 100, 8);
    drop(first);
    let mut second = Heap::new(&global);
    let other = block(&mut second, &mut rng, 100, 8);
    // Não pediu segmento novo: adotou o abandonado.
    assert_eq!(global.source().live(), 1);
    assert_eq!(
        kept.ptr.0.addr() & !(SEGMENT_SIZE - 1),
        other.ptr.0.addr() & !(SEGMENT_SIZE - 1)
    );
    release(&mut second, &kept);
    release(&mut second, &other);
}

// ---- aceite da T-334 ----

/// Alocações por thread: 4 × 250 000 = 10⁶.
const ALLOCS_PER_THREAD: usize = if cfg!(miri) { 400 } else { 250_000 };
const THREADS: usize = 4;
const SLOTS: usize = if cfg!(miri) { 32 } else { 512 };

/// Mistura de tamanhos da carga: muitos pequenos, alguns médios, raros
/// grandes e enormes.
fn pick_size(rng: &mut Rng) -> (usize, usize) {
    let size = match rng.below(1000) {
        0..=699 => rng.log_uniform(1, 256),
        700..=949 => rng.log_uniform(257, 8192),
        950..=989 => rng.log_uniform(8193, 524_288),
        990..=997 if !cfg!(miri) => rng.log_uniform(524_289, 1_500_000),
        _ => rng.log_uniform(1, 64),
    };
    let align = [8, 8, 8, 16, 16, 64][rng.below(6)];
    (size, align)
}

/// Resultado de uma thread da carga.
#[derive(Default)]
struct Tally {
    allocs: usize,
    frees: usize,
    sent: usize,
    received: usize,
}

fn worker(
    id: usize,
    global: &Global<HostSource>,
    inbox: &Receiver<Block>,
    peers: &[Sender<Block>],
    barrier: &Barrier,
) -> Tally {
    let mut heap = Heap::new(global);
    let mut rng = Rng::new(0x00C0_FFEE + id as u64);
    let mut slots: Vec<Option<Block>> = (0..SLOTS).map(|_| None).collect();
    let mut tally = Tally::default();
    while tally.allocs < ALLOCS_PER_THREAD {
        if rng.below(4) == 0 {
            while let Ok(b) = inbox.try_recv() {
                release(&mut heap, &b);
                tally.frees += 1;
                tally.received += 1;
            }
        }
        let i = rng.below(SLOTS);
        if let Some(b) = slots[i].take() {
            // Um terço dos blocos vai para outra thread liberar.
            if rng.below(3) == 0 {
                let to = (id + 1 + rng.below(THREADS - 1)) % THREADS;
                check(&b);
                peers[to].send(b).unwrap();
                tally.sent += 1;
            } else {
                release(&mut heap, &b);
                tally.frees += 1;
            }
        } else {
            let (size, align) = pick_size(&mut rng);
            slots[i] = Some(block(&mut heap, &mut rng, size, align));
            tally.allocs += 1;
        }
    }
    // Todos terminaram de enviar; agora cada um libera o que recebeu e o que
    // tem, e só depois recolhe.
    barrier.wait();
    while let Ok(b) = inbox.try_recv() {
        release(&mut heap, &b);
        tally.frees += 1;
        tally.received += 1;
    }
    for b in slots.iter().flatten() {
        release(&mut heap, b);
        tally.frees += 1;
    }
    barrier.wait();
    heap.trim();
    assert_eq!(
        heap.stats(),
        Stats::default(),
        "o heap {id} ficou com memória"
    );
    tally
}

#[test]
fn um_milhao_de_alocacoes_em_4_threads_sem_vazamento_nem_corrupcao() {
    let global = Global::new(HostSource::new());
    let barrier = Barrier::new(THREADS);
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..THREADS).map(|_| channel::<Block>()).unzip();
    let tallies: Vec<Tally> = thread::scope(|s| {
        let handles: Vec<_> = rxs
            .into_iter()
            .enumerate()
            .map(|(id, rx)| {
                let (global, barrier, txs) = (&global, &barrier, &txs);
                s.spawn(move || worker(id, global, &rx, txs, barrier))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let allocs: usize = tallies.iter().map(|t| t.allocs).sum();
    let frees: usize = tallies.iter().map(|t| t.frees).sum();
    let sent: usize = tallies.iter().map(|t| t.sent).sum();
    let received: usize = tallies.iter().map(|t| t.received).sum();
    println!(
        "oalloc: {allocs} alocações, {frees} liberações ({received} cruzadas), pico de {} segmentos",
        global.source().peak()
    );
    assert_eq!(allocs, THREADS * ALLOCS_PER_THREAD);
    assert_eq!(frees, allocs, "toda alocação foi liberada");
    assert_eq!(sent, received, "toda liberação cruzada chegou");
    assert!(received > 0);
    // Sem vazamento: todo segmento voltou à fonte.
    assert_eq!(global.mapped_segments(), 0);
    assert_eq!(global.source().live(), 0);
}

#[test]
fn threads_que_saem_deixam_segmentos_que_outra_thread_adota() {
    let global = Global::new(HostSource::new());
    let produced: Mutex<Vec<Block>> = Mutex::new(Vec::new());
    thread::scope(|s| {
        for id in 0..THREADS {
            let (global, produced) = (&global, &produced);
            s.spawn(move || {
                let mut heap = Heap::new(global);
                let mut rng = Rng::new(100 + id as u64);
                let n = if cfg!(miri) { 40 } else { 2000 };
                let blocks: Vec<Block> = (0..n)
                    .map(|_| {
                        let (size, align) = pick_size(&mut rng);
                        block(&mut heap, &mut rng, size, align)
                    })
                    .collect();
                produced.lock().unwrap().extend(blocks);
                // O heap morre com tudo vivo: os segmentos são abandonados.
            });
        }
    });
    let blocks = produced.into_inner().unwrap();
    let mut reaper = Heap::new(&global);
    for b in &blocks {
        release(&mut reaper, b);
    }
    reaper.adopt();
    reaper.trim();
    assert_eq!(reaper.stats(), Stats::default());
    drop(reaper);
    assert_eq!(global.mapped_segments(), 0);
    assert_eq!(global.source().live(), 0);
}

// ---- fragmentação ----

/// Bytes que o alocador reserva para um pedido (bloco da classe, páginas do
/// bloco grande ou segmentos do enorme).
fn block_bytes(size: usize) -> usize {
    match plan(size, 8) {
        Plan::Small(c) => class_size(c),
        Plan::Large(n) => n * PAGE_SIZE,
        Plan::Huge(n) => n * SEGMENT_SIZE - PAGE_SIZE,
        Plan::Fail => unreachable!(),
    }
}

struct Measure {
    name: &'static str,
    requested: usize,
    stats: Stats,
}

impl Measure {
    fn row(&self) -> String {
        let (r, b, m) = (
            self.requested as f64,
            self.stats.live_bytes as f64,
            self.stats.mapped_bytes as f64,
        );
        format!(
            "| {} | {:.1} MiB | {:.1} MiB | {:.1} MiB | {:.1}% | {:.2} |",
            self.name,
            r / 1_048_576.0,
            b / 1_048_576.0,
            m / 1_048_576.0,
            (b / r - 1.0) * 100.0,
            m / r,
        )
    }
}

/// Mantém `live` blocos vivos, trocando um aleatório por um novo `rounds`
/// vezes, com tamanhos de `lo` a `hi` (log-uniforme).
fn churn(name: &'static str, lo: usize, hi: usize, live: usize, rounds: usize) -> Measure {
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(0xF4A6);
    let mut slots: Vec<(*mut u8, usize)> = Vec::new();
    let mut requested = 0usize;
    for _ in 0..live {
        let size = rng.log_uniform(lo, hi);
        slots.push((heap.alloc(size, 8), size));
        requested += size;
    }
    for _ in 0..rounds {
        let i = rng.below(live);
        let (ptr, size) = slots[i];
        // SAFETY: bloco vivo, liberado uma vez antes de ser trocado.
        unsafe { heap.free(ptr) };
        requested -= size;
        let size = rng.log_uniform(lo, hi);
        slots[i] = (heap.alloc(size, 8), size);
        requested += size;
    }
    let measure = Measure {
        name,
        requested,
        stats: heap.stats(),
    };
    for (ptr, _) in slots {
        // SAFETY: cada bloco vivo é liberado uma vez.
        unsafe { heap.free(ptr) };
    }
    heap.trim();
    assert_eq!(heap.stats(), Stats::default());
    measure
}

/// Mede a fragmentação (bytes pedidos × ocupados × mapeados) em cargas
/// sintéticas e imprime a tabela que vai para `docs/bench/`. Rode com
/// `cargo test -p oalloc --release fragmentacao -- --nocapture`.
#[test]
fn fragmentacao_medida() {
    let scale = if cfg!(miri) { 20 } else { 1 };
    let runs = [
        churn("8 a 256 B", 8, 256, 200_000 / scale, 400_000 / scale),
        churn("8 B a 8 KiB", 8, 8192, 10_000 / scale, 400_000 / scale),
        churn("8 B a 64 KiB", 8, 65_536, 2_000 / scale, 200_000 / scale),
        churn(
            "8 KiB a 512 KiB",
            8193,
            524_288,
            200 / scale,
            20_000 / scale,
        ),
    ];
    println!(
        "| Carga | Pedido vivo | Blocos vivos | Mapeado | Perda de arredondamento | Mapeado / pedido |"
    );
    println!("|---|---:|---:|---:|---:|---:|");
    for m in &runs {
        println!("{}", m.row());
        // Os blocos nunca ocupam menos que o pedido.
        assert!(m.stats.live_bytes >= m.requested);
        assert!(m.stats.mapped_bytes >= m.stats.live_bytes);
    }
    // Até 8 KiB a perda de arredondamento é de no máximo ~20% do bloco e o
    // mapeado fica abaixo do dobro do pedido.
    for m in &runs[..2] {
        assert!(
            m.stats.live_bytes as f64 <= m.requested as f64 * 1.30,
            "{}",
            m.name
        );
        assert!(
            (m.stats.mapped_bytes as f64) < m.requested as f64 * 2.0,
            "{}",
            m.name
        );
    }

    println!();
    println!("| Pedido | Bloco | Perda |");
    println!("|---:|---:|---:|");
    for size in [
        1, 8, 9, 24, 33, 65, 100, 1000, 4097, 8192, 8193, 40_000, 65_537, 524_288, 524_289,
    ] {
        let b = block_bytes(size);
        println!(
            "| {size} B | {b} B | {:.1}% |",
            (b - size) as f64 / b as f64 * 100.0
        );
    }

    // Retenção depois de um pico: aloca 200 000 blocos de 64 B, libera 9 de
    // cada 10 ao acaso e mede o que ficou mapeado.
    let global = Global::new(HostSource::new());
    let mut heap = Heap::new(&global);
    let mut rng = Rng::new(0xBEE5);
    let n = 200_000 / scale;
    let mut blocks: Vec<*mut u8> = (0..n).map(|_| heap.alloc(64, 8)).collect();
    let peak = heap.stats().mapped_bytes;
    let mut kept = Vec::new();
    for ptr in blocks.drain(..) {
        if rng.below(10) == 0 {
            kept.push(ptr);
        } else {
            // SAFETY: bloco vivo, liberado uma vez.
            unsafe { heap.free(ptr) };
        }
    }
    heap.collect();
    let after = heap.stats();
    println!();
    println!(
        "pico: {:.1} MiB mapeados; depois de liberar 90% ao acaso: {:.1} MiB mapeados para {:.1} MiB vivos",
        peak as f64 / 1_048_576.0,
        after.mapped_bytes as f64 / 1_048_576.0,
        after.live_bytes as f64 / 1_048_576.0
    );
    for ptr in kept {
        // SAFETY: bloco vivo, liberado uma vez.
        unsafe { heap.free(ptr) };
    }
    heap.trim();
    assert_eq!(heap.stats(), Stats::default());
}
