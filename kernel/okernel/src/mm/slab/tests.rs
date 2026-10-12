//! Testes no host do slab e do heap.

use super::*;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Memória falsa: palavras num mapa e blocos alinhados vindos de um ponteiro
/// que só cresce.
#[derive(Default)]
struct Fake {
    words: HashMap<u64, u64>,
    next: u64,
    live: HashSet<(u64, usize)>,
    deny: bool,
}

impl PageSource for Fake {
    fn alloc_pages(&mut self, order: usize) -> Option<u64> {
        if self.deny {
            return None;
        }
        let bytes = FRAME_SIZE << order;
        let addr = (0x1_0000_0000 + self.next).next_multiple_of(bytes);
        self.next = addr + bytes - 0x1_0000_0000;
        self.live.insert((addr, order));
        Some(addr)
    }

    fn free_pages(&mut self, addr: u64, order: usize) {
        assert!(
            self.live.remove(&(addr, order)),
            "bloco liberado duas vezes"
        );
    }

    fn read(&mut self, addr: u64) -> u64 {
        assert_eq!(addr % 8, 0);
        self.words.get(&addr).copied().unwrap_or(0xdead_beef)
    }

    fn write(&mut self, addr: u64, value: u64) {
        assert_eq!(addr % 8, 0);
        self.words.insert(addr, value);
    }
}

fn layout(size: usize, align: usize) -> Layout {
    Layout::from_size_align(size, align).unwrap()
}

const MIB: u64 = 1 << 20;

#[test]
fn geometria_dos_caches() {
    let heap = Heap::new(Fake::default(), MIB);
    let per_slab: Vec<_> = heap.cache_stats().iter().map(|s| s.per_slab).collect();
    assert_eq!(per_slab, [254, 127, 63, 31, 15, 7, 15, 7]);
    assert_eq!(class(layout(1, 1)), Some(0));
    assert_eq!(class(layout(17, 8)), Some(1));
    assert_eq!(class(layout(8, 256)), Some(4));
    assert_eq!(class(layout(2048, 8)), Some(7));
    assert_eq!(class(layout(2049, 8)), None);
    assert_eq!(large_order(layout(4097, 8)), Some(1));
    assert_eq!(large_order(layout(8, 1 << 14)), Some(2));
}

#[test]
fn aloca_libera_e_alinha_em_todos_os_caches() {
    let mut heap = Heap::new(Fake::default(), MIB);
    for (i, &size) in CLASSES.iter().enumerate() {
        let l = layout(size, size);
        let objs: Vec<_> = (0..20).map(|_| heap.alloc(l).unwrap()).collect();
        assert!(objs.iter().all(|a| a % size as u64 == 0));
        let unique: HashSet<_> = objs.iter().collect();
        assert_eq!(unique.len(), objs.len());
        let s = heap.cache_stats()[i];
        assert_eq!((s.in_use, s.allocs), (20, 20));
        for a in objs {
            heap.free(a, l).unwrap();
        }
        let s = heap.cache_stats()[i];
        assert_eq!((s.in_use, s.frees, s.slabs), (0, 20, 1));
    }
    let big = layout(10_000, 8);
    let a = heap.alloc(big).unwrap();
    assert_eq!(a % (16 << 10), 0);
    assert_eq!(heap.large_stats().bytes, 16 << 10);
    heap.free(a, big).unwrap();
    assert_eq!(
        heap.large_stats(),
        LargeStats {
            bytes: 0,
            allocs: 1,
            frees: 1
        }
    );
}

#[test]
fn limite_vira_erro_e_nao_panico() {
    let mut heap = Heap::new(Fake::default(), 2 * FRAME_SIZE);
    let l = layout(512, 8);
    let objs: Vec<_> = (0..14).map(|_| heap.alloc(l).unwrap()).collect();
    assert_eq!(heap.alloc(l), Err(HeapError::LimitExceeded));
    assert_eq!(heap.alloc(layout(5000, 8)), Err(HeapError::LimitExceeded));
    assert_eq!(heap.failures(), 2);
    assert!(heap.used() <= heap.limit());
    heap.free(objs[0], l).unwrap();
    assert!(heap.alloc(l).is_ok());
    assert_eq!(heap.alloc(layout(1 << 40, 8)), Err(HeapError::TooLarge));

    let mut empty = Heap::new(
        Fake {
            deny: true,
            ..Fake::default()
        },
        MIB,
    );
    assert_eq!(empty.alloc(l), Err(HeapError::OutOfMemory));
    assert_eq!(empty.used(), 0);
}

#[test]
fn liberacao_invalida_e_recusada() {
    let mut heap = Heap::new(Fake::default(), MIB);
    let l = layout(64, 8);
    let a = heap.alloc(l).unwrap();
    // No cabeçalho, desalinhado, fora de qualquer slab.
    let slab = a & !(FRAME_SIZE - 1);
    assert_eq!(heap.free(slab, l), Err(HeapError::BadFree));
    assert_eq!(heap.free(a + 8, l), Err(HeapError::BadFree));
    assert_eq!(heap.free(0x7_0000_0040, l), Err(HeapError::BadFree));
    heap.free(a, l).unwrap();
    // Liberação dupla que zeraria a contagem de novo.
    assert_eq!(heap.free(a, l), Err(HeapError::BadFree));
}

#[test]
fn objetos_por_classe_para_os_caches_por_cpu() {
    let mut heap = Heap::new(Fake::default(), MIB);
    for (i, &size) in CLASSES.iter().enumerate() {
        let a = heap.alloc_class(i).unwrap();
        // Serve a qualquer layout da classe: tamanho e alinhamento.
        assert_eq!(class(layout(size, size)), Some(i));
        assert!(a.is_multiple_of(size as u64));
        assert!(plausible(i, a));
        assert!(!plausible(i, a + 8));
        assert!(!plausible(i, a & !(FRAME_SIZE - 1)));
        // O objeto volta pela classe ou pelo layout, indistintamente.
        heap.free_class(i, a).unwrap();
        assert_eq!(heap.free_class(i, a), Err(HeapError::BadFree));
        let b = heap.alloc_class(i).unwrap();
        heap.free(b, layout(size, 8)).unwrap();
    }
    assert_eq!(heap.alloc_class(CLASSES.len()), None);
    assert_eq!(heap.free_class(CLASSES.len(), 0), Err(HeapError::BadFree));
    assert!(!plausible(CLASSES.len(), 0x1_0000_0040));
    assert_eq!(heap.failures(), 0);
    // Sem páginas, o cache só deixa de encher: não é falha do heap.
    let mut empty = Heap::new(Fake::default(), 0);
    assert_eq!(empty.alloc_class(0), None);
    assert_eq!(empty.failures(), 0);
}

/// PRNG xorshift64.
struct XorShift(u64);

impl XorShift {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

#[test]
fn cem_mil_operacoes_aleatorias_sem_sobreposicao() {
    let mut heap = Heap::new(Fake::default(), 64 * MIB);
    let mut rng = XorShift(0x5eed);
    let mut live: BTreeMap<u64, Layout> = BTreeMap::new();
    for _ in 0..100_000 {
        if live.is_empty() || rng.below(100) < 55 {
            let size = 1 + usize::try_from(rng.below(3000)).unwrap();
            let align = 1 << rng.below(7);
            let l = layout(size, align);
            let a = heap.alloc(l).unwrap();
            assert_eq!(a % align as u64, 0);
            // Nenhum vizinho vivo se sobrepõe ao novo objeto.
            if let Some((&prev, pl)) = live.range(..=a).next_back() {
                assert!(prev + pl.size() as u64 <= a);
            }
            if let Some((&next, _)) = live.range(a..).next() {
                assert!(a + size as u64 <= next);
            }
            live.insert(a, l);
        } else {
            let skip = usize::try_from(rng.below(live.len() as u64)).unwrap();
            let (&a, &l) = live.iter().nth(skip).unwrap();
            live.remove(&a);
            heap.free(a, l).unwrap();
        }
    }
    for (a, l) in live {
        heap.free(a, l).unwrap();
    }
    let stats = heap.cache_stats();
    assert!(stats.iter().all(|s| s.in_use == 0 && s.slabs <= KEEP_EMPTY));
    assert!(stats.iter().all(|s| s.allocs == s.frees));
    assert_eq!(heap.large_stats().bytes, 0);
    let kept: u64 = heap
        .caches
        .iter()
        .map(|c| c.stats.slabs as u64 * c.bytes())
        .sum();
    assert_eq!(heap.used(), kept);
    assert_eq!(
        heap.mem.live.len(),
        stats.iter().map(|s| s.slabs).sum::<usize>()
    );
}
