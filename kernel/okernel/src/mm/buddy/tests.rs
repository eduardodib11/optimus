//! Testes no host do alocador buddy.

use super::*;
use std::time::Instant;

const MIB: u64 = 1 << 20;

/// PRNG xorshift64: determinístico e sem dependências.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

#[test]
fn divide_e_coalesce() {
    let mut meta = vec![FrameMeta::EMPTY; 1024];
    let mut a = FrameAllocator::new(PhysAddr(0), &mut meta).unwrap();
    assert_eq!(a.add_region(PhysAddr(0), 4 * MIB), Ok(1024));
    assert_eq!(a.free_blocks()[10], 1);

    let x = a.alloc(0).unwrap();
    assert_eq!(x, PhysAddr(0));
    // Um bloco de 4 MiB vira um livre de cada ordem 0..=9.
    assert!((0..10).all(|k| a.free_blocks()[k] == 1));
    assert_eq!((a.used_frames(), a.free_frames()), (1, 1023));
    let y = a.alloc(0).unwrap();
    assert_eq!(y, PhysAddr(FRAME_SIZE));
    let z = a.alloc(3).unwrap();
    assert_eq!(z.0 % (8 * FRAME_SIZE), 0);
    assert_eq!(a.used_blocks()[3], 1);

    a.free(y, 0).unwrap();
    a.free(z, 3).unwrap();
    a.free(x, 0).unwrap();
    assert_eq!(a.free_blocks()[10], 1);
    assert_eq!((a.free_frames(), a.used_frames()), (1024, 0));
}

#[test]
fn fronteiras_nao_alinhadas_e_buracos() {
    let mut meta = vec![FrameMeta::EMPTY; 512];
    let base = PhysAddr(MIB);
    let mut a = FrameAllocator::new(base, &mut meta).unwrap();
    // Bordas parciais descartadas: dos 10 frames tocados sobram 8 inteiros.
    assert_eq!(a.add_region(PhysAddr(MIB + 1), 10 * FRAME_SIZE - 2), Ok(8));
    // Fora da faixa é recortado; antes da base nada entra.
    assert_eq!(a.add_region(PhysAddr(0), MIB), Ok(0));
    assert_eq!(
        a.add_region(PhysAddr(MIB + 256 * FRAME_SIZE), 8 * MIB),
        Ok(256)
    );
    assert_eq!(
        a.add_region(PhysAddr(MIB), 4 * FRAME_SIZE),
        Err(BuddyError::Overlap)
    );
    assert_eq!(a.managed_frames(), 264);
    assert_eq!(a.alloc(9), None);
    assert_eq!(a.alloc(8), Some(PhysAddr(MIB + 256 * FRAME_SIZE)));
    // O buraco não é entregue: restam 8 frames em blocos de ordem 0 a 2.
    assert_eq!(a.alloc(3), None);
    assert_eq!(a.free_frames(), 8);
    assert!(a.alloc(1).is_some());
}

#[test]
fn double_free_e_enderecos_invalidos() {
    let mut meta = vec![FrameMeta::EMPTY; 64];
    let mut a = FrameAllocator::new(PhysAddr(0), &mut meta).unwrap();
    assert_eq!(
        FrameAllocator::new(PhysAddr(1), &mut [FrameMeta::EMPTY; 1]).err(),
        Some(BuddyError::BadSpan)
    );
    a.add_region(PhysAddr(0), 64 * FRAME_SIZE).unwrap();
    let x = a.alloc(2).unwrap();
    let y = a.alloc(2).unwrap();
    assert_eq!(a.free(x, 1), Err(BuddyError::WrongOrder));
    assert_eq!(a.free(x, MAX_ORDER + 1), Err(BuddyError::BadOrder));
    assert_eq!(a.free(PhysAddr(x.0 + 1), 0), Err(BuddyError::BadAddress));
    assert_eq!(a.free(PhysAddr(x.0 + 4), 2), Err(BuddyError::BadAddress));
    assert_eq!(
        a.free(PhysAddr(64 * FRAME_SIZE), 0),
        Err(BuddyError::BadAddress)
    );
    // Frame interno de bloco alocado e frame livre.
    let inner = PhysAddr(x.0 + FRAME_SIZE);
    assert_eq!(a.free(inner, 0), Err(BuddyError::NotAllocated));
    a.free(x, 2).unwrap();
    assert_eq!(a.free(x, 2), Err(BuddyError::NotAllocated));
    a.free(y, 2).unwrap();
    assert_eq!(a.free(y, 2), Err(BuddyError::NotAllocated));
    assert_eq!((a.free_frames(), a.used_frames()), (64, 0));
    assert_eq!(a.free_blocks()[6], 1);
}

#[test]
fn um_milhao_de_operacoes_aleatorias_sem_vazamento() {
    const FRAMES: usize = 8192;
    const OPS: usize = 1_000_000;
    let base = PhysAddr(MIB);
    let mut meta = vec![FrameMeta::EMPTY; FRAMES];
    let mut a = FrameAllocator::new(base, &mut meta).unwrap();
    // Duas regiões desalinhadas com um buraco no meio, como num mapa de memória real.
    let regions = [(MIB + 123, 12 * MIB - 0x2000), (14 * MIB + 0x800, 18 * MIB)];
    let mut usable = vec![false; FRAMES];
    for (start, len) in regions {
        a.add_region(PhysAddr(start), len).unwrap();
        let first = start.div_ceil(FRAME_SIZE) - base.0 / FRAME_SIZE;
        let last = ((start + len) / FRAME_SIZE - base.0 / FRAME_SIZE).min(FRAMES as u64);
        for f in first..last {
            usable[usize::try_from(f).unwrap()] = true;
        }
    }
    let total = a.free_frames();
    assert_eq!(total, usable.iter().filter(|&&u| u).count());
    assert_eq!(a.managed_frames(), total);
    let initial = a.free_blocks();

    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut taken = vec![false; FRAMES];
    let mut live: Vec<(PhysAddr, usize)> = Vec::new();
    let (mut allocs, mut fails) = (0usize, 0usize);
    let start = Instant::now();
    for op in 0..OPS {
        if live.is_empty() || rng.below(100) < 52 {
            // Ordens pequenas são mais comuns: P(k) ~ 2^-(k+1), até 10.
            let order = (rng.next().trailing_zeros() as usize).min(10);
            if let Some(addr) = a.alloc(order) {
                allocs += 1;
                assert_eq!(addr.0 % (FRAME_SIZE << order), 0);
                let first = usize::try_from((addr.0 - base.0) / FRAME_SIZE).unwrap();
                for f in first..first + (1 << order) {
                    assert!(usable[f] && !taken[f], "sobreposição no frame {f}");
                    taken[f] = true;
                }
                live.push((addr, order));
            } else {
                fails += 1;
                assert!(a.free_blocks()[order..].iter().all(|&n| n == 0));
            }
        } else {
            let (addr, order) = live.swap_remove(rng.below(live.len()));
            let first = usize::try_from((addr.0 - base.0) / FRAME_SIZE).unwrap();
            taken[first..first + (1 << order)].fill(false);
            a.free(addr, order).unwrap();
            assert_eq!(a.free(addr, order), Err(BuddyError::NotAllocated));
        }
        if op % 4096 == 0 {
            assert_eq!(a.free_frames() + a.used_frames(), total);
            assert_eq!(a.used_frames(), taken.iter().filter(|&&t| t).count());
        }
    }
    for (addr, order) in live.drain(..) {
        a.free(addr, order).unwrap();
    }
    let elapsed = start.elapsed();
    assert_eq!((a.free_frames(), a.used_frames()), (total, 0));
    // Coalescência completa: mesmos blocos livres do início.
    assert_eq!(a.free_blocks(), initial);
    println!(
        "{OPS} operações ({allocs} alocações, {fails} falhas por falta de memória) em {elapsed:?}"
    );
}
