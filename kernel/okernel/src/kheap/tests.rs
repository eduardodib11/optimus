//! Testes de kernel do heap (T-108).

use alloc::alloc::dealloc;
use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::alloc::Layout;

use okernel::mm::slab::HeapError;

use super::{HEAP, set_limit, try_alloc, usage};
use crate::kmem::frame_stats;
use crate::ktest::{Outcome, Test};

/// Testes de kernel do heap.
pub const TESTS: &[Test] = &[
    Test {
        name: "heap.box_vec_e_string",
        run: colecoes,
    },
    Test {
        name: "heap.alinhamento",
        run: alinhamento,
    },
    Test {
        name: "heap.limite_devolve_erro",
        run: limite,
    },
    Test {
        name: "heap.slabs_voltam_ao_buddy",
        run: slabs_voltam,
    },
];

fn allocs() -> u64 {
    HEAP.lock().cache_stats().iter().map(|s| s.allocs).sum()
}

fn colecoes() -> Outcome {
    let before = allocs();
    let boxed = Box::new(0x0123_4567_89ab_cdefu64);
    let mut v: Vec<u32> = Vec::new();
    for i in 0..1000 {
        v.push(i * 3);
    }
    let text = format!("{} itens, soma {}", v.len(), v.iter().sum::<u32>());
    ensure!(*boxed == 0x0123_4567_89ab_cdef);
    ensure!(v.iter().enumerate().all(|(i, &x)| x as usize == i * 3));
    ensure!(text == "1000 itens, soma 1498500");
    ensure!(allocs() > before);
    Ok(())
}

fn alinhamento() -> Outcome {
    for (size, align) in [(8, 64), (100, 4096), (5000, 8192), (24, 8)] {
        let layout = Layout::from_size_align(size, align).map_err(|_| "layout")?;
        let ptr = try_alloc(layout).map_err(|_| "try_alloc falhou")?;
        ensure!(ptr.addr().get().is_multiple_of(align));
        // SAFETY: o bloco veio do alocador global com este layout.
        unsafe { dealloc(ptr.as_ptr(), layout) };
    }
    Ok(())
}

fn limite() -> Outcome {
    let (limit, used) = usage();
    set_limit(used);
    let big = Layout::from_size_align(8192, 8).map_err(|_| "layout")?;
    let refused = try_alloc(big);
    let mut v: Vec<u8> = Vec::new();
    let reserve = v.try_reserve(1 << 20);
    set_limit(limit);
    ensure!(refused == Err(HeapError::LimitExceeded));
    ensure!(reserve.is_err());
    ensure!(usage().1 == used);
    Ok(())
}

fn slabs_voltam() -> Outcome {
    let (free_before, _) = frame_stats();
    let objects: Vec<Box<[u8; 128]>> = (0..2000).map(|_| Box::new([7; 128])).collect();
    let (free_during, _) = frame_stats();
    ensure!(objects.iter().all(|o| o[127] == 7));
    // 2000 objetos de 128 bytes ocupam ao menos 64 slabs de 4 KiB.
    ensure!(free_during + 64 <= free_before);
    drop(objects);
    let (free_after, _) = frame_stats();
    // Só o slab vazio guardado pode continuar fora do buddy.
    ensure!(free_after + 1 >= free_before);
    Ok(())
}
