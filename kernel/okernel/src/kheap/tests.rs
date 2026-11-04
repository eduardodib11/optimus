//! Testes de kernel do heap (T-108).

use alloc::alloc::dealloc;
use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::alloc::Layout;

use okernel::mm::slab::HeapError;

use super::{
    KEPT_FRAMES, WINDOW_END, WINDOW_START, choose_window_base, drain_object_cache, live_blocks,
    set_limit, try_alloc, usage, window_base, window_tables,
};
use crate::kmem::{self, frame_stats};
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
    Test {
        name: "heap.na_faixa_de_objetos",
        run: na_faixa,
    },
    Test {
        name: "heap.bloco_solto_sai_da_janela",
        run: bloco_solto,
    },
];

fn colecoes() -> Outcome {
    let before = live_blocks();
    let boxed = Box::new(0x0123_4567_89ab_cdefu64);
    let mut v: Vec<u32> = Vec::new();
    for i in 0..1000 {
        v.push(i * 3);
    }
    let text = format!("{} itens, soma {}", v.len(), v.iter().sum::<u32>());
    ensure!(*boxed == 0x0123_4567_89ab_cdef);
    ensure!(v.iter().enumerate().all(|(i, &x)| x as usize == i * 3));
    ensure!(text == "1000 itens, soma 1498500");
    // A caixa, o vetor e o texto: contados mesmo vindo do cache da CPU.
    ensure!(live_blocks() == before + 3);
    drop((boxed, v, text));
    ensure!(live_blocks() == before);
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
    let tables_before = window_tables();
    let objects: Vec<Box<[u8; 128]>> = (0..2000).map(|_| Box::new([7; 128])).collect();
    let (free_during, _) = frame_stats();
    ensure!(objects.iter().all(|o| o[127] == 7));
    // 2000 objetos de 128 bytes ocupam ao menos 64 slabs de 4 KiB.
    ensure!(free_during + 64 <= free_before);
    drop(objects);
    // Os objetos parados no cache desta CPU seguram os slabs deles.
    drain_object_cache();
    let (free_after, _) = frame_stats();
    // Só o slab vazio guardado, os blocos que a janela deixa mapeados e as
    // tabelas novas dela podem continuar fora do buddy.
    let tables = usize::try_from(window_tables() - tables_before).map_err(|_| "tabelas")?;
    let kept = usize::try_from(KEPT_FRAMES).map_err(|_| "guardados")?;
    ensure!(free_after + 1 + kept + tables >= free_before);
    Ok(())
}

/// O heap mora na faixa de objetos da seção 6.4, fora do mapa direto, em
/// páginas RW, NX e globais que apontam para o mesmo frame que o mapa
/// direto mostra.
fn na_faixa() -> Outcome {
    let base = window_base();
    ensure!((WINDOW_START..WINDOW_END).contains(&base) && base.is_multiple_of(1 << 30));
    ensure!(base + kmem::managed_end() <= WINDOW_END);
    let boxed = Box::new(0x1234_5678_9abc_def0_u64);
    let addr = core::ptr::from_ref(&*boxed).addr() as u64;
    ensure!((base..base + kmem::managed_end()).contains(&addr));
    let m = kmem::translate(addr).ok_or("objeto sem mapeamento")?;
    ensure!(m.flags.write && !m.flags.exec && m.flags.global && m.phys.0 == addr - base);
    // SAFETY: o mesmo frame, lido pelo mapa direto (RW, alinhado a 8).
    let alias = unsafe { (kmem::direct(m.phys) as *const u64).read_volatile() };
    ensure!(alias == *boxed);
    // A faixa inteira cabe para qualquer sorteio, e RAM demais é recusada.
    ensure!(choose_window_base(0, 1 << 30) == Some(WINDOW_START));
    ensure!(choose_window_base(u64::MAX, 1 << 30).is_some_and(|b| b + (1 << 30) <= WINDOW_END));
    ensure!(choose_window_base(1, WINDOW_END - WINDOW_START + 1).is_none());
    Ok(())
}

/// Um bloco grande (64 KiB, ordem 4) solto é desmapeado da janela.
fn bloco_solto() -> Outcome {
    let layout = Layout::from_size_align(64 << 10, 8).map_err(|_| "layout")?;
    let ptr = try_alloc(layout).map_err(|_| "try_alloc falhou")?;
    let addr = ptr.addr().get() as u64;
    let mapped = (0..16).all(|i| kmem::translate(addr + i * 4096).is_some());
    // SAFETY: o bloco veio do alocador global com este layout.
    unsafe { dealloc(ptr.as_ptr(), layout) };
    ensure!(mapped);
    ensure!((0..16).all(|i| kmem::translate(addr + i * 4096).is_none()));
    Ok(())
}
