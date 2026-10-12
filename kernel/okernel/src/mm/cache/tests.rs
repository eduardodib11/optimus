use std::vec::Vec;

use super::{
    FRAME_BATCH, FRAME_CAPACITY, FrameCache, Magazine, OBJECT_CAPACITY, ObjectCache, object_cache,
};
use crate::mm::slab::CLASSES;

fn frame(i: u64) -> u64 {
    0x10_0000 + i * 4096
}

#[test]
fn pilha_devolve_o_ultimo_que_entrou() {
    let mut c = FrameCache::new();
    assert!(c.is_empty() && c.pop().is_none());
    assert!(c.push(frame(1)) && c.push(frame(2)));
    assert!(c.contains(frame(1)) && !c.contains(frame(3)));
    assert_eq!(c.pop(), Some(frame(2)));
    assert_eq!(c.pop(), Some(frame(1)));
    assert_eq!(c.pop(), None);
    assert!(!c.contains(frame(1)));
}

#[test]
fn cheia_recusa_e_esvazia_um_lote() {
    let mut c = FrameCache::new();
    for i in 0..FRAME_CAPACITY as u64 {
        assert!(c.push(frame(i)));
    }
    assert!(!c.push(frame(999)));
    let mut out = Vec::new();
    assert_eq!(c.spill(FRAME_BATCH, &mut |f| out.push(f)), FRAME_BATCH);
    assert_eq!(c.len(), FRAME_CAPACITY - FRAME_BATCH);
    // Saem os do topo, do último para o primeiro.
    assert_eq!(out[0], frame(FRAME_CAPACITY as u64 - 1));
    assert!(c.push(frame(999)));
    let mut rest = 0;
    c.spill(usize::MAX, &mut |_| rest += 1);
    assert_eq!(rest, FRAME_CAPACITY - FRAME_BATCH + 1);
    assert!(c.is_empty());
}

#[test]
fn vazia_traz_um_lote_e_para_no_primeiro_none() {
    let mut c = FrameCache::new();
    let mut next = 0;
    let mut source = || {
        next += 1;
        Some(frame(next))
    };
    assert_eq!(c.refill(FRAME_BATCH, &mut source), FRAME_BATCH);
    assert_eq!(c.len(), FRAME_BATCH);
    let mut left = 3;
    let got = c.refill(FRAME_BATCH, &mut || {
        if left == 0 {
            return None;
        }
        left -= 1;
        Some(frame(100 + left))
    });
    assert_eq!(got, 3);
    assert_eq!(c.len(), FRAME_BATCH + 3);
}

#[test]
fn enche_sem_passar_da_capacidade() {
    let mut c = Magazine::<8>::new();
    for i in 0..5 {
        assert!(c.push(frame(i)));
    }
    let mut next = 1000;
    let got = c.refill(4, &mut || {
        next += 1;
        Some(frame(next))
    });
    assert_eq!(got, 3);
    assert_eq!(c.len(), 8);
}

#[test]
fn cache_de_objetos_tem_uma_pilha_por_classe() {
    let mut c: ObjectCache = object_cache();
    assert_eq!(c.len(), CLASSES.len());
    for (i, m) in c.iter_mut().enumerate() {
        for k in 0..OBJECT_CAPACITY as u64 {
            assert!(m.push(i as u64 * 0x1000 + k * 16));
        }
        assert!(!m.push(0));
    }
    assert!(c.iter().all(|m| m.len() == OBJECT_CAPACITY));
}

#[test]
fn nada_se_perde_nem_se_repete() {
    // Simula o buddy com um conjunto e a pilha na frente dele.
    let mut buddy: Vec<u64> = (0..500).map(frame).collect();
    let mut c = FrameCache::new();
    let mut held = Vec::new();
    let mut seed = 7u64;
    for _ in 0..20_000 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        if seed >> 63 == 0 || held.is_empty() {
            if c.is_empty() {
                c.refill(FRAME_BATCH, &mut || buddy.pop());
            }
            if let Some(f) = c.pop() {
                held.push(f);
            }
        } else {
            let i = (seed >> 33) as usize % held.len();
            let f = held.swap_remove(i);
            if !c.push(f) {
                c.spill(FRAME_BATCH, &mut |g| buddy.push(g));
                assert!(c.push(f));
            }
        }
    }
    c.spill(usize::MAX, &mut |g| buddy.push(g));
    buddy.extend(held);
    buddy.sort_unstable();
    buddy.dedup();
    assert_eq!(buddy.len(), 500);
}
