#![allow(clippy::cast_possible_truncation)]

use super::*;
use std::collections::HashMap;

fn blk(seed: u64) -> [u8; BLOCK_SIZE] {
    let mut b = [0u8; BLOCK_SIZE];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (seed as u8).wrapping_add(i as u8).wrapping_mul(3);
    }
    b
}

#[test]
fn despeja_o_menos_recente() {
    let mut c = BlockCache::with_capacity(2);
    c.insert(1, &blk(1));
    c.insert(2, &blk(2));
    assert!(c.get(1).is_some()); // 2 vira o menos recente
    c.insert(3, &blk(3));
    assert!(c.get(2).is_none());
    assert_eq!(c.get(1), Some(&blk(1)));
    assert_eq!(c.get(3), Some(&blk(3)));
    assert_eq!(c.stats().evictions, 1);
}

#[test]
fn cota_em_bytes_vira_blocos_e_zero_nao_guarda() {
    assert_eq!(BlockCache::with_quota(10 * BLOCK_SIZE + 100).capacity(), 10);
    let mut c = BlockCache::with_quota(100);
    c.insert(1, &blk(1));
    assert!(c.is_empty() && c.get(1).is_none());
}

#[test]
fn trocar_e_invalidar() {
    let mut c = BlockCache::with_capacity(4);
    c.insert(7, &blk(1));
    c.insert(7, &blk(2));
    assert_eq!(c.len(), 1);
    assert_eq!(c.get(7), Some(&blk(2)));
    c.invalidate(7);
    assert!(c.get(7).is_none());
    c.invalidate(7);
}

#[test]
fn pressao_baixa_o_limite_e_devolve_memoria() {
    let mut c = BlockCache::with_capacity(8);
    for a in 0..8 {
        c.insert(a, &blk(a));
    }
    let _ = c.get(0);
    assert_eq!(c.trim(3), 5);
    assert_eq!((c.len(), c.capacity(), c.bytes()), (3, 3, 3 * BLOCK_SIZE));
    assert!(c.get(0).is_some(), "o mais recente sobrevive");
    c.insert(100, &blk(100));
    assert_eq!(c.len(), 3);
    c.grow(6, 8);
    assert_eq!(c.capacity(), 6);
    c.grow(50, 8);
    assert_eq!(c.capacity(), 8);
}

/// Estresse: operações aleatórias, com pressão no meio. O cache nunca passa
/// do limite, e todo acerto devolve o último valor gravado (modelo).
#[test]
fn estresse_contra_um_modelo() {
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    let mut c = BlockCache::with_capacity(32);
    let mut model: HashMap<u64, u64> = HashMap::new();
    for step in 0..40_000u64 {
        let addr = next() % 96;
        match next() % 8 {
            0..=2 => {
                let v = next();
                c.insert(addr, &blk(v));
                model.insert(addr, v);
            }
            3 => {
                c.invalidate(addr);
                model.remove(&addr);
            }
            4 if step % 500 == 0 => {
                let keep = (next() % 32) as usize;
                c.trim(keep);
                c.grow(32, 32);
            }
            _ => {
                if let Some(b) = c.get(addr) {
                    assert_eq!(*b, blk(model[&addr]), "bloco {addr} no passo {step}");
                }
            }
        }
        assert!(c.len() <= c.capacity() && c.capacity() <= 32);
    }
    assert!(c.stats().hits > 1000 && c.stats().evictions > 1000);
}
