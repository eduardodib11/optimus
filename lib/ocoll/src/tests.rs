//! Testes de propriedade no host: modelo contra implementação com
//! sequências aleatórias (PRNG próprio, sem crates externas, ADR 0003).

#![allow(clippy::cast_possible_truncation, clippy::similar_names)]

extern crate std;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::hash::{BuildHasher, DefaultHasher, Hash, Hasher};
use std::string::String;
use std::vec::Vec;

use crate::prng::{SplitMix64, Xoshiro256pp};
use crate::utf8::{self, Decoder, Utf8Error};
use crate::{HashMap, HashSet, RandomState, Ring, SipHasher13, is_seeded, seed_random_state};

/// Quantas rodadas cada teste de propriedade faz.
const ROUNDS: u64 = if cfg!(miri) { 4 } else { 200 };

// ---- SipHash-1-3 ----

#[test]
fn siphash13_confere_com_o_do_std() {
    // `DefaultHasher::new()` é SipHash-1-3 com chave zero.
    let mut rng = Xoshiro256pp::from_u64(1);
    for _ in 0..ROUNDS {
        let mut ours = SipHasher13::new_with_keys(0, 0);
        let mut theirs = DefaultHasher::new();
        // Várias escritas de tamanhos variados: o resto pendente atravessa
        // fronteiras de palavra.
        for _ in 0..rng.below(8) {
            let mut buf = std::vec![0u8; rng.below(40) as usize];
            rng.fill(&mut buf);
            ours.write(&buf);
            theirs.write(&buf);
            assert_eq!(ours.finish(), theirs.finish(), "{buf:?}");
        }
    }
    let mut a = SipHasher13::new_with_keys(0, 0);
    let mut b = DefaultHasher::new();
    "olá, mundo".hash(&mut a);
    "olá, mundo".hash(&mut b);
    assert_eq!(a.finish(), b.finish());
}

#[test]
fn siphash13_depende_da_chave() {
    let h = |k0, k1| {
        let mut s = SipHasher13::new_with_keys(k0, k1);
        s.write(b"mesma mensagem");
        s.finish()
    };
    assert_eq!(h(1, 2), h(1, 2));
    assert_ne!(h(1, 2), h(1, 3));
    assert_ne!(h(1, 2), h(2, 2));
}

// ---- HashMap ----

/// Hasher ruim de propósito: poucos valores de hash, muitas colisões e
/// aglomerados longos (o pior caso do Robin Hood).
#[derive(Clone, Default)]
struct Coarse(u64);

impl Hasher for Coarse {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.wrapping_mul(31).wrapping_add(u64::from(b));
        }
    }

    fn finish(&self) -> u64 {
        (self.0 % 13).wrapping_mul(0x0101_0101)
    }
}

#[derive(Clone, Default)]
struct CoarseState;

impl BuildHasher for CoarseState {
    type Hasher = Coarse;

    fn build_hasher(&self) -> Coarse {
        Coarse(0)
    }
}

fn model_run<S: BuildHasher + Default + Clone>(seed: u64, key_range: u64, ops: usize) {
    let mut rng = Xoshiro256pp::from_u64(seed);
    let mut map: HashMap<u64, u64, S> = HashMap::default();
    let mut model = BTreeMap::new();
    for step in 0..ops {
        let key = rng.below(key_range);
        match rng.below(10) {
            0..=3 => {
                let value = rng.next_u64();
                assert_eq!(map.insert(key, value), model.insert(key, value), "insert");
            }
            4..=5 => assert_eq!(map.remove(&key), model.remove(&key), "remove {key}"),
            6 => {
                let got = *map.get_or_insert_with(key, || key * 3);
                assert_eq!(got, *model.entry(key).or_insert(key * 3));
            }
            7 => {
                if let Some(v) = map.get_mut(&key) {
                    *v ^= 1;
                    *model.get_mut(&key).unwrap() ^= 1;
                }
            }
            8 => {
                assert_eq!(map.get(&key), model.get(&key));
                assert_eq!(map.contains_key(&key), model.contains_key(&key));
            }
            _ => {
                if rng.below(50) == 0 {
                    let m = rng.below(3) + 2;
                    map.retain(|k, _| k % m != 0);
                    model.retain(|k, _| k % m != 0);
                }
            }
        }
        assert_eq!(map.len(), model.len());
        if step % 16 == 0 {
            map.check_invariants();
        }
    }
    map.check_invariants();
    let got: BTreeMap<u64, u64> = map.iter().map(|(k, v)| (*k, *v)).collect();
    assert_eq!(got, model);
    assert_eq!(map.iter().len(), model.len());
    let mut owned: Vec<_> = map.clone().into_iter().collect();
    owned.sort_unstable();
    assert_eq!(owned, model.into_iter().collect::<Vec<_>>());
}

#[test]
fn hashmap_confere_com_o_modelo() {
    for seed in 0..ROUNDS / 4 {
        model_run::<RandomState>(seed, 64, 600);
        model_run::<RandomState>(seed + 1000, 5000, 600);
    }
}

#[test]
fn hashmap_com_colisoes_em_massa_confere_com_o_modelo() {
    for seed in 0..ROUNDS / 4 {
        model_run::<CoarseState>(seed, 40, 600);
    }
}

#[test]
fn hashmap_cresce_e_esvazia() {
    let mut m = HashMap::new();
    assert!(m.is_empty());
    assert_eq!(m.get(&1), None);
    assert_eq!(m.remove(&1), None);
    for i in 0..5000u32 {
        m.insert(i, i.to_string());
    }
    m.check_invariants();
    assert_eq!(m.len(), 5000);
    assert!(m.capacity() >= 5000);
    for i in 0..5000u32 {
        assert_eq!(m.get(&i).map(String::as_str), Some(i.to_string().as_str()));
    }
    for i in (0..5000u32).step_by(2) {
        assert!(m.remove(&i).is_some());
    }
    m.check_invariants();
    assert_eq!(m.len(), 2500);
    assert!(m.iter().all(|(k, _)| k % 2 == 1));
    m.clear();
    assert!(m.is_empty());
    assert_eq!(m.iter().count(), 0);
    // Busca por `&str` num mapa de `String` (`Borrow`).
    let mut names: HashMap<String, u8> = HashMap::new();
    names.insert("um".into(), 1);
    assert_eq!(names.get("um"), Some(&1));
    assert!(!names.contains_key("dois"));
    let with_cap: HashMap<u8, u8> = HashMap::with_capacity(100);
    assert!(with_cap.capacity() >= 100);
}

#[test]
fn hashmap_igualdade_e_colecao() {
    let a: HashMap<u8, u8> = (0..50).map(|i| (i, i * 2)).collect();
    let mut b: HashMap<u8, u8> = (0..50).rev().map(|i| (i, i * 2)).collect();
    assert_eq!(a, b);
    b.insert(7, 0);
    assert_ne!(a, b);
    let mut set: HashSet<u16> = HashSet::new();
    assert!(set.insert(5));
    assert!(!set.insert(5));
    assert!(set.contains(&5));
    assert!(set.remove(&5));
    assert!(!set.remove(&5));
    set.extend(0..100);
    assert_eq!(set.len(), 100);
    assert_eq!(
        set.iter().copied().collect::<BTreeSet<_>>(),
        (0..100).collect()
    );
}

#[test]
fn hashset_confere_com_o_modelo() {
    let mut rng = Xoshiro256pp::from_u64(77);
    let mut set: HashSet<u32> = HashSet::new();
    let mut model = BTreeSet::new();
    for _ in 0..5000 {
        let k = rng.below(300) as u32;
        match rng.below(3) {
            0 => assert_eq!(set.insert(k), model.insert(k)),
            1 => assert_eq!(set.remove(&k), model.remove(&k)),
            _ => assert_eq!(set.contains(&k), model.contains(&k)),
        }
        assert_eq!(set.len(), model.len());
    }
}

#[test]
fn random_state_tem_chave_propria_por_mapa_e_depende_da_semente() {
    // Duas chaves do mesmo processo nunca coincidem.
    let keys: BTreeSet<(u64, u64)> = (0..1000).map(|_| RandomState::new().keys()).collect();
    assert_eq!(keys.len(), 1000);
    // O hash do mesmo dado difere entre mapas.
    let (a, b) = (RandomState::new(), RandomState::new());
    assert_ne!(a.hash_one("x"), b.hash_one("x"));
    // Reproduzível com a chave dada.
    assert_eq!(
        RandomState::with_keys(1, 2).hash_one("x"),
        RandomState::with_keys(1, 2).hash_one("x")
    );
    // Semear muda as chaves seguintes (o contador é global, então comparamos
    // chaves sorteadas depois de duas sementes diferentes com o mesmo
    // contador não é possível: basta que a semente entre no cálculo).
    seed_random_state([11, 22]);
    assert!(is_seeded());
    let before = RandomState::new().keys();
    seed_random_state([33, 44]);
    let after = RandomState::new().keys();
    assert_ne!(before, after);
}

// ---- Ring ----

#[test]
fn ring_confere_com_a_fila_modelo() {
    let mut rng = Xoshiro256pp::from_u64(5);
    for cap in [0usize, 1, 2, 3, 7, 16] {
        let mut ring = Ring::new(cap);
        let mut model: VecDeque<u32> = VecDeque::new();
        for i in 0..2000u32 {
            match rng.below(4) {
                0 | 1 => {
                    let r = ring.push(i);
                    if model.len() < cap {
                        model.push_back(i);
                        assert_eq!(r, Ok(()));
                    } else {
                        assert_eq!(r, Err(i), "cheio devolve o valor");
                    }
                }
                2 => assert_eq!(ring.pop(), model.pop_front()),
                _ => {
                    let dropped = ring.push_overwrite(i);
                    if cap == 0 {
                        assert_eq!(dropped, Some(i));
                    } else {
                        let old = if model.len() == cap {
                            model.pop_front()
                        } else {
                            None
                        };
                        model.push_back(i);
                        assert_eq!(dropped, old);
                    }
                }
            }
            assert_eq!(ring.len(), model.len());
            assert_eq!(ring.is_full(), model.len() == cap);
            assert_eq!(ring.front(), model.front());
            assert_eq!(ring.back(), model.back());
            assert!(ring.iter().eq(model.iter()));
            assert_eq!(ring.get(model.len()), None);
        }
        ring.clear();
        assert!(ring.is_empty());
        assert_eq!(ring.capacity(), cap);
    }
}

// ---- UTF-8 ----

/// Bytes que mais importam na validação: limites das faixas, continuações,
/// inícios proibidos.
const INTERESTING: &[u8] = &[
    0x00, 0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xEC,
    0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xFF,
];

fn random_bytes(rng: &mut Xoshiro256pp) -> Vec<u8> {
    let n = rng.below(24) as usize;
    (0..n)
        .map(|_| {
            if rng.below(4) == 0 {
                rng.next_u64() as u8
            } else {
                INTERESTING[rng.below(INTERESTING.len() as u64) as usize]
            }
        })
        .collect()
}

#[test]
fn validate_confere_com_o_core() {
    let mut rng = Xoshiro256pp::from_u64(9);
    for _ in 0..ROUNDS * 100 {
        let bytes = random_bytes(&mut rng);
        let ours = utf8::validate(&bytes);
        let core = core::str::from_utf8(&bytes);
        match (ours, core) {
            (Ok(a), Ok(b)) => assert_eq!(a, b),
            (Err(a), Err(b)) => assert_eq!(
                a,
                Utf8Error {
                    valid_up_to: b.valid_up_to(),
                    error_len: b.error_len()
                },
                "{bytes:02x?}"
            ),
            (a, b) => panic!("divergência em {bytes:02x?}: {a:?} contra {b:?}"),
        }
    }
}

#[test]
fn validate_casos_de_borda() {
    let ok: &[&[u8]] = &[
        b"",
        b"ascii",
        "á".as_bytes(),
        "€".as_bytes(),
        "𝄞".as_bytes(),
        &[0xC2, 0x80],
        &[0xDF, 0xBF],
        &[0xE0, 0xA0, 0x80],
        &[0xED, 0x9F, 0xBF],
        &[0xEF, 0xBF, 0xBF],
        &[0xF0, 0x90, 0x80, 0x80],
        &[0xF4, 0x8F, 0xBF, 0xBF],
    ];
    for b in ok {
        assert!(utf8::validate(b).is_ok(), "{b:02x?}");
    }
    let bad: &[(&[u8], usize, Option<usize>)] = &[
        (&[0x80], 0, Some(1)),
        (&[0xC0, 0x80], 0, Some(1)),
        (&[0xC1, 0xBF], 0, Some(1)),
        (&[0xE0, 0x80, 0x80], 0, Some(1)),
        (&[0xED, 0xA0, 0x80], 0, Some(1)),
        (&[0xF0, 0x80, 0x80, 0x80], 0, Some(1)),
        (&[0xF4, 0x90, 0x80, 0x80], 0, Some(1)),
        (&[0xF5, 0x80, 0x80, 0x80], 0, Some(1)),
        (&[0xFF], 0, Some(1)),
        (&[b'a', 0xE2, 0x82], 1, None),
        (&[b'a', 0xF0, 0x9F], 1, None),
        (&[b'a', 0xE2, 0x28, 0xA1], 1, Some(1)),
        (&[0xF0, 0x9F, 0x28], 0, Some(2)),
    ];
    for &(b, up_to, len) in bad {
        assert_eq!(
            utf8::validate(b),
            Err(Utf8Error {
                valid_up_to: up_to,
                error_len: len
            }),
            "{b:02x?}"
        );
    }
}

#[test]
fn decoder_incremental_confere_com_lossy_em_qualquer_corte() {
    let mut rng = Xoshiro256pp::from_u64(21);
    for _ in 0..ROUNDS * 50 {
        let bytes = random_bytes(&mut rng);
        let mut dec = Decoder::new();
        let mut out = String::new();
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let cut = 1 + rng.below(rest.len() as u64) as usize;
            let (head, tail) = rest.split_at(cut);
            dec.push(head, &mut out);
            rest = tail;
        }
        dec.finish(&mut out);
        assert!(!dec.has_pending());
        assert_eq!(out, String::from_utf8_lossy(&bytes), "{bytes:02x?}");
    }
}

#[test]
fn decoder_junta_caractere_partido_entre_pedacos() {
    let text = "a€𝄞é";
    let mut dec = Decoder::new();
    let mut out = String::new();
    for b in text.as_bytes() {
        dec.push(&[*b], &mut out);
    }
    assert_eq!(out, text);
    assert!(!dec.has_pending());
    // Fluxo que acaba no meio de um caractere.
    dec.push(&text.as_bytes()[1..2], &mut out);
    assert!(dec.has_pending());
    dec.finish(&mut out);
    assert!(out.ends_with('\u{FFFD}'));
}

#[test]
fn cortes_em_fronteira_de_caractere() {
    let s = "aé€𝄞z";
    for max in 0..=s.len() + 3 {
        let cut = utf8::truncate(s, max);
        assert!(cut.len() <= max.min(s.len()));
        assert!(s.starts_with(cut));
        // É o maior prefixo possível.
        let next = s[cut.len()..].chars().next().map_or(0, char::len_utf8);
        assert!(cut.len() + next > max || cut.len() == s.len());
        assert_eq!(utf8::floor_boundary(s, max), cut.len());
    }
    assert_eq!(utf8::truncate("", 5), "");
    assert_eq!(utf8::sequence_len(0xC0), None);
    assert_eq!(utf8::sequence_len(0xF0), Some(4));
}

// ---- PRNG ----

#[test]
fn xoshiro_confere_com_o_vetor_de_referencia() {
    // Estado [1, 2, 3, 4]: primeira saída = rotl(1 + 4, 23) + 1.
    let mut g = Xoshiro256pp::from_state([1, 2, 3, 4]);
    assert_eq!(g.next_u64(), 41_943_041);
    assert_eq!(g.next_u64(), 58_720_359);
    assert_eq!(g.next_u64(), 3_588_806_011_781_223);
    // Estado zero é trocado por um válido.
    let mut z = Xoshiro256pp::from_state([0; 4]);
    assert_ne!(z.next_u64() | z.next_u64(), 0);
    // SplitMix64 de referência: semente 0.
    assert_eq!(SplitMix64(0).next_u64(), 0xE220_A839_7B1D_CDAF);
}

#[test]
fn xoshiro_below_e_uniforme_e_dentro_do_limite() {
    let mut g = Xoshiro256pp::from_u64(3);
    let mut counts = [0u32; 10];
    for _ in 0..100_000 {
        counts[g.below(10) as usize] += 1;
    }
    // Esperado 10 000 por balde; desvio padrão ~95: 5 sigmas.
    assert!(
        counts.iter().all(|&c| (9_500..10_500).contains(&c)),
        "{counts:?}"
    );
    assert_eq!(g.below(0), 0);
    assert_eq!(g.below(1), 0);
    let mut buf = [0u8; 13];
    g.fill(&mut buf);
    assert!(buf.iter().any(|&b| b != 0));
    let seeds = [
        Xoshiro256pp::from_bytes(&[7; 32]),
        Xoshiro256pp::from_bytes(&[8; 32]),
    ];
    assert_ne!(seeds[0], seeds[1]);
}
