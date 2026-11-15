//! Vetores FIPS 180-4 / NIST e testes de fronteira.

use super::*;
use crate::testutil::hex;

#[test]
fn vetores_nist() {
    let casos: &[(&[u8], &str)] = &[
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        ),
    ];
    for (msg, esperado) in casos {
        assert_eq!(hex(&hash(msg)), *esperado);
    }
}

#[test]
fn um_milhao_de_a() {
    let mut h = Sha256::new();
    for _ in 0..1000 {
        h.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex(&h.finalize()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

/// Algoritmo Monte Carlo do CAVP (SHA-256), com semente própria; o valor
/// esperado vem de uma implementação independente (hashlib do Python).
#[test]
fn monte_carlo() {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::try_from(i * 7 + 3).unwrap();
    }
    let seed_hex = "6e1b0a3f2b2bd2f0f0e6a8d5a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5";
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).unwrap();
    }
    for _ in 0..100 {
        let mut md = vec![s, s, s];
        for i in 3..1003 {
            let mut m = Vec::with_capacity(96);
            m.extend_from_slice(&md[i - 3]);
            m.extend_from_slice(&md[i - 2]);
            m.extend_from_slice(&md[i - 1]);
            md.push(hash(&m));
        }
        s = md[1002];
    }
    assert_eq!(
        hex(&s),
        "33ddcd0a6c01e3ee432d9963c6f216ef1d94b72ff0c6d2c6f88ee47ab40f98da"
    );
}

/// Todo tamanho de 0 a 300 e todo ponto de corte dão o mesmo resumo.
#[test]
fn incremental_igual_ao_de_uma_vez() {
    let dados: Vec<u8> = (0..300u32)
        .map(|i| u8::try_from(i * 31 % 251).unwrap())
        .collect();
    for n in 0..=300 {
        let um = hash(&dados[..n]);
        for corte in 0..=n {
            let mut h = Sha256::new();
            h.update(&dados[..corte]);
            h.update(&dados[corte..n]);
            assert_eq!(h.finalize(), um, "n={n} corte={corte}");
        }
    }
}
