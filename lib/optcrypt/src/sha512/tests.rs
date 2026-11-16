//! Vetores NIST CAVP (`ShortMsg` e `Monte`, byte a byte) do SHA-384 e do
//! SHA-512, mais fronteiras de bloco.

use super::*;
use crate::testutil::{cavp_monte, cavp_msg, hex};

#[test]
fn cavp_short_msg() {
    for (msg, md) in cavp_msg(include_str!("../../vetores/SHA512ShortMsg.rsp")) {
        assert_eq!(hash(&msg)[..], md[..], "SHA-512 de {} bytes", msg.len());
    }
    for (msg, md) in cavp_msg(include_str!("../../vetores/SHA384ShortMsg.rsp")) {
        assert_eq!(hash384(&msg)[..], md[..], "SHA-384 de {} bytes", msg.len());
    }
}

/// Monte Carlo do CAVP: `MD_i = H(MD_{i-3} ‖ MD_{i-2} ‖ MD_{i-1})`, mil
/// vezes por ponto de controle.
fn monte(texto: &str, h: fn(&[u8]) -> Vec<u8>) {
    let (mut seed, mds) = cavp_monte(texto);
    for (j, esperado) in mds.iter().enumerate() {
        let mut md = [seed.clone(), seed.clone(), seed.clone()];
        for _ in 3..1003 {
            let m = [&md[0][..], &md[1], &md[2]].concat();
            md = [md[1].clone(), md[2].clone(), h(&m)];
        }
        seed = md[2].clone();
        assert_eq!(seed, *esperado, "ponto {j}");
    }
}

#[test]
fn cavp_monte_512() {
    monte(include_str!("../../vetores/SHA512Monte.rsp"), |m| {
        hash(m).to_vec()
    });
}

#[test]
fn cavp_monte_384() {
    monte(include_str!("../../vetores/SHA384Monte.rsp"), |m| {
        hash384(m).to_vec()
    });
}

#[test]
fn um_milhao_de_a() {
    let mut h = Sha512::new();
    for _ in 0..1000 {
        h.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex(&h.finalize()),
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
         de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    );
}

/// Alimentar aos pedaços dá o mesmo resumo que de uma vez, inclusive nas
/// fronteiras do preenchimento (111, 112 e 128 bytes).
#[test]
fn incremental_igual_de_uma_vez() {
    let dados: Vec<u8> = (0..400u32).map(|i| (i * 31 % 251) as u8).collect();
    for n in [0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 256, 400] {
        let msg = &dados[..n];
        for corte in [0, 1.min(n), n / 2, n] {
            let mut a = Sha512::new();
            a.update(&msg[..corte]);
            a.update(&msg[corte..]);
            assert_eq!(a.finalize(), hash(msg), "{n}/{corte}");
            let mut b = Sha384::new();
            b.update(&msg[..corte]);
            b.update(&msg[corte..]);
            assert_eq!(b.finalize(), hash384(msg), "{n}/{corte}");
        }
    }
}
