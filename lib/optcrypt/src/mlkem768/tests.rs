//! Vetores do ACVP-Server (FIPS 203), do Wycheproof e acumulados (Go),
//! mais propriedades da aritmética e da rejeição implícita.

#![allow(clippy::cast_possible_truncation, reason = "valores dos testes cabem")]

use super::*;
use crate::testutil::{hex, unhex, wycheproof};

fn arr<const L: usize>(s: &str) -> [u8; L] {
    unhex(s).try_into().unwrap()
}

fn h(b: &[u8]) -> Vec<u8> {
    sha3_256(b).to_vec()
}

#[test]
fn barrett_e_compressao() {
    for x in (0..(1u32 << 24))
        .step_by(97)
        .chain([u32::MAX, u32::MAX - 1, Q * Q])
    {
        assert_eq!(div_q(x), x / Q, "{x}");
    }
    for a in (0..Q).step_by(7) {
        for b in (0..Q).step_by(13) {
            let (a, b) = (a as u16, b as u16);
            assert_eq!(u32::from(mul(a, b)), u32::from(a) * u32::from(b) % Q);
            assert_eq!(u32::from(sub(a, b)), (u32::from(a) + Q - u32::from(b)) % Q);
        }
    }
    // Compress_d(x) = round(2^d·x/q) mod 2^d, conferido em aritmética exata.
    for d in [1, 4, 10] {
        let mut f = [0u16; N];
        for x in 0..Q {
            f[0] = x as u16;
            compress(&mut f, d);
            let esperado = ((2 * (x << d) + Q) / (2 * Q)) % (1 << d);
            assert_eq!(u32::from(f[0]), esperado, "d={d} x={x}");
        }
    }
}

#[test]
fn ntt_ida_e_volta() {
    let mut f = [0u16; N];
    for (i, x) in f.iter_mut().enumerate() {
        *x = ((i * 1031 + 7) % Q as usize) as u16;
    }
    let g = f;
    ntt(&mut f);
    ntt_inv(&mut f);
    assert_eq!(f, g);
}

#[test]
fn acvp() {
    for c in wycheproof(include_str!("../../vetores/mlkem768_acvp.txt")) {
        let id = c.id;
        match (c.grupo[0], &c.campos[..]) {
            ("keygen", [d, z, hek, hdk]) => {
                let (ek, dk) = keygen_internal(&arr(d), &arr(z));
                assert_eq!(h(&ek), unhex(hek), "tc {id}");
                assert_eq!(h(dk.expose()), unhex(hdk), "tc {id}");
            }
            ("encapsulation", [ek, m, hc, k]) => {
                let (ct, kk) = encaps_internal(&arr(ek), &arr(m)).unwrap();
                assert_eq!(h(&ct), unhex(hc), "tc {id}");
                assert_eq!(kk.expose()[..], unhex(k)[..], "tc {id}");
            }
            ("decapsulation", [dk, ct, k]) => {
                let dk = Secret::take(&mut arr(dk));
                let kk = decaps(&dk, &arr(ct)).unwrap();
                assert_eq!(kk.expose()[..], unhex(k)[..], "tc {id}");
            }
            ("encapsulationKeyCheck", [ek]) => {
                let r = encaps_internal(&arr(ek), &[0; 32]);
                assert_eq!(r.is_ok(), c.res == 'v', "tc {id}");
            }
            ("decapsulationKeyCheck", [dk]) => {
                let r = decaps(&Secret::take(&mut arr(dk)), &[0; CT_LEN]);
                assert_eq!(r.is_ok(), c.res == 'v', "tc {id}");
            }
            _ => panic!("tc {id}: seção {}", c.grupo[0]),
        }
    }
}

/// Wycheproof: casos `Strcmp` (zero no meio do texto cifrado),
/// `MalleableCiphertext` (rejeição implícita) e `ModulusOverflow`.
#[test]
fn wycheproof_mlkem768() {
    for c in wycheproof(include_str!("../../vetores/mlkem768_wycheproof.txt")) {
        let id = c.id;
        match (c.grupo[0], &c.campos[..]) {
            ("decaps", [seed, hek, ct, k]) => {
                let seed = unhex(seed);
                let (ek, dk) = keygen_internal(&arr(&hex(&seed[..32])), &arr(&hex(&seed[32..])));
                assert_eq!(h(&ek), unhex(hek), "tc {id}");
                let kk = decaps(&dk, &arr(ct)).unwrap();
                assert_eq!(kk.expose()[..], unhex(k)[..], "tc {id}");
            }
            ("encaps", [ek, m]) => {
                assert_eq!(
                    encaps_internal(&arr(ek), &arr(m)).err(),
                    Some(Error::InvalidKey),
                    "tc {id}"
                );
            }
            _ => panic!("tc {id}"),
        }
    }
}

/// Testes acumulados (o `TestAccumulated` do pacote `crypto/mlkem` do Go,
/// FIPS 203 final): entradas tiradas de um SHAKE128 vazio, na ordem `d ‖ z`,
/// `m` e um texto cifrado aleatório; `ek`, `c`, `K` e a chave da rejeição
/// implícita vão para outro SHAKE128, conferido no fim. O README do CCTV
/// traz hashes da versão preliminar (FIPS 203 ipd), que não servem aqui.
fn acumulado(n: usize) -> String {
    let mut rng = Shake128::new();
    let mut acc = Shake128::new();
    for _ in 0..n {
        let (mut d, mut z, mut m, mut ct) = ([0u8; 32], [0u8; 32], [0u8; 32], [0u8; CT_LEN]);
        rng.squeeze(&mut d);
        rng.squeeze(&mut z);
        rng.squeeze(&mut m);
        rng.squeeze(&mut ct);
        let (ek, dk) = keygen_internal(&d, &z);
        acc.update(&ek);
        let (c, k) = encaps_internal(&ek, &m).unwrap();
        acc.update(&c);
        acc.update(k.expose());
        assert!(decaps(&dk, &c).unwrap().ct_eq(&k));
        acc.update(decaps(&dk, &ct).unwrap().expose());
    }
    let mut out = [0u8; 32];
    acc.squeeze(&mut out);
    hex(&out)
}

#[test]
fn acumulado_100() {
    assert_eq!(
        acumulado(100),
        "1114b1b6699ed191734fa339376afa7e285c9e6acf6ff0177d346696ce564415"
    );
}

#[test]
#[ignore = "10 000 casos; rode com --ignored em --release"]
fn acumulado_10k() {
    assert_eq!(
        acumulado(10_000),
        "8a518cc63da366322a8e7a818c7a0d63483cb3528d34a4cf42f35d5ad73f22fc"
    );
}

/// Ida e volta e rejeição implícita: mudar qualquer byte do texto cifrado
/// troca a chave pela de `J(z ‖ c)`, sem erro.
#[test]
fn rejeicao_implicita() {
    let (ek, dk) = keygen_internal(&[1; 32], &[2; 32]);
    let (c, k) = encaps_internal(&ek, &[3; 32]).unwrap();
    assert!(decaps(&dk, &c).unwrap().ct_eq(&k));
    for i in [0, 1, C1_LEN - 1, C1_LEN, CT_LEN - 1] {
        let mut ruim = c;
        ruim[i] ^= 0x10;
        let mut j = [0u8; SS_LEN];
        shake256_into(&[&[2; 32], &ruim], &mut j);
        let kk = decaps(&dk, &ruim).unwrap();
        assert!(!kk.ct_eq(&k), "byte {i}");
        assert_eq!(kk.expose(), &j, "byte {i}");
    }
}
