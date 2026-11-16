//! Vetores da RFC 8032 (seção 7.1) e do Wycheproof.

use super::*;
use crate::testutil::{unhex, wycheproof};

fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap()
}

#[test]
fn rfc8032() {
    for c in wycheproof(include_str!("../../vetores/ed25519_rfc8032.txt")) {
        let [sk, pk, msg, sig] = c.campos[..] else {
            panic!()
        };
        let sk = Secret::take(&mut arr(sk));
        let (pk, msg, sig) = (arr(pk), unhex(msg), arr(sig));
        assert_eq!(public_key(&sk), pk, "teste {}", c.id);
        assert_eq!(sign(&sk, &msg), sig, "teste {}", c.id);
        assert!(verify(&pk, &msg, &sig), "teste {}", c.id);
        let mut ruim = sig;
        ruim[0] ^= 1;
        assert!(!verify(&pk, &msg, &ruim), "teste {}", c.id);
    }
}

/// Wycheproof `ed25519_test`. A verificação estrita recusa todos os
/// inválidos; os `acceptable` (assinaturas com `R` ou `A` de ordem
/// pequena) podem ir para qualquer lado, e o teste só registra.
#[test]
fn wycheproof_ed25519() {
    let mut aceitaveis = (0, 0);
    for c in wycheproof(include_str!("../../vetores/ed25519.txt")) {
        let pk: [u8; 32] = arr(c.grupo[0]);
        let [msg, sig] = c.campos[..] else { panic!() };
        let sig = unhex(sig);
        let ok = sig
            .as_slice()
            .try_into()
            .is_ok_and(|s: [u8; 64]| verify(&pk, &unhex(msg), &s));
        match c.res {
            'a' => {
                aceitaveis.0 += usize::from(ok);
                aceitaveis.1 += 1;
            }
            r => assert_eq!(ok, r == 'v', "tc {}", c.id),
        }
    }
    println!("acceptable aceitos: {} de {}", aceitaveis.0, aceitaveis.1);
}

#[test]
fn escalares() {
    // L mod L = 0, (L - 1)·(L - 1) + 0 = 1 mod L.
    let mut l = [0u64; 8];
    l[..4].copy_from_slice(&L);
    assert_eq!(reduce512(&l), [0; 4]);
    let mut lm1 = L;
    lm1[0] -= 1;
    assert_eq!(mul_add(&lm1, &lm1, &[0; 4]), [1, 0, 0, 0]);
    // 2^512 - 1 mod L, calculado fora (Python).
    assert_eq!(
        to_bytes(&reduce512(&[u64::MAX; 8]))[..],
        unhex("000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903")[..]
    );
}
