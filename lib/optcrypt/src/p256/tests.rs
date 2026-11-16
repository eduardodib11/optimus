//! Vetores do NIST CAVP (`SigVer`, P-256 com SHA-256/384/512) e do
//! Wycheproof (`ecdsa_secp256r1_sha256_test`, assinaturas DER).

use super::*;
use crate::sha512;
use crate::testutil::{unhex, wycheproof};

#[test]
fn cavp_sigver() {
    let mut hash: fn(&[u8]) -> Vec<u8> = |m| sha256::hash(m).to_vec();
    let (mut msg, mut qx, mut qy, mut r, mut s) = (vec![], vec![], vec![], vec![], vec![]);
    let mut n = 0;
    for linha in include_str!("../../vetores/ecdsa_p256_SigVer.rsp").lines() {
        let (k, v) = linha.split_once(" = ").unwrap_or((linha, ""));
        match k {
            "[P-256,SHA-256]" => hash = |m| sha256::hash(m).to_vec(),
            "[P-256,SHA-384]" => hash = |m| sha512::hash384(m).to_vec(),
            "[P-256,SHA-512]" => hash = |m| sha512::hash(m).to_vec(),
            "Msg" => msg = unhex(v),
            "Qx" => qx = unhex(v),
            "Qy" => qy = unhex(v),
            "R" => r = unhex(v),
            "S" => s = unhex(v),
            "Result" => {
                let pk = [&[4u8][..], &qx, &qy].concat();
                let ok = verify_prehashed(
                    &pk,
                    &hash(&msg),
                    &r.clone().try_into().unwrap(),
                    &s.clone().try_into().unwrap(),
                );
                assert_eq!(ok, v.starts_with('P'), "caso {n}: {v}");
                n += 1;
            }
            _ => {}
        }
    }
    assert_eq!(n, 45);
}

#[test]
fn wycheproof_ecdsa_p256() {
    for c in wycheproof(include_str!("../../vetores/ecdsa_p256_sha256.txt")) {
        let pk = unhex(c.grupo[0]);
        let [msg, sig] = c.campos[..] else { panic!() };
        let ok = verify_sha256(&pk, &unhex(msg), &unhex(sig));
        assert_eq!(ok, c.res == 'v', "tc {}", c.id);
    }
}

#[test]
fn der_estrito() {
    let um = |r: u8| {
        let mut x = [0u8; 32];
        x[31] = r;
        x
    };
    assert_eq!(der_sig(&[0x30, 6, 2, 1, 1, 2, 1, 2]), Some((um(1), um(2))));
    // Tamanho longo, zero à esquerda desnecessário, negativo e sobra.
    assert!(der_sig(&[0x30, 0x81, 6, 2, 1, 1, 2, 1, 2]).is_none());
    assert!(der_sig(&[0x30, 7, 2, 2, 0, 1, 2, 1, 2]).is_none());
    assert!(der_sig(&[0x30, 6, 2, 1, 0x81, 2, 1, 2]).is_none());
    assert!(der_sig(&[0x30, 7, 2, 1, 1, 2, 1, 2, 0]).is_none());
    assert!(der_sig(&[0x30, 7, 2, 2, 0, 0x81, 2, 1, 2]).is_some());
}
