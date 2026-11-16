//! Vetores do Wycheproof (PKCS#1 v1.5 e PSS, 2048 e 4096 bits) e limites
//! de tamanho da chave.

use super::*;
use crate::testutil::{unhex, unhex_usize, wycheproof};

/// Confere um arquivo; os `acceptable` (só `MissingNull`, `DigestInfo` sem
/// o `NULL`) são recusados de propósito pela comparação byte a byte.
fn confere(texto: &str, alg: Hash, pss: bool) {
    let mut chave: Option<(String, PublicKey)> = None;
    for c in wycheproof(texto) {
        let id = c.grupo[0].to_owned() + c.grupo[1];
        if chave.as_ref().is_none_or(|(k, _)| *k != id) {
            chave = Some((
                id,
                PublicKey::new(&unhex(c.grupo[0]), &unhex(c.grupo[1])).unwrap(),
            ));
        }
        let pk = &chave.as_ref().unwrap().1;
        let [msg, sig] = c.campos[..] else { panic!() };
        let h = alg.digest(&[&unhex(msg)]);
        let h = &h[..alg.out_len()];
        let sig = unhex(sig);
        let ok = if pss {
            pk.verify_pss(alg, h, &sig, unhex_usize(c.grupo[2]))
        } else {
            pk.verify_pkcs1v15(alg, h, &sig)
        };
        assert_eq!(ok, c.res == 'v', "tc {}", c.id);
    }
}

#[test]
fn wycheproof_pkcs1v15() {
    confere(
        include_str!("../../vetores/rsa_pkcs1_2048_sha256.txt"),
        Hash::Sha256,
        false,
    );
    confere(
        include_str!("../../vetores/rsa_pkcs1_4096_sha512.txt"),
        Hash::Sha512,
        false,
    );
}

#[test]
fn wycheproof_pss() {
    confere(
        include_str!("../../vetores/rsa_pss_2048_sha256.txt"),
        Hash::Sha256,
        true,
    );
    confere(
        include_str!("../../vetores/rsa_pss_4096_sha512.txt"),
        Hash::Sha512,
        true,
    );
}

#[test]
fn limites_da_chave() {
    let e = [0x01, 0x00, 0x01];
    let mut n = [0xffu8; 256];
    assert!(PublicKey::new(&n, &e).is_ok());
    // 2047 bits, 4097 bits e módulo par.
    n[0] = 0x7f;
    assert_eq!(PublicKey::new(&n, &e).err(), Some(Error::Modulus));
    let mut grande = [0xffu8; 513];
    grande[0] = 1;
    assert_eq!(PublicKey::new(&grande, &e).err(), Some(Error::Modulus));
    let mut par = [0xffu8; 256];
    par[255] = 0xfe;
    assert_eq!(PublicKey::new(&par, &e).err(), Some(Error::Modulus));
    // Zeros à esquerda (como no DER) não contam.
    let mut com_zero = [0xffu8; 257];
    com_zero[0] = 0;
    assert!(PublicKey::new(&com_zero, &e).is_ok());
    // Expoentes 1, par e maior que n.
    let n = [0xffu8; 256];
    assert_eq!(PublicKey::new(&n, &[1]).err(), Some(Error::Exponent));
    assert_eq!(
        PublicKey::new(&n, &[0x01, 0x00, 0x00]).err(),
        Some(Error::Exponent)
    );
    assert_eq!(
        PublicKey::new(&n, &[0xffu8; 257]).err(),
        Some(Error::Exponent)
    );
    // Assinatura de tamanho errado.
    let pk = PublicKey::new(&n, &e).unwrap();
    let h = [0u8; 32];
    assert!(!pk.verify_pkcs1v15(Hash::Sha256, &h, &[1u8; 255]));
    assert!(!pk.verify_pss(Hash::Sha256, &h, &[1u8; 257], 32));
}
