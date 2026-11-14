//! Vetores da RFC 5869 (casos 1 a 3, SHA-256).

use super::*;
use crate::testutil::hex;

fn caso(salt: &[u8], ikm: &[u8], info: &[u8], prk_esp: &str, okm_esp: &str) {
    let prk = extract(salt, ikm);
    assert_eq!(hex(prk.expose()), prk_esp);
    let mut okm = vec![0u8; okm_esp.len() / 2];
    expand(&prk, info, &mut okm).unwrap();
    assert_eq!(hex(&okm), okm_esp);
}

#[test]
fn rfc5869_caso1() {
    let salt: Vec<u8> = (0..13).collect();
    let info: Vec<u8> = (0xf0..=0xf9).collect();
    caso(
        &salt,
        &[0x0b; 22],
        &info,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
}

#[test]
fn rfc5869_caso2() {
    let ikm: Vec<u8> = (0..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();
    caso(
        &salt,
        &ikm,
        &info,
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    );
}

#[test]
fn rfc5869_caso3_sal_e_info_vazios() {
    caso(
        &[],
        &[0x0b; 22],
        &[],
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
}

#[test]
fn limite_de_saida() {
    let prk = extract(b"", b"x");
    let mut ok = vec![0u8; MAX_OUT];
    assert!(expand(&prk, b"", &mut ok).is_ok());
    let mut longo = vec![0u8; MAX_OUT + 1];
    assert_eq!(expand(&prk, b"", &mut longo), Err(Error::TooLong));
    let k: Secret<32> = expand_secret(&prk, b"rotulo").unwrap();
    assert_ne!(k.expose(), &[0u8; 32]);
}
