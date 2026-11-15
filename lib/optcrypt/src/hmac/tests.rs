//! Vetores da RFC 4231 (SHA-256).

use super::*;
use crate::testutil::hex;

#[test]
fn rfc4231() {
    let k25: Vec<u8> = (1..=25).collect();
    let casos: Vec<(Vec<u8>, Vec<u8>, &str)> = vec![
        (vec![0x0b; 20], b"Hi There".to_vec(),
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(),
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (vec![0xaa; 20], vec![0xdd; 50],
         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        (k25, vec![0xcd; 50],
         "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (vec![0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (vec![0xaa; 131],
         b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
         "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    ];
    for (k, d, esperado) in &casos {
        assert_eq!(hex(&hmac_sha256(k, d)), *esperado);
        let mut h = HmacSha256::new(k);
        let (a, b) = d.split_at(d.len() / 2);
        h.update(a);
        h.update(b);
        assert_eq!(hex(&h.finalize()), *esperado);
    }
}

#[test]
fn verify_aceita_e_recusa() {
    let tag = hmac_sha256(b"k", b"msg");
    assert!(verify(b"k", b"msg", &tag));
    assert!(!verify(b"k", b"msg", &tag[..31]));
    for i in 0..tag.len() {
        let mut ruim = tag;
        ruim[i] ^= 1;
        assert!(!verify(b"k", b"msg", &ruim), "byte {i}");
    }
    assert!(!verify(b"outra", b"msg", &tag));
}
