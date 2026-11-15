//! RFC 8439, seção 2.3.2 (bloco), mais o caso de contador alto.

use super::*;
use crate::testutil::hex;

#[test]
fn bloco_rfc8439() {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    assert_eq!(
        hex(&block(&key, 1, &nonce)),
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
    );
}

#[test]
fn contador_dá_a_volta() {
    let (key, nonce) = ([7u8; 32], [3u8; 12]);
    let mut a = [0u8; 128];
    apply(&key, u32::MAX, &nonce, &mut a);
    assert_eq!(a[..64], block(&key, u32::MAX, &nonce));
    assert_eq!(a[64..], block(&key, 0, &nonce));
}
