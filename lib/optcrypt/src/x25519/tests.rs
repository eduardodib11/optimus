//! Vetores da RFC 7748 (seções 5.2 e 6.1) e do Wycheproof.

use super::*;
use crate::testutil::{hex, unhex, wycheproof};

fn arr(s: &str) -> [u8; LEN] {
    unhex(s).try_into().unwrap()
}

#[test]
fn rfc7748_vetores() {
    let casos = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
        ),
    ];
    for (k, u, esperado) in casos {
        assert_eq!(hex(&x25519(&arr(k), &arr(u))), esperado);
    }
}

/// Seção 5.2: `k = u = 9`; a cada passo `(k, u) = (X25519(k, u), k)`.
fn iterado(n: usize) -> String {
    let (mut k, mut u) = (BASEPOINT, BASEPOINT);
    for _ in 0..n {
        let r = x25519(&k, &u);
        u = k;
        k = r;
    }
    hex(&k)
}

#[test]
fn rfc7748_iterado() {
    assert_eq!(
        iterado(1),
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
    );
    assert_eq!(
        iterado(1000),
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
    );
}

#[test]
#[ignore = "um milhão de iterações; rode com --ignored em --release"]
fn rfc7748_iterado_milhao() {
    assert_eq!(
        iterado(1_000_000),
        "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
    );
}

#[test]
fn rfc7748_alice_e_bob() {
    let a = Secret::take(&mut arr(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let b = Secret::take(&mut arr(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let pa = public_key(&a);
    let pb = public_key(&b);
    assert_eq!(
        hex(&pa),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex(&pb),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );
    let ka = diffie_hellman(&a, &pb).unwrap();
    let kb = diffie_hellman(&b, &pa).unwrap();
    assert!(ka.ct_eq(&kb));
    assert_eq!(
        hex(ka.expose()),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );
}

/// Wycheproof `x25519_test`: todos (válidos e aceitáveis) têm o segredo
/// esperado; os que dão zero (pontos de ordem pequena) são recusados pelo
/// [`diffie_hellman`].
#[test]
fn wycheproof_x25519() {
    for c in wycheproof(include_str!("../../vetores/x25519.txt")) {
        let [public, private, shared] = c.campos[..] else {
            panic!("tc {}", c.id)
        };
        let (u, k) = (arr(public), arr(private));
        let esperado = arr(shared);
        assert_eq!(x25519(&k, &u), esperado, "tc {}", c.id);
        let r = diffie_hellman(&Secret::take(&mut k.clone()), &u);
        if esperado == [0u8; LEN] {
            assert_eq!(r.err(), Some(Error::LowOrder), "tc {}", c.id);
        } else {
            assert_eq!(r.unwrap().expose(), &esperado, "tc {}", c.id);
        }
    }
}
