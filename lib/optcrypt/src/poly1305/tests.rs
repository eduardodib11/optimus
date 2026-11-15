//! RFC 8439, seção 2.5.2, e casos diferenciais contra o OpenSSL
//! (pacote `cryptography` do Python), incluindo mensagem e chave 0xff.

use super::*;
use crate::testutil::hex;

fn de_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc8439() {
    let key: [u8; 32] = de_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        .try_into()
        .unwrap();
    assert_eq!(
        hex(&tag(&key, b"Cryptographic Forum Research Group")),
        "a8061dc1305136c6c22b8baf0c0127a9"
    );
}

const CASOS: &[(&str, &str, &str)] = &[
    (
        "92c1126363cf7cff0d3a9c32adacb153061764ff108bf3681772a9a071bce908",
        "",
        "061764ff108bf3681772a9a071bce908",
    ),
    (
        "103e62379f3d7e2138b3ac82d2568a9c21c8597bfb059cf0761c6fc43190f812",
        "85",
        "8516a2b312a46f359170dbd4457a2e21",
    ),
    (
        "01ea4b3d297ea3bc7bf90300a4c9b4a2896e97e74c046574029a2d747969c46f",
        "904669563cf971e09c82285fee30b1f3",
        "1674fac21ed02e2fce2456a2a16d20e2",
    ),
    (
        "079a0754519fc28ef0ac4463e463340aff5c960f658a528dcc8a28b49f397c0a",
        "758fc1e28322f5caf84ccff41fcb166784",
        "c39b53c55ad30e1b96332e68c88437e2",
    ),
    (
        "a959bcdc53c4761f9074d5fbf55aeff6fbe27a79a5704b2b3ee4ef054b07f947",
        "391721dae15e3d0aaadfad7253fcfca519a304ff156861818e98757be322fef477",
        "5df55e50cac6258a26e88880e41c4547",
    ),
    (
        "a8d4846ebadf00a13d4c79a19278b57f9635f5813c8916493533e0994a71a2a6",
        "5e16dcd9c4013a84c82c3103a09dee474cba9b8e2adfda03e8f59ef3329d267dd8383579c762f2bb674b0f0c3dcfd305efac77a0fc846b74f9f78123882b95dd17ef1b581977d94c6ab37820db5c72e4fb44e353b9f73aef9824eca5b87c258fbe9d13b1",
        "5b09c4ebeb5c8e5902881e9586116d8f",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "900fe32bc15fa8d7bca8efe4c7e37eb1",
    ),
];

#[test]
fn diferencial_e_incremental() {
    for (k, m, t) in CASOS {
        let key: [u8; 32] = de_hex(k).try_into().unwrap();
        let msg = de_hex(m);
        assert_eq!(hex(&tag(&key, &msg)), *t);
        for corte in 0..=msg.len() {
            let mut p = Poly1305::new(&key);
            p.update(&msg[..corte]);
            p.update(&msg[corte..]);
            assert_eq!(hex(&p.finalize()), *t, "corte {corte}");
        }
    }
}
