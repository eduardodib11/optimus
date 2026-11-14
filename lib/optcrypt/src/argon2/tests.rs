//! RFC 9106 (Argon2id, com segredo e dados associados) e casos
//! diferenciais contra o `argon2-cffi` (referência em C).

use super::*;
use crate::testutil::hex;

fn de_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[allow(
    clippy::too_many_arguments,
    clippy::many_single_char_names,
    reason = "auxiliar de teste"
)]
fn roda(t: u32, m: u32, p: u32, pw: &[u8], sa: &[u8], k: &[u8], x: &[u8], n: usize) -> String {
    let pr = Params { t, m_kib: m, p };
    let mut work = vec![[0u64; 128]; pr.work_blocks().unwrap()];
    let mut out = vec![0u8; n];
    argon2id(pw, sa, k, x, pr, &mut work, &mut out).unwrap();
    assert!(
        work.iter().all(|b| b.iter().all(|w| *w == 0)),
        "memória não zerada"
    );
    hex(&out)
}

#[test]
fn rfc9106_argon2id() {
    let tag = roda(3, 32, 4, &[1; 32], &[2; 16], &[3; 8], &[4; 12], 32);
    assert_eq!(
        tag,
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
}

/// `(t, m, p, senha, sal, tag)`.
const CASOS: &[(u32, u32, u32, &str, &str, &str)] = &[
    (
        1,
        8,
        1,
        "762638249a01343d",
        "63bc9eb5481f2248",
        "1e91de58778d61310d64b69396f86105ebc01056258ec8c720cb605930e45b8c",
    ),
    (
        2,
        16,
        1,
        "0fd34927",
        "df5e2cb5ff6534d547f86228f90f2d45",
        "b40317efe4f8ade854336a557524f037ca2937a9c3477c14fb86d643ace11b61",
    ),
    (
        3,
        64,
        1,
        "9983ab708b4d4fda0afa",
        "a1562c50103739989a0cd4104c5f2a00",
        "0415242fcdc51eb160b78749ef7c7d74ba00666a02b089f20776ac09d52a1236",
    ),
    (
        3,
        32,
        4,
        "be226eca76d0b3ab70b1c807",
        "7b8618bdabb4e878d459664c6c81e7f5",
        "0b7b7a8ecd79b88b45a6315e1f491623c3e6ae801d58b9b023eeb5a43992e95e",
    ),
    (
        2,
        64,
        2,
        "71aa5e7985820b5e9f",
        "76219aa868117e2f",
        "2d3969d5a23d028996bc415b830967f90ed52a537534d53c2f92d4a69b36c77a35fb91791144e7c556220dc1524e217ac0246aec438f308a4d1440803e13ae16",
    ),
    (
        3,
        256,
        1,
        "287de26f16d446bdb62325c645d677ad69c29222",
        "f3071aff10c221d95149226951fc73a3af464548a31562794579e8bcbe3d8b4a",
        "9a8a063c1d808fd46df5549d48ae9729a31a81685fffe0c7c0de5465b1372ab9c1e48a8b723dcc3c11f6800f695aca03912a98c5650d7e16b6c5a481c308d61d21bb8fe6e023724f6a0f1d77cf00e7cd9bf8283c5dfdbb31e19cc6c53884d415016d46f4",
    ),
    (
        2,
        24,
        2,
        "245eb1193f",
        "9da45d3e8ce2862f29720827",
        "5070f9fe4172bfdbd7a0a2c2b9ecbe2f",
    ),
    (1, 40, 1, "", "9e5f52a93596f7eb", "7fa16fc3"),
    (
        2,
        128,
        4,
        "b3faee13614b",
        "f00ce0cd1a90531758cd",
        "847e1c9d5e30e38ffcf2bb0eadac8838353886d73e23a4820bc3d9bc25604daf86cc926c443cf91a49db9349e4924db58071a6a1a9de2dc4dcc60f63c4b9e2ef7ee4dd7139f573f42540a3fce84b86223320f16aebee49af74c72cd59686d1f4fce88411bb3bd91f3671309d9d1460470f72cf55f44fe55ca0cc4d19deca430e889807fb262ceea905a36c2371f7f4aa840f158717481f36c96244a026fe9fddfe06ccf54666c7c255c4129e3b67d03e59c0dc86a4572a712119b0e28557410bf7fb043bbc746aaeb6bcc069709f353ecdfa93f28a7f35f432be4dbbd15afd572608e953489784f8d4ca62e5d9cec1bcb419855f193baaf26f79116425af94b491f6621db7b69d646b6ed82b4cbb566cdbee56b51d6e01ffa0462e57bfcb973e1c63089307bfe10e78cb230e41823e58d33a66c87b92cf229836685ed5d9a656fb51c517190d0be858b87ea148034d7c4432bdc96248e5a6030e78e87dfe549c85854981605dc7afd384c2378b03051b73ff05400dc42f0b4a51c1bd49cf62854f0c4f8b7db30ebdae675e749e0949e3c962a96f765d6c801fb927f443e29a05d22169b8fd07613c815d40f2bfb4ab6ecb3618e955d6ff20e37bd5968bcd2339137807bc60309ac422393addc0cff02d11f818dab47dc3f4b30fa9dbe0d546f052e85ff9b8dd9771036c8cfd79149512df8d248f7f39da2b4b83608d83f13a51b53b80bdf1b63cbd0d7d544a6c0de9b2a16d8aa89ea51ca0f74ff3b17de6fa13033f8956e06eda9913e1d98836628275ab399c90f7f85c9b36301f4496e881e048b541d70008558d4a14f48542abebb753d6b5aacfbeb72683f1ea5c4fba8e63a24b8c41dfd6bd08d61a13555838e5cb169851e6ad2597b9c53de9023fa0e2b19f0f6f191f5b3ee8190c5a53d79064d5a231bc86f515000285e1339d5374c6f1a763c0770ab5b7521ae5a20c8ca832affa387cfc5169795705bd4d675538f76641f72cf9848c017591eaf6841b95d4415191081aa8c72055362a2b7adeeac641e95e2d3cfb349add23701cc6ac28ea5d8afcd3616fbb9b5e78d868b1e4009d9d68b5f94a21cea87bd71311fd939731d02cdbf23fa203c81929ca2a9e7bf943e0a96541ae41acd675d0c9aeb1bbb1f3a0d5bce56dc1a393bfc7d4c37bb4a13261b092cf8ed515ebaa51ea6f3a14a27a4a09248e6164f33741d3bfff00f8b2f87fe3ef43e3fdb4cc6c76b9b04e3abaf1e3e243f45faf45231d9809e212b80302e6af3c65f1316558ebe5ccb310542971356f236a2448fcfe40125e4f2b5189fd4c6e61f8ffc7667669fccad61249a070e06c0edabd020fd9e972c892cd7bf64af16985542cb1f1b0d1e2ad872f4f3b2f34c96b618ecda6a08feaf95b5cb4d6baec5839cc1c49291f91a67f6737869b6e88d60abf4d46a5de649c9ae39b1ee7729f847dc83da715191b0a912aa28a94f04fb493e30e86ee1cd9cc47c6da6c6e639be63b398e561633f75673a2f69b2d822bc7410d04fa4b787a025337636c0859fa1608f711987b8c3de61aea45",
    ),
];

#[test]
fn diferencial() {
    for (t, m, p, pw, sa, esp) in CASOS {
        let r = roda(
            *t,
            *m,
            *p,
            &de_hex(pw),
            &de_hex(sa),
            &[],
            &[],
            esp.len() / 2,
        );
        assert_eq!(r, *esp, "t={t} m={m} p={p}");
    }
}

#[test]
fn parametros_invalidos() {
    let ok = Params {
        t: 1,
        m_kib: 8,
        p: 1,
    };
    let mut w = vec![[0u64; 128]; 8];
    let mut o = [0u8; 32];
    assert_eq!(
        argon2id(b"p", b"curto", &[], &[], ok, &mut w, &mut o),
        Err(Error::SaltTooShort)
    );
    assert_eq!(
        argon2id(b"p", b"saaaaaaa", &[], &[], ok, &mut w, &mut [0u8; 3]),
        Err(Error::BadOutputLen)
    );
    let ruim = Params { t: 0, ..ok };
    assert_eq!(
        argon2id(b"p", b"saaaaaaa", &[], &[], ruim, &mut w, &mut o),
        Err(Error::BadParams)
    );
    assert_eq!(
        argon2id(b"p", b"saaaaaaa", &[], &[], ok, &mut w[..4], &mut o),
        Err(Error::WorkTooSmall)
    );
}
