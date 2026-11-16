use super::Suite;
use super::record::{HEADER_LEN, MAX_PLAINTEXT, RecordError, RecordKeys, content, parse_header};
use super::schedule::*;

fn h(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Hash dado em hex, para os contextos da RFC 8448.
fn digest(s: &str) -> Digest {
    test_digest(&h(s))
}

/// RFC 8448, seção 3 (1-RTT simples, SHA-256). Os valores de chave de 16
/// bytes são do AES-128-GCM do exemplo; a derivação é a mesma.
#[test]
fn rfc8448_agenda_sha256() {
    let suite = Suite::Chacha20Poly1305Sha256;
    let early = EarlySecret::new(suite);
    assert_eq!(
        early_expose(&early),
        h("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
    );
    let shared = h("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    let hello = digest("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    let (hs, c_hs, s_hs) = early.handshake(&shared, &hello);
    assert_eq!(
        hs_expose(&hs),
        h("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
    );
    assert_eq!(
        c_hs.expose(),
        h("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    );
    assert_eq!(
        s_hs.expose(),
        h("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    );
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    s_hs.expand(b"key", &mut key);
    s_hs.expand(b"iv", &mut iv);
    assert_eq!(key.to_vec(), h("3fce516009c21727d0f2e4e86ee403bc"));
    assert_eq!(iv.to_vec(), h("5d313eb2671276ee13000b30"));
    c_hs.expand(b"key", &mut key);
    c_hs.expand(b"iv", &mut iv);
    assert_eq!(key.to_vec(), h("dbfaa693d1762c5b666af5d950258d01"));
    assert_eq!(iv.to_vec(), h("5bd3c71b836e0b76bb73265f"));
    let mut fk = [0u8; 32];
    s_hs.expand(b"finished", &mut fk);
    assert_eq!(
        fk.to_vec(),
        h("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")
    );
    c_hs.expand(b"finished", &mut fk);
    assert_eq!(
        fk.to_vec(),
        h("b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4")
    );

    let fin = digest("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    let (ms, c_ap, s_ap) = hs.application(&fin);
    assert_eq!(
        ms_expose(&ms),
        h("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
    );
    assert_eq!(
        c_ap.expose(),
        h("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
    );
    assert_eq!(
        s_ap.expose(),
        h("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
    );
    s_ap.expand(b"key", &mut key);
    s_ap.expand(b"iv", &mut iv);
    assert_eq!(key.to_vec(), h("9f02283b6c9c07efc26bb9f2ac92e356"));
    assert_eq!(iv.to_vec(), h("cf782b88dd83549aadf1e984"));
    c_ap.expand(b"key", &mut key);
    c_ap.expand(b"iv", &mut iv);
    assert_eq!(key.to_vec(), h("17422dda596ed5d9acd890e3c63f5051"));
    assert_eq!(iv.to_vec(), h("5b78923dee08579033e523d9"));
}

/// `Finished` = `HMAC(finished_key, hash)`: confere contra HMAC independente.
#[test]
fn finished_e_atualizacao() {
    for suite in [Suite::Chacha20Poly1305Sha256, Suite::Aes256GcmSha384] {
        let n = suite.hash_len();
        let mut t = Transcript::new(suite);
        t.update(b"mensagens");
        let hash = t.current();
        assert_eq!(hash.as_bytes().len(), n);
        let (_, c, _) = EarlySecret::new(suite).handshake(&[7; 32], &hash);
        let mut fk = vec![0u8; n];
        c.expand(b"finished", &mut fk);
        let want = match suite {
            Suite::Chacha20Poly1305Sha256 => {
                optcrypt::hmac::hmac_sha256(&fk, hash.as_bytes()).to_vec()
            }
            Suite::Aes256GcmSha384 => optcrypt::hmac::hmac_sha384(&fk, hash.as_bytes()).to_vec(),
        };
        assert_eq!(c.finished(&hash).as_bytes(), want);
        assert!(c.verify_finished(&hash, &want));
        let mut ruim = want.clone();
        ruim[0] ^= 1;
        assert!(!c.verify_finished(&hash, &ruim));
        assert!(!c.verify_finished(&hash, &want[..n - 1]));
        let mut upd = vec![0u8; n];
        c.expand(b"traffic upd", &mut upd);
        let next = c.update();
        assert_eq!(next.expose(), upd);
        assert_ne!(next.expose(), c.expose());
    }
}

#[test]
fn transcricao_parcial_nao_fecha() {
    let mut t = Transcript::new(Suite::Chacha20Poly1305Sha256);
    t.update(b"ab");
    let a = t.current();
    t.update(b"c");
    assert_eq!(a.as_bytes(), optcrypt::sha256::hash(b"ab"));
    assert_eq!(t.current().as_bytes(), optcrypt::sha256::hash(b"abc"));
    let mut t = Transcript::new(Suite::Aes256GcmSha384);
    t.update(b"abc");
    assert_eq!(t.current().as_bytes(), optcrypt::sha512::hash384(b"abc"));
}

fn par(suite: Suite) -> (RecordKeys, RecordKeys) {
    let (_, c, _) = EarlySecret::new(suite).handshake(&[1; 32], &Transcript::new(suite).current());
    (c.record_keys().unwrap(), c.record_keys().unwrap())
}

#[test]
fn registro_ida_e_volta() {
    for suite in [Suite::Chacha20Poly1305Sha256, Suite::Aes256GcmSha384] {
        assert!(suite.available());
        let (mut tx, mut rx) = par(suite);
        for msg in [&b""[..], b"GET / HTTP/1.1\r\n", &[0xAB; MAX_PLAINTEXT]] {
            let mut buf = vec![0u8; HEADER_LEN + msg.len() + 1 + 16];
            buf[HEADER_LEN..HEADER_LEN + msg.len()].copy_from_slice(msg);
            let n = tx
                .seal(content::APPLICATION_DATA, &mut buf, msg.len())
                .unwrap();
            assert_eq!(n, buf.len());
            assert_eq!(&buf[..3], &[23, 3, 3]);
            if !msg.is_empty() {
                assert_ne!(
                    &buf[HEADER_LEN..HEADER_LEN + msg.len().min(16)],
                    &msg[..msg.len().min(16)]
                );
            }
            let (kind, pt) = rx.open(&mut buf).unwrap();
            assert_eq!((kind, pt), (content::APPLICATION_DATA, msg));
        }
        assert_eq!((tx.sequence(), rx.sequence()), (3, 3));
    }
}

#[test]
fn registro_adulterado_ou_fora_de_ordem() {
    let (mut tx, mut rx) = par(Suite::Chacha20Poly1305Sha256);
    let seal = |tx: &mut RecordKeys| {
        let mut b = vec![0u8; HEADER_LEN + 4 + 1 + 16];
        b[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(b"oi!!");
        tx.seal(content::HANDSHAKE, &mut b, 4).unwrap();
        b
    };
    let a = seal(&mut tx);
    let b = seal(&mut tx);
    // Cabeçalho, conteúdo e tag adulterados: sempre o mesmo erro.
    for i in [1, 6, a.len() - 1] {
        let mut x = a.clone();
        x[i] ^= 1;
        let (mut _t, mut r) = par(Suite::Chacha20Poly1305Sha256);
        assert_eq!(r.open(&mut x).unwrap_err(), RecordError::BadRecordMac);
    }
    // Fora de ordem: o segundo registro com o número do primeiro.
    let mut x = b.clone();
    assert_eq!(rx.open(&mut x).unwrap_err(), RecordError::BadRecordMac);
    let mut x = a.clone();
    assert_eq!(rx.open(&mut x).unwrap_err(), RecordError::BadRecordMac);
}

#[test]
fn enchimento_e_tipo_interno() {
    let (mut tx, mut rx) = par(Suite::Chacha20Poly1305Sha256);
    // Texto interno só de zeros: sem tipo, `unexpected_message`.
    let mut b = vec![0u8; HEADER_LEN + 3 + 1 + 16];
    tx.seal(0, &mut b, 3).unwrap();
    assert_eq!(rx.open(&mut b).unwrap_err(), RecordError::Malformed);
    // Com enchimento: o tipo é o último byte não nulo.
    let mut b = vec![0u8; HEADER_LEN + 6 + 1 + 16];
    b[HEADER_LEN..HEADER_LEN + 6].copy_from_slice(&[b'x', b'y', content::ALERT, 0, 0, 0]);
    tx.seal(0, &mut b, 6).unwrap();
    assert_eq!(rx.open(&mut b).unwrap(), (content::ALERT, &b"xy"[..]));
}

#[test]
fn limites_do_registro() {
    let (mut tx, mut rx) = par(Suite::Chacha20Poly1305Sha256);
    let mut b = vec![0u8; HEADER_LEN + MAX_PLAINTEXT + 1 + 1 + 16];
    assert_eq!(
        tx.seal(23, &mut b, MAX_PLAINTEXT + 1).unwrap_err(),
        RecordError::Overflow
    );
    let mut small = [0u8; HEADER_LEN + 4];
    assert_eq!(
        tx.seal(23, &mut small, 1).unwrap_err(),
        RecordError::BufferTooSmall
    );
    assert_eq!(
        parse_header(&[23, 3, 3, 0x41, 0x01]).unwrap_err(),
        RecordError::Overflow
    );
    assert_eq!(
        parse_header(&[24, 3, 3, 0, 1]).unwrap_err(),
        RecordError::Malformed
    );
    assert_eq!(parse_header(&[22, 3, 1, 0, 1]), Ok((22, 1)));
    // Tipo externo errado, tamanho que não bate e curto demais.
    let mut outro_tipo = [&[22u8, 3, 3, 0, 17][..], &[0; 17]].concat();
    let mut tamanho = [&[23u8, 3, 3, 0, 18][..], &[0; 17]].concat();
    let mut curto = vec![23u8, 3, 3, 0, 2, 0, 0];
    let mut so_tipo = vec![23u8];
    for v in [&mut outro_tipo, &mut tamanho, &mut curto, &mut so_tipo] {
        assert_eq!(rx.open(v).unwrap_err(), RecordError::Malformed);
    }
    // Sequência no fim: o próximo registro pede `KeyUpdate`.
    tx.set_sequence(u64::MAX);
    let mut b = vec![0u8; HEADER_LEN + 1 + 16];
    assert_eq!(
        tx.seal(23, &mut b, 0).unwrap_err(),
        RecordError::SequenceExhausted
    );
}

#[test]
fn suites() {
    assert_eq!(Suite::from_id(0x1302), Some(Suite::Aes256GcmSha384));
    assert_eq!(Suite::from_id(0x1303).map(Suite::id), Some(0x1303));
    // TLS_AES_128_GCM_SHA256 fica de fora (ADR 0070, item 3).
    assert_eq!(Suite::from_id(0x1301), None);
}
