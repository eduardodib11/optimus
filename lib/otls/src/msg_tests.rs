//! Mensagens de handshake (T-653) fora do cliente: casos que o servidor de
//! teste de `client_tests` não produz.

use crate::Error;
use crate::msg::{
    ClientHello, HRR_RANDOM, Reader, ServerHello, Writer, certificate, certificate_staple,
    certificate_verify, encrypted_extensions, ext, group, verify_input,
};

/// Corpo de `ServerHello` com `random`, suíte e extensões cruas.
fn sh(random: [u8; 32], exts: &[u8]) -> Vec<u8> {
    let mut v = vec![3, 3];
    v.extend(random);
    v.extend([1, 0xAA, 0x13, 0x03, 0]);
    if !exts.is_empty() {
        v.extend(u16::try_from(exts.len()).unwrap().to_be_bytes());
        v.extend(exts);
    }
    v
}

const VERSION: [u8; 6] = [0, 43, 0, 2, 3, 4];
const SHARE: [u8; 9] = [0, 51, 0, 5, 0, 0x1D, 0, 1, 9];

#[test]
fn server_hello_normal() {
    let exts = [&VERSION[..], &SHARE[..]].concat();
    let b = sh([7; 32], &exts);
    let s = ServerHello::parse(&b).unwrap();
    assert!(!s.retry && !s.downgrade);
    assert_eq!(
        (s.session_id, s.suite, s.version, s.share),
        (
            &[0xAA][..],
            0x1303,
            Some(0x0304),
            Some((group::X25519, &[9][..]))
        )
    );
}

#[test]
fn server_hello_sentinelas() {
    // TLS 1.2 sem extensões e com a sentinela de rebaixamento.
    let mut r = [7u8; 32];
    r[24..].copy_from_slice(b"DOWNGRD\x01");
    let b = sh(r, &[]);
    let s = ServerHello::parse(&b).unwrap();
    assert!(s.downgrade && s.version.is_none());
    // HRR: partilha só com o grupo, cookie aceito.
    let exts = [
        &VERSION[..],
        &[0, 51, 0, 2, 0x11, 0xEC],
        &[0, 44, 0, 3, 0, 1, 5],
    ]
    .concat();
    let b = sh(HRR_RANDOM, &exts);
    let s = ServerHello::parse(&b).unwrap();
    assert!(s.retry);
    assert_eq!(s.share, Some((group::X25519_MLKEM768, &[][..])));
}

#[test]
fn server_hello_recusas() {
    let rep = [&VERSION[..], &VERSION[..]].concat();
    assert_eq!(
        ServerHello::parse(&sh([7; 32], &rep)),
        Err(Error::IllegalParameter)
    );
    // Cookie fora de HRR e extensão desconhecida.
    let cookie = [0, 44, 0, 3, 0, 1, 5];
    assert_eq!(
        ServerHello::parse(&sh([7; 32], &cookie)),
        Err(Error::UnsupportedExtension)
    );
    // Lixo depois da extensão e versão truncada.
    assert_eq!(
        ServerHello::parse(&sh([7; 32], &[0, 43, 0, 3, 3, 4, 0])),
        Err(Error::Decode)
    );
    assert_eq!(
        ServerHello::parse(&sh([7; 32], &[0, 43, 0, 1, 3])),
        Err(Error::Decode)
    );
    // Compressão não nula.
    let mut b = sh([7; 32], &VERSION);
    b[2 + 32 + 2 + 2] = 1;
    assert_eq!(ServerHello::parse(&b), Err(Error::IllegalParameter));
    // Todos os prefixos falham sem pânico.
    let full = sh([7; 32], &[&VERSION[..], &SHARE[..]].concat());
    for n in 0..full.len() {
        assert!(ServerHello::parse(&full[..n]).is_err() || n == 2 + 32 + 2 + 2 + 1);
    }
}

#[test]
fn extensoes_cifradas() {
    assert_eq!(encrypted_extensions(&[0, 0]), Ok(()));
    let ok = [0, 14, 0, 0, 0, 0, 0, 10, 0, 6, 0, 4, 0x11, 0xEC, 0, 0x1D];
    assert_eq!(encrypted_extensions(&ok), Ok(()));
    assert_eq!(
        encrypted_extensions(&[0, 4, 0, 0, 0, 0, 0]),
        Err(Error::Decode)
    );
    let rep = [0, 8, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(encrypted_extensions(&rep), Err(Error::IllegalParameter));
    // ALPN não foi oferecido.
    assert_eq!(
        encrypted_extensions(&[0, 4, 0, 16, 0, 0]),
        Err(Error::UnsupportedExtension)
    );
    let sni = [0, 5, 0, 0, 0, 1, 0];
    assert_eq!(encrypted_extensions(&sni), Err(Error::Decode));
}

#[test]
fn lista_de_certificados() {
    let entry = |c: &[u8]| {
        let mut v = vec![0, 0, u8::try_from(c.len()).unwrap()];
        v.extend(c);
        v.extend([0, 0]);
        v
    };
    let body = |ctx: &[u8], entries: &[Vec<u8>]| {
        let list = entries.concat();
        let mut v = vec![u8::try_from(ctx.len()).unwrap()];
        v.extend(ctx);
        v.extend(&u32::try_from(list.len()).unwrap().to_be_bytes()[1..]);
        v.extend(list);
        v
    };
    let b = body(&[], &[entry(b"a"), entry(b"bc")]);
    let (l, n) = certificate(&b).unwrap();
    assert_eq!(&l[..n], &[&b"a"[..], &b"bc"[..]]);
    assert_eq!(certificate(&body(&[], &[])), Err(Error::Decode));
    assert_eq!(certificate(&body(&[], &[entry(b"")])), Err(Error::Decode));
    assert_eq!(
        certificate(&body(&[1], &[entry(b"a")])),
        Err(Error::IllegalParameter)
    );
    let many = vec![entry(b"x"); ox509::MAX_CHAIN + 1];
    assert_eq!(certificate(&body(&[], &many)), Err(Error::BadCertificate));
    assert_eq!(certificate_verify(&[4, 3, 0, 1, 9]), Ok((0x0403, &[9][..])));
    assert_eq!(certificate_verify(&[4, 3, 0, 2, 9]), Err(Error::Decode));
}

#[test]
fn ocsp_grampeado_na_folha() {
    // Uma entrada: certificado `a` e as extensões dadas.
    let body = |exts: &[u8], second: &[u8]| {
        let mut entry = vec![0, 0, 1, b'a'];
        entry.extend(u16::try_from(exts.len()).unwrap().to_be_bytes());
        entry.extend(exts);
        entry.extend(second);
        let mut v = vec![0];
        v.extend(&u32::try_from(entry.len()).unwrap().to_be_bytes()[1..]);
        v.extend(entry);
        v
    };
    let status = |t: u8, resp: &[u8]| {
        let mut data = vec![t];
        data.extend(&u32::try_from(resp.len()).unwrap().to_be_bytes()[1..]);
        data.extend(resp);
        let mut e = vec![0, 5];
        e.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
        e.extend(data);
        e
    };
    assert_eq!(certificate_staple(&body(&[], &[])), Ok(None));
    let ok = status(1, b"resp");
    assert_eq!(certificate_staple(&body(&ok, &[])), Ok(Some(&b"resp"[..])));
    // Outra extensão (SCT) antes: ignorada.
    let mut sct = vec![0, 18, 0, 1, 7];
    sct.extend(&ok);
    assert_eq!(certificate_staple(&body(&sct, &[])), Ok(Some(&b"resp"[..])));
    // Só a primeira entrada conta.
    let second = [0, 0, 1, b'b', 0, 0];
    assert_eq!(certificate_staple(&body(&[], &second)), Ok(None));
    // Tipo de status que não é OCSP, vazia, repetida, truncada.
    assert_eq!(
        certificate_staple(&body(&status(2, b"x"), &[])),
        Err(Error::IllegalParameter)
    );
    assert_eq!(
        certificate_staple(&body(&status(1, b""), &[])),
        Err(Error::Decode)
    );
    let twice = [ok.clone(), ok.clone()].concat();
    assert_eq!(
        certificate_staple(&body(&twice, &[])),
        Err(Error::IllegalParameter)
    );
    let mut cut = status(1, b"resp");
    cut.pop();
    cut[3] -= 1;
    assert_eq!(certificate_staple(&body(&cut, &[])), Err(Error::Decode));
}

#[test]
fn texto_do_certificate_verify() {
    let mut buf = [0u8; 64 + 34 + 48];
    let t = verify_input(&[0xEE; 32], &mut buf);
    assert_eq!(t.len(), 64 + 34 + 32);
    assert!(t[..64].iter().all(|&b| b == 0x20));
    assert_eq!(&t[64..98], b"TLS 1.3, server CertificateVerify\0");
    assert!(t[98..].iter().all(|&b| b == 0xEE));
}

#[test]
fn client_hello_e_escritor() {
    let mut buf = [0u8; 512];
    let mut w = Writer::new(&mut buf);
    let ch = ClientHello {
        random: &[1; 32],
        session_id: &[2; 32],
        suites: &[0x1303],
        server_name: Some("a.b"),
        shares: &[(group::X25519, &[3; 32])],
    };
    ch.write(&mut w).unwrap();
    let n = w.len();
    let mut r = Reader::new(&buf[..n]);
    assert_eq!(r.u8().unwrap(), 1);
    let mut body = Reader::new(r.vec(3).unwrap());
    r.finish().unwrap();
    assert_eq!(body.take(2).unwrap(), [3, 3]);
    assert_eq!(body.take(32).unwrap(), [1; 32]);
    assert_eq!(body.vec(1).unwrap(), [2; 32]);
    assert_eq!(body.vec(2).unwrap(), [0x13, 0x03]);
    assert_eq!(body.vec(1).unwrap(), [0]);
    let mut exts = Reader::new(body.vec(2).unwrap());
    body.finish().unwrap();
    let mut ids = Vec::new();
    while !exts.is_empty() {
        ids.push(exts.u16().unwrap());
        exts.vec(2).unwrap();
    }
    assert_eq!(
        ids,
        [
            ext::SERVER_NAME,
            ext::STATUS_REQUEST,
            ext::SUPPORTED_GROUPS,
            ext::SIGNATURE_ALGORITHMS,
            ext::SIGNATURE_ALGORITHMS_CERT,
            ext::SUPPORTED_VERSIONS,
            ext::KEY_SHARE
        ]
    );
    // Buffer curto: erro, não pânico.
    for len in 0..n {
        let mut small = vec![0u8; len];
        assert!(ch.write(&mut Writer::new(&mut small)).is_err());
    }
}
