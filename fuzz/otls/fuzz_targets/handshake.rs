#![no_main]

//! Handshake do cliente contra bytes do fuzz, em dois modos (primeiro
//! byte par ou ímpar):
//!
//! - registros crus logo depois do `ClientHello`: cabeçalhos, alertas, CCS,
//!   `ServerHello` mal formado;
//! - depois de um `ServerHello` válido feito aqui (ML-KEM-768 e X25519 com
//!   chaves fixas), o resto da entrada é o texto claro do voo do servidor,
//!   cifrado com a chave de handshake em registros do tamanho pedido pelo
//!   segundo byte. Assim o fuzz chega a `EncryptedExtensions`,
//!   `Certificate`, `CertificateVerify` e `Finished`.
//!
//! O verificador aceita toda assinatura, para o fuzz passar da cadeia de
//! teste do `ox509`; o `Finished` ele não acerta, e nenhuma entrada pode
//! terminar o handshake.

use libfuzzer_sys::fuzz_target;
use optcrypt::mlkem768;
use optcrypt::secret::Secret;
use optcrypt::x25519;
use otls::Suite;
use otls::client::{Client, Config};
use otls::msg::Reader;
use otls::record::{HEADER_LEN, MAX_RECORD, content};
use otls::schedule::{EarlySecret, Transcript};
use ox509::verify::{Anchors, ServerName, SignatureVerifier};
use ox509::{PublicKey, SignatureAlgorithm};

const ROOT: &[u8] = include_bytes!("../../../lib/ox509/testdata/teste-root.der");
const LEAF: &[u8] = include_bytes!("../../../lib/ox509/testdata/teste-leaf.der");

struct Aceita;

impl SignatureVerifier for Aceita {
    fn verify(&self, _: SignatureAlgorithm, _: &PublicKey<'_>, _: &[u8], _: &[u8]) -> bool {
        true
    }
}

fn client() -> Client<'static, Aceita> {
    let cfg = Config {
        name: ServerName::Dns("optimus.test"),
        anchors: Anchors::parse(ROOT).unwrap(),
        // Um dia depois do `notBefore` da folha de teste.
        now: ox509::Certificate::parse(LEAF).unwrap().not_before + 86_400,
        allow_classic: false,
        pin: None,
    };
    let mut n = 0u8;
    Client::new(cfg, Aceita, &mut |b: &mut [u8]| {
        for x in b {
            n = n.wrapping_mul(29).wrapping_add(3);
            *x = n;
        }
    })
}

/// Lê do `ClientHello` o `session_id` e a partilha híbrida.
fn hello(ch: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut r = Reader::new(&ch[HEADER_LEN + 4..]);
    r.take(34).unwrap();
    let sid = r.vec(1).unwrap().to_vec();
    r.vec(2).unwrap();
    r.vec(1).unwrap();
    let mut exts = Reader::new(r.vec(2).unwrap());
    while !exts.is_empty() {
        let id = exts.u16().unwrap();
        let data = exts.vec(2).unwrap();
        if id == 51 {
            let mut l = Reader::new(Reader::new(data).vec(2).unwrap());
            l.u16().unwrap();
            return (sid, l.vec(2).unwrap().to_vec());
        }
    }
    unreachable!("ClientHello sem key_share")
}

fn feed(c: &mut Client<'_, Aceita>, rec: &mut [u8], out: &mut [u8]) -> bool {
    match c.read_record(rec, out) {
        Ok(ev) => {
            assert!(!ev.connected, "handshake terminou sem Finished válido");
            true
        }
        Err(e) => {
            let _ = c.alert(e, out);
            false
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut c = client();
    let mut out = vec![0u8; 4096];
    let n = c.start(&mut out).unwrap();
    if mode % 2 == 0 {
        // Registros crus: cabeçalho do fuzz, tamanho limitado ao que sobra.
        let mut d = rest;
        while d.len() >= HEADER_LEN {
            let len = usize::from(u16::from_be_bytes([d[3], d[4]])).min(d.len() - HEADER_LEN);
            let mut rec = d[..HEADER_LEN + len].to_vec();
            rec[3..5].copy_from_slice(&u16::try_from(len).unwrap().to_be_bytes());
            d = &d[HEADER_LEN + len..];
            if !feed(&mut c, &mut rec, &mut out) {
                return;
            }
        }
        return;
    }
    let Some((&chunk, flight)) = rest.split_first() else {
        return;
    };
    let chunk = (usize::from(chunk) + 1) * 64;
    // ServerHello válido com ChaCha20 e X25519MLKEM768.
    let (sid, share) = hello(&out[..n]);
    let ch = out[HEADER_LEN..n].to_vec();
    let ek: &[u8; mlkem768::EK_LEN] = share[..mlkem768::EK_LEN].try_into().unwrap();
    let xpub: &[u8; 32] = share[mlkem768::EK_LEN..].try_into().unwrap();
    let mut m = Secret::<32>::zeroed();
    m.expose_mut().fill(9);
    let (ct, ss) = mlkem768::encaps(ek, &m).unwrap();
    let mut sk = Secret::<32>::zeroed();
    sk.expose_mut().fill(0x42);
    let xs = x25519::diffie_hellman(&sk, xpub).unwrap();
    let mut body = vec![3, 3];
    body.extend([0x55; 32]);
    body.push(u8::try_from(sid.len()).unwrap());
    body.extend(&sid);
    body.extend([0x13, 0x03, 0]);
    let ks = [&[0x11, 0xEC, 0x04, 0x60][..], &ct, &x25519::public_key(&sk)].concat();
    let mut e = vec![0, 43, 0, 2, 3, 4, 0, 51];
    e.extend(u16::try_from(ks.len()).unwrap().to_be_bytes());
    e.extend(ks);
    body.extend(u16::try_from(e.len()).unwrap().to_be_bytes());
    body.extend(e);
    let mut sh = vec![2, 0];
    sh.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
    sh.extend(body);
    let mut rec = vec![content::HANDSHAKE, 3, 3];
    rec.extend(u16::try_from(sh.len()).unwrap().to_be_bytes());
    rec.extend(&sh);
    assert!(
        feed(&mut c, &mut rec, &mut out),
        "ServerHello válido recusado"
    );
    let suite = Suite::Chacha20Poly1305Sha256;
    let mut t = Transcript::new(suite);
    t.update(&ch);
    t.update(&sh);
    let shared = [&ss.expose()[..], &xs.expose()[..]].concat();
    let (_, _, s) = EarlySecret::new(suite).handshake(&shared, &t.current());
    let mut keys = s.record_keys().unwrap();
    for part in flight.chunks(chunk.min(1 << 14)) {
        let mut buf = vec![0u8; MAX_RECORD];
        buf[HEADER_LEN..HEADER_LEN + part.len()].copy_from_slice(part);
        let total = keys.seal(content::HANDSHAKE, &mut buf, part.len()).unwrap();
        if !feed(&mut c, &mut buf[..total], &mut out) {
            return;
        }
    }
});
