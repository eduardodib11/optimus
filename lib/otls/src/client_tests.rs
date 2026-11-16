//! Handshake contra um servidor de teste escrito aqui com as mesmas
//! primitivas e a mesma agenda. O verificador de mentira aceita os elos da
//! cadeia (a cadeia é testada no `ox509`) e confere o `CertificateVerify`
//! como SHA-256 do texto assinado, o que confere o texto montado pelo
//! cliente contra o do servidor.

#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use optcrypt::mlkem768;
use optcrypt::secret::Secret;
use optcrypt::x25519;
use ox509::ocsp::OcspError;
use ox509::verify::{Anchors, ServerName, SignatureVerifier, VerifyError};
use ox509::{PublicKey, SignatureAlgorithm};

use super::*;
use crate::client::{Client, Config, Ocsp, OcspPolicy};
use crate::msg::{HRR_RANDOM, Reader, group, kind};
use crate::record::{HEADER_LEN, RecordKeys, content};
use crate::schedule::{EarlySecret, Traffic, Transcript};

const ROOT: &[u8] = include_bytes!("../../ox509/testdata/teste-root.der");
const INT: &[u8] = include_bytes!("../../ox509/testdata/teste-int.der");
const LEAF: &[u8] = include_bytes!("../../ox509/testdata/teste-leaf.der");
/// Cadeia do OCSP: uma CA e uma folha sem `must-staple` (`ocsp.optimus.test`).
const OCSP_CA: &[u8] = include_bytes!("../../ox509/testdata/ocsp-ca.der");
const OCSP_LEAF: &[u8] = include_bytes!("../../ox509/testdata/ocsp-folha-bom.der");
const OCSP_GOOD: &[u8] = include_bytes!("../../ox509/testdata/ocsp-resp-bom.der");
const OCSP_STALE: &[u8] = include_bytes!("../../ox509/testdata/ocsp-resp-curta.der");

struct Fake;

impl SignatureVerifier for Fake {
    fn verify(&self, _: SignatureAlgorithm, _: &PublicKey<'_>, msg: &[u8], sig: &[u8]) -> bool {
        !msg.starts_with(&[0x20; 64]) || optcrypt::sha256::hash(msg) == sig
    }
}

fn now() -> i64 {
    ox509::Certificate::parse(LEAF).unwrap().not_before + 86_400
}

fn ocsp_now() -> i64 {
    ox509::Certificate::parse(OCSP_LEAF).unwrap().not_before + 86_400
}

/// DER na mão, para montar respostas OCSP que o `Fake` aceita.
fn tlv(tag: u8, v: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match v.len() {
        n if n < 0x80 => out.push(u8::try_from(n).unwrap()),
        n if n < 0x100 => out.extend([0x81, u8::try_from(n).unwrap()]),
        n => {
            out.push(0x82);
            out.extend(u16::try_from(n).unwrap().to_be_bytes());
        }
    }
    out.extend(v);
    out
}

/// `GeneralizedTime` de `t` (segundos desde 1970).
fn gtime(t: i64) -> Vec<u8> {
    let (days, secs) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // `civil_from_days` de H. Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let text = format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    );
    tlv(0x18, text.as_bytes())
}

/// Resposta OCSP do `teste-leaf` (série 0xD1), "assinada" com RSA SHA-256:
/// o `Fake` aceita qualquer assinatura que não seja de `CertificateVerify`.
fn built_staple(status: Staple, this: i64, next: i64) -> Vec<u8> {
    let st = match status {
        Staple::Revoked => tlv(0xA1, &gtime(this - 100)),
        Staple::Unknown => tlv(0x82, &[]),
        _ => tlv(0x80, &[]),
    };
    let sha1 = tlv(
        0x30,
        &[tlv(0x06, &[0x2B, 0x0E, 0x03, 0x02, 0x1A]), tlv(0x05, &[])].concat(),
    );
    let id = tlv(
        0x30,
        &[
            sha1,
            tlv(0x04, &[0; 20]),
            tlv(0x04, &[0; 20]),
            tlv(0x02, &[0x00, 0xD1]),
        ]
        .concat(),
    );
    let single = tlv(
        0x30,
        &[id, st, gtime(this), tlv(0xA0, &gtime(next))].concat(),
    );
    let tbs = tlv(
        0x30,
        &[tlv(0xA1, &tlv(0x30, &[])), gtime(this), tlv(0x30, &single)].concat(),
    );
    let rsa_sha256 = tlv(
        0x30,
        &[
            tlv(
                0x06,
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
            ),
            tlv(0x05, &[]),
        ]
        .concat(),
    );
    let basic = tlv(0x30, &[tbs, rsa_sha256, tlv(0x03, &[0, 1, 2, 3])].concat());
    let basic_oid = tlv(
        0x06,
        &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
    );
    let rb = tlv(0x30, &[basic_oid, tlv(0x04, &basic)].concat());
    tlv(0x30, &[tlv(0x0A, &[0]), tlv(0xA0, &rb)].concat())
}

fn rng() -> impl FnMut(&mut [u8]) {
    let mut n = 0u8;
    move |b: &mut [u8]| {
        for x in b {
            n = n.wrapping_mul(31).wrapping_add(7);
            *x = n;
        }
    }
}

/// O OCSP que o servidor de teste grampeia.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Staple {
    /// Resposta boa: do `teste-leaf` (montada) ou do `ocsp-folha-bom` (real).
    #[default]
    Good,
    /// Nada.
    Absent,
    /// Revogado.
    Revoked,
    /// `unknown`.
    Unknown,
    /// `nextUpdate` já passou.
    Stale,
    /// Bytes de uma resposta pronta.
    Raw(&'static [u8]),
}

/// A cadeia que o servidor de teste apresenta.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Pki {
    /// `teste-leaf` (com `must-staple`) e `teste-int`.
    #[default]
    Teste,
    /// `ocsp-folha-bom` direto da `ocsp-ca`, sem `must-staple`.
    Ocsp,
}

/// O que o servidor de teste faz de diferente.
#[derive(Clone, Copy, Default)]
struct Knobs {
    staple: Staple,
    pki: Pki,
    classic: bool,
    tls12: bool,
    retry: bool,
    bad_cv: bool,
    bad_finished: bool,
    cert_request: bool,
    ee_extra: bool,
    aes: bool,
}

struct Server {
    t: Transcript,
    hs: Option<crate::schedule::HandshakeSecret>,
    c: Option<Traffic>,
    s_ap: Option<Traffic>,
    read: RecordKeys,
    write: RecordKeys,
}

fn record(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![kind, 3, 3];
    v.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    v.extend(data);
    v
}

fn hs_msg(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![kind];
    v.extend(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    v.extend(body);
    v
}

fn seal(keys: &mut RecordKeys, kind: u8, data: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; HEADER_LEN + data.len() + 1 + 16];
    b[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
    let n = keys.seal(kind, &mut b, data.len()).unwrap();
    b.truncate(n);
    b
}

/// Responde ao `ClientHello` (registro) com o registro do `ServerHello` e o
/// voo cifrado.
fn serve(ch_record: &[u8], k: Knobs) -> (Option<Server>, Vec<Vec<u8>>) {
    let ch = &ch_record[HEADER_LEN..];
    let mut r = Reader::new(&ch[4..]);
    r.take(2 + 32).unwrap();
    let sid = r.vec(1).unwrap().to_vec();
    let suites = r.vec(2).unwrap();
    r.vec(1).unwrap();
    let mut exts = Reader::new(r.vec(2).unwrap());
    let mut shares = Vec::new();
    while !exts.is_empty() {
        let id = exts.u16().unwrap();
        let data = exts.vec(2).unwrap();
        if id == 51 {
            let mut l = Reader::new(Reader::new(data).vec(2).unwrap());
            while !l.is_empty() {
                shares.push((l.u16().unwrap(), l.vec(2).unwrap().to_vec()));
            }
        }
    }
    let suite = if k.aes {
        Suite::Aes256GcmSha384
    } else {
        Suite::Chacha20Poly1305Sha256
    };
    assert!(suites.chunks(2).any(|s| s == suite.id().to_be_bytes()));
    let want = if k.classic {
        group::X25519
    } else {
        group::X25519_MLKEM768
    };
    let mut sk = Secret::<32>::zeroed();
    sk.expose_mut().fill(0x42);
    let spub = x25519::public_key(&sk);
    let (share, shared) = match shares.iter().find(|s| s.0 == want) {
        Some((_, ek_x)) if want == group::X25519_MLKEM768 => {
            let ek: &[u8; mlkem768::EK_LEN] = ek_x[..mlkem768::EK_LEN].try_into().unwrap();
            let xpub: &[u8; 32] = ek_x[mlkem768::EK_LEN..].try_into().unwrap();
            let mut m = Secret::<32>::zeroed();
            m.expose_mut().fill(9);
            let (ct, ss) = mlkem768::encaps(ek, &m).unwrap();
            let xs = x25519::diffie_hellman(&sk, xpub).unwrap();
            (
                [&ct[..], &spub[..]].concat(),
                [&ss.expose()[..], &xs.expose()[..]].concat(),
            )
        }
        Some((_, xpub)) => {
            let xs = x25519::diffie_hellman(&sk, xpub[..].try_into().unwrap()).unwrap();
            (spub.to_vec(), xs.expose().to_vec())
        }
        // O cliente não ofereceu: o servidor responde com x25519 mesmo.
        None => {
            let mut fake = Secret::<32>::zeroed();
            fake.expose_mut().fill(1);
            (spub.to_vec(), x25519::public_key(&fake).to_vec())
        }
    };
    let mut sh = vec![3, 3];
    sh.extend(if k.retry { HRR_RANDOM } else { [0x55; 32] });
    sh.push(32);
    sh.extend(&sid);
    sh.extend(suite.id().to_be_bytes());
    sh.push(0);
    let mut e = Vec::new();
    if !k.tls12 {
        e.extend([0, 43, 0, 2, 3, 4]);
    }
    e.extend([0, 51]);
    let ks: Vec<u8> = if k.retry {
        want.to_be_bytes().to_vec()
    } else {
        [
            &want.to_be_bytes()[..],
            &u16::try_from(share.len()).unwrap().to_be_bytes(),
            &share,
        ]
        .concat()
    };
    e.extend(u16::try_from(ks.len()).unwrap().to_be_bytes());
    e.extend(ks);
    sh.extend(u16::try_from(e.len()).unwrap().to_be_bytes());
    sh.extend(e);
    let sh = hs_msg(kind::SERVER_HELLO, &sh);
    let mut out = vec![record(content::HANDSHAKE, &sh)];
    if k.retry || k.tls12 {
        return (None, out);
    }

    let mut t = Transcript::new(suite);
    t.update(ch);
    t.update(&sh);
    let (hs, c, s) = EarlySecret::new(suite).handshake(&shared, &t.current());
    let mut write = s.record_keys().unwrap();
    let read = c.record_keys().unwrap();
    out.push(record(content::CHANGE_CIPHER_SPEC, &[1]));

    let mut flight = Vec::new();
    let mut add = |t: &mut Transcript, m: Vec<u8>| {
        t.update(&m);
        flight.extend(m);
    };
    let ee: &[u8] = if k.ee_extra {
        &[0, 4, 0, 16, 0, 0]
    } else {
        &[0, 0]
    };
    add(&mut t, hs_msg(kind::ENCRYPTED_EXTENSIONS, ee));
    if k.cert_request {
        add(
            &mut t,
            hs_msg(kind::CERTIFICATE_REQUEST, &[2, 0xAB, 0xCD, 0, 0]),
        );
    }
    let (chain, t_now): (&[&[u8]], i64) = match k.pki {
        Pki::Teste => (&[LEAF, INT], now()),
        Pki::Ocsp => (&[OCSP_LEAF], ocsp_now()),
    };
    let staple = match (k.staple, k.pki) {
        (Staple::Absent, _) => None,
        (Staple::Raw(b), _) => Some(b.to_vec()),
        (Staple::Good, Pki::Ocsp) => Some(OCSP_GOOD.to_vec()),
        (Staple::Stale, Pki::Ocsp) => Some(OCSP_STALE.to_vec()),
        (Staple::Stale, _) => Some(built_staple(Staple::Good, t_now - 7200, t_now - 10)),
        (st, _) => Some(built_staple(st, t_now - 3600, t_now + 3600)),
    };
    let mut list = Vec::new();
    for (i, cert) in chain.iter().enumerate() {
        list.extend(&u32::try_from(cert.len()).unwrap().to_be_bytes()[1..]);
        list.extend(*cert);
        match (&staple, i) {
            // `status_request` na folha: tipo `ocsp` e a resposta.
            (Some(resp), 0) => {
                let mut data = vec![1];
                data.extend(&u32::try_from(resp.len()).unwrap().to_be_bytes()[1..]);
                data.extend(resp);
                let mut e = vec![0, 5];
                e.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
                e.extend(data);
                list.extend(u16::try_from(e.len()).unwrap().to_be_bytes());
                list.extend(e);
            }
            _ => list.extend([0, 0]),
        }
    }
    let mut body = vec![0];
    body.extend(&u32::try_from(list.len()).unwrap().to_be_bytes()[1..]);
    body.extend(list);
    add(&mut t, hs_msg(kind::CERTIFICATE, &body));
    let mut buf = [0u8; 64 + 34 + 48];
    let mut sig =
        optcrypt::sha256::hash(crate::msg::verify_input(t.current().as_bytes(), &mut buf));
    if k.bad_cv {
        sig[0] ^= 1;
    }
    let mut cv = vec![4, 3, 0, 32];
    cv.extend(sig);
    add(&mut t, hs_msg(kind::CERTIFICATE_VERIFY, &cv));
    let mut fin = s.finished(&t.current()).as_bytes().to_vec();
    if k.bad_finished {
        fin[0] ^= 1;
    }
    add(&mut t, hs_msg(kind::FINISHED, &fin));
    out.push(seal(&mut write, content::HANDSHAKE, &flight));
    let srv = Server {
        t,
        hs: Some(hs),
        c: Some(c),
        s_ap: None,
        read,
        write,
    };
    (Some(srv), out)
}

impl Server {
    /// Confere o voo do cliente e passa às chaves da aplicação.
    fn finish(&mut self, client_out: &mut [u8], cert_request: bool) {
        assert_eq!(&client_out[..6], &[20, 3, 3, 0, 1, 1]);
        let rec = &mut client_out[6..];
        let (kind_, pt) = self.read.open(rec).unwrap();
        assert_eq!(kind_, content::HANDSHAKE);
        let mut pt = pt.to_vec();
        let (_, c_ap, s_ap) = self.hs.take().unwrap().application(&self.t.current());
        if cert_request {
            // Certificate vazio com o contexto pedido.
            assert_eq!(
                &pt[..10],
                &[kind::CERTIFICATE, 0, 0, 6, 2, 0xAB, 0xCD, 0, 0, 0]
            );
            self.t.update(&pt[..10]);
            pt.drain(..10);
        }
        assert_eq!(pt[0], kind::FINISHED);
        assert!(
            self.c
                .take()
                .unwrap()
                .verify_finished(&self.t.current(), &pt[4..])
        );
        self.read = c_ap.record_keys().unwrap();
        self.write = s_ap.record_keys().unwrap();
        // Guarda os segredos para o KeyUpdate.
        self.c = Some(c_ap);
        self.s_ap = Some(s_ap);
    }
}

fn config(anchors: &[u8]) -> Config<'_, 'static> {
    Config {
        name: ServerName::Dns("optimus.test"),
        anchors: Anchors::parse(anchors).unwrap(),
        now: now(),
        allow_classic: false,
        pin: None,
        ocsp: OcspPolicy::Opportunistic,
    }
}

fn ocsp_config(anchors: &[u8]) -> Config<'_, 'static> {
    Config {
        name: ServerName::Dns("ocsp.optimus.test"),
        now: ocsp_now(),
        ..config(anchors)
    }
}

/// Faz o handshake com `k`; devolve o cliente, o servidor e o erro, se houve.
fn run<'a>(
    cfg: Config<'a, '_>,
    k: Knobs,
) -> (Client<'a, Fake>, Option<Server>, Result<Vec<u8>, Error>) {
    let mut c = Client::new(cfg, Fake, &mut rng());
    let mut out = vec![0u8; 4096];
    let n = c.start(&mut out).unwrap();
    let (srv, recs) = serve(&out[..n], k);
    let mut last = Vec::new();
    for mut r in recs {
        match c.read_record(&mut r, &mut out) {
            Ok(ev) => last = out[..ev.send].to_vec(),
            Err(e) => return (c, srv, Err(e)),
        }
    }
    (c, srv, Ok(last))
}

#[test]
fn handshake_hibrido_e_dados() {
    for aes in [false, true] {
        if aes && !Suite::Aes256GcmSha384.available() {
            continue;
        }
        let k = Knobs {
            aes,
            ..Knobs::default()
        };
        let (mut c, srv, r) = run(config(ROOT), k);
        let mut flight = r.unwrap();
        let mut srv = srv.unwrap();
        assert!(c.is_connected());
        assert_eq!(
            c.suite(),
            Some(if aes {
                Suite::Aes256GcmSha384
            } else {
                Suite::Chacha20Poly1305Sha256
            })
        );
        srv.finish(&mut flight, false);
        // Cliente → servidor.
        let mut out = vec![0u8; 256];
        let n = c.write_app(b"GET / HTTP/1.1\r\n", &mut out).unwrap();
        assert_eq!(
            srv.read.open(&mut out[..n]).unwrap(),
            (content::APPLICATION_DATA, &b"GET / HTTP/1.1\r\n"[..])
        );
        // Servidor → cliente.
        let mut rec = seal(
            &mut srv.write,
            content::APPLICATION_DATA,
            b"HTTP/1.1 200 OK",
        );
        let ev = c.read_record(&mut rec, &mut out).unwrap();
        assert_eq!(&rec[ev.app], b"HTTP/1.1 200 OK");
        // close_notify.
        let mut rec = seal(&mut srv.write, content::ALERT, &[1, 0]);
        assert!(c.read_record(&mut rec, &mut out).unwrap().closed);
    }
}

#[test]
fn x25519_puro_so_com_politica() {
    let k = Knobs {
        classic: true,
        ..Knobs::default()
    };
    let (_, _, r) = run(config(ROOT), k);
    assert_eq!(r.unwrap_err(), Error::IllegalParameter);
    let cfg = Config {
        allow_classic: true,
        ..config(ROOT)
    };
    let (c, _, r) = run(cfg, k);
    assert!(r.is_ok() && c.is_connected());
}

#[test]
fn tls12_e_hrr_recusados() {
    let (_, _, r) = run(
        config(ROOT),
        Knobs {
            tls12: true,
            ..Knobs::default()
        },
    );
    assert_eq!(r.unwrap_err(), Error::Tls12Only);
    let (_, _, r) = run(
        config(ROOT),
        Knobs {
            retry: true,
            ..Knobs::default()
        },
    );
    assert_eq!(r.unwrap_err(), Error::HandshakeFailure);
}

#[test]
fn assinatura_e_finished_errados() {
    let (mut c, _, r) = run(
        config(ROOT),
        Knobs {
            bad_cv: true,
            ..Knobs::default()
        },
    );
    let e = r.unwrap_err();
    assert_eq!(e, Error::DecryptError);
    // O alerta sai cifrado com a chave de handshake: o par não vê o motivo.
    let mut out = [0u8; 64];
    let n = c.alert(e, &mut out);
    assert_eq!(
        (out[0], n),
        (content::APPLICATION_DATA, HEADER_LEN + 2 + 1 + 16)
    );
    let (_, _, r) = run(
        config(ROOT),
        Knobs {
            bad_finished: true,
            ..Knobs::default()
        },
    );
    assert_eq!(r.unwrap_err(), Error::DecryptError);
}

#[test]
fn cadeia_e_nome() {
    let cfg = Config {
        name: ServerName::Dns("outro.test"),
        ..config(ROOT)
    };
    let (_, _, r) = run(cfg, Knobs::default());
    assert_eq!(
        r.unwrap_err(),
        Error::Certificate(VerifyError::NameMismatch)
    );
    let (_, _, r) = run(config(&[]), Knobs::default());
    assert_eq!(
        r.unwrap_err(),
        Error::Certificate(VerifyError::UnknownIssuer)
    );
    assert_eq!(
        Error::Certificate(VerifyError::UnknownIssuer).alert(),
        Some(48)
    );
}

#[test]
fn modo_pin() {
    let spki = ox509::Certificate::parse(LEAF).unwrap().spki;
    let pin = optcrypt::sha256::hash(spki);
    let cfg = Config {
        pin: Some(pin),
        ..config(&[])
    };
    let (c, _, r) = run(cfg, Knobs::default());
    assert!(r.is_ok() && c.is_connected());
    let mut errado = pin;
    errado[0] ^= 1;
    let cfg = Config {
        pin: Some(errado),
        ..config(&[])
    };
    assert_eq!(
        run(cfg, Knobs::default()).2.unwrap_err(),
        Error::BadCertificate
    );
}

#[test]
fn pedido_de_certificado_responde_vazio() {
    let k = Knobs {
        cert_request: true,
        ..Knobs::default()
    };
    let (c, srv, r) = run(config(ROOT), k);
    assert!(c.is_connected());
    srv.unwrap().finish(&mut r.unwrap(), true);
}

#[test]
fn extensao_nao_oferecida() {
    let (_, _, r) = run(
        config(ROOT),
        Knobs {
            ee_extra: true,
            ..Knobs::default()
        },
    );
    assert_eq!(r.unwrap_err(), Error::UnsupportedExtension);
}

#[test]
fn key_update_com_pedido() {
    let (mut c, srv, r) = run(config(ROOT), Knobs::default());
    let mut srv = srv.unwrap();
    srv.finish(&mut r.unwrap(), false);
    // O servidor atualiza a própria chave e pede a do cliente.
    let mut rec = seal(
        &mut srv.write,
        content::HANDSHAKE,
        &[kind::KEY_UPDATE, 0, 0, 1, 1],
    );
    let s_next = srv.s_ap.take().unwrap().update();
    srv.write = s_next.record_keys().unwrap();
    let mut out = vec![0u8; 256];
    let ev = c.read_record(&mut rec, &mut out).unwrap();
    // A resposta vai com a chave velha; depois tudo com a nova.
    let (k, pt) = srv.read.open(&mut out[..ev.send]).unwrap();
    assert_eq!(
        (k, pt),
        (content::HANDSHAKE, &[kind::KEY_UPDATE, 0, 0, 1, 0][..])
    );
    let c_next = srv.c.take().unwrap().update();
    srv.read = c_next.record_keys().unwrap();
    let n = c.write_app(b"depois", &mut out).unwrap();
    assert_eq!(srv.read.open(&mut out[..n]).unwrap().1, b"depois");
    let mut rec = seal(&mut srv.write, content::APPLICATION_DATA, b"nova");
    let ev = c.read_record(&mut rec, &mut out).unwrap();
    assert_eq!(&rec[ev.app], b"nova");
}

#[test]
fn ordem_e_estado() {
    let mut c = Client::new(config(ROOT), Fake, &mut rng());
    let mut out = vec![0u8; 4096];
    // Dados antes do handshake e registro antes do ClientHello.
    assert_eq!(
        c.write_app(b"x", &mut out).unwrap_err(),
        Error::UnexpectedMessage
    );
    let mut rec = record(content::HANDSHAKE, &[2, 0, 0, 0]);
    assert_eq!(
        c.read_record(&mut rec, &mut out).unwrap_err(),
        Error::UnexpectedMessage
    );
    let mut c = Client::new(config(ROOT), Fake, &mut rng());
    c.start(&mut out).unwrap();
    // Alerta em claro do servidor.
    let mut rec = record(content::ALERT, &[2, 40]);
    assert_eq!(
        c.read_record(&mut rec, &mut out).unwrap_err(),
        Error::PeerAlert(40)
    );
    assert_eq!(c.alert(Error::PeerAlert(40), &mut out), 0);
}

#[test]
fn client_hello_oferece_o_que_a_adr_manda() {
    let mut c = Client::new(config(ROOT), Fake, &mut rng());
    let mut out = vec![0u8; 4096];
    let n = c.start(&mut out).unwrap();
    let ch = &out[..n];
    assert_eq!(&ch[..3], &[content::HANDSHAKE, 3, 1]);
    let has = |needle: &[u8]| ch.windows(needle.len()).any(|w| w == needle);
    let mut r = Reader::new(&ch[HEADER_LEN + 4..]);
    r.take(2 + 32).unwrap();
    assert_eq!(r.vec(1).unwrap().len(), 32);
    let suites = r.vec(2).unwrap();
    // supported_versions só com TLS 1.3, X25519MLKEM768 e não x25519.
    assert!(has(&[0, 43, 0, 3, 2, 3, 4]));
    assert!(has(&[0x11, 0xEC, 0x04, 0xC0]));
    assert!(!has(&[0, 0x1D, 0, 32]));
    // SNI com o nome.
    assert!(has(b"\x00\x0coptimus.test"));
    // Só as suítes da ADR, a ChaCha20 sempre por último.
    assert!(suites.ends_with(&[0x13, 0x03]));
    assert!(
        suites
            .chunks(2)
            .all(|s| s == [0x13, 0x02] || s == [0x13, 0x03])
    );
}

#[test]
fn ocsp_pedido_no_client_hello() {
    let mut c = Client::new(config(ROOT), Fake, &mut rng());
    let mut out = vec![0u8; 4096];
    let n = c.start(&mut out).unwrap();
    // `status_request` com `ocsp`, sem responder nem extensões.
    assert!(
        out[..n]
            .windows(9)
            .any(|w| w == [0, 5, 0, 5, 1, 0, 0, 0, 0])
    );
}

#[test]
fn ocsp_bom_passa() {
    let (c, _, r) = run(config(ROOT), Knobs::default());
    assert!(r.is_ok(), "{:?}", r.err());
    assert_eq!(c.ocsp(), Some(Ocsp::Good));
}

#[test]
fn must_staple_exige_resposta() {
    for staple in [Staple::Absent, Staple::Stale, Staple::Unknown] {
        let k = Knobs {
            staple,
            ..Knobs::default()
        };
        let e = run(config(ROOT), k).2.unwrap_err();
        assert_eq!(
            e,
            match staple {
                Staple::Absent => Error::StapleRequired,
                Staple::Stale => Error::Ocsp(OcspError::Stale),
                _ => Error::Ocsp(OcspError::UnknownCertificate),
            }
        );
    }
    assert_eq!(Error::StapleRequired.alert(), Some(42));
    assert_eq!(Error::Ocsp(OcspError::Stale).alert(), Some(113));
}

#[test]
fn certificado_revogado_e_recusado() {
    let k = Knobs {
        staple: Staple::Revoked,
        ..Knobs::default()
    };
    let (mut c, _, r) = run(config(ROOT), k);
    assert_eq!(r.unwrap_err(), Error::Revoked);
    assert_eq!(Error::Revoked.alert(), Some(44));
    // Mesmo com a política de aceitar sem resposta.
    let mut out = [0u8; 64];
    assert!(c.alert(Error::Revoked, &mut out) > 0);
}

#[test]
fn sem_must_staple_aceita_sem_resposta_ou_com_resposta_inutil() {
    let run_ocsp = |staple, policy| {
        let k = Knobs {
            pki: Pki::Ocsp,
            staple,
            ..Knobs::default()
        };
        let cfg = Config {
            ocsp: policy,
            ..ocsp_config(OCSP_CA)
        };
        let (c, _, r) = run(cfg, k);
        (c.ocsp(), r.map(|_| ()))
    };
    let opp = OcspPolicy::Opportunistic;
    assert_eq!(run_ocsp(Staple::Good, opp), (Some(Ocsp::Good), Ok(())));
    assert_eq!(run_ocsp(Staple::Absent, opp), (Some(Ocsp::Absent), Ok(())));
    assert_eq!(
        run_ocsp(Staple::Stale, opp),
        (Some(Ocsp::Ignored(OcspError::Stale)), Ok(()))
    );
    assert_eq!(
        run_ocsp(Staple::Raw(b"lixo"), opp),
        (
            Some(Ocsp::Ignored(OcspError::Parse(ox509::Error::Malformed))),
            Ok(())
        )
    );
    // `Require` não deixa passar sem uma resposta boa.
    let req = OcspPolicy::Require;
    assert_eq!(run_ocsp(Staple::Good, req), (Some(Ocsp::Good), Ok(())));
    assert_eq!(run_ocsp(Staple::Absent, req).1, Err(Error::StapleRequired));
    assert_eq!(
        run_ocsp(Staple::Stale, req).1,
        Err(Error::Ocsp(OcspError::Stale))
    );
}

#[test]
fn pin_nao_olha_revogacao() {
    let spki = ox509::Certificate::parse(LEAF).unwrap().spki;
    let cfg = Config {
        pin: Some(optcrypt::sha256::hash(spki)),
        ..config(&[])
    };
    let k = Knobs {
        staple: Staple::Revoked,
        ..Knobs::default()
    };
    let (c, _, r) = run(cfg, k);
    assert!(r.is_ok());
    assert_eq!(c.ocsp(), Some(Ocsp::Skipped));
}
