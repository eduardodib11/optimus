//! O cliente TLS 1.3 do `tlsd` (`otls`, com o verificador real do `optcrypt`)
//! contra o `rustls` do host por um soquete de verdade (T-657). Cada teste é
//! uma linha da tabela de `docs/aceite/m6-tls.md`.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use otls::Error;
use otls::client::{Client, Config, Ocsp, OcspPolicy};
use otls::verifier::Optcrypt;
use ox509::Certificate;
use ox509::ocsp::OcspError;
use ox509::verify::{Anchors, ServerName, VerifyError};
use tlshost::{
    CA, ED25519, Leaf, NAME, Opts, P256, RSA, STAPLE_GOOD, STAPLE_REVOKED, Server, Suites,
};

/// O que o teste muda no lado do cliente.
#[derive(Clone, Copy)]
struct Cli {
    name: &'static str,
    anchors: &'static [u8],
    pin: Option<[u8; 32]>,
    ocsp: OcspPolicy,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            name: NAME,
            anchors: CA,
            pin: None,
            ocsp: OcspPolicy::Opportunistic,
        }
    }
}

#[derive(Debug)]
#[allow(dead_code, reason = "o Debug mostra o motivo nas falhas")]
enum Failure {
    Tls(Error),
    Io(String),
}

struct Outcome {
    body: Vec<u8>,
    ocsp: Option<Ocsp>,
    suite: Option<otls::Suite>,
}

fn urandom() -> impl FnMut(&mut [u8]) {
    let mut f = File::open("/dev/urandom").unwrap();
    move |b| f.read_exact(b).unwrap()
}

/// GET `path`; o corpo da resposta HTTP, conferido contra o `Content-Length`.
fn get(addr: SocketAddr, cli: Cli, path: &str) -> Result<Outcome, Failure> {
    let io = |e: std::io::Error| Failure::Io(e.to_string());
    let anchors = Anchors::parse(cli.anchors).unwrap();
    // Dentro da validade das folhas de teste (geradas no mesmo dia).
    let now = Certificate::parse(P256).unwrap().not_before + 86_400;
    let cfg = Config {
        name: ServerName::Dns(cli.name),
        anchors,
        now,
        allow_classic: false,
        pin: cli.pin,
        ocsp: cli.ocsp,
    };
    let mut sock = TcpStream::connect(addr).map_err(io)?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(io)?;
    let mut c = Box::new(Client::new(cfg, Optcrypt, &mut urandom()));
    let mut out = vec![0u8; 64 * 1024];
    let n = c.start(&mut out).map_err(Failure::Tls)?;
    sock.write_all(&out[..n]).map_err(io)?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {NAME}\r\n\r\n");
    let mut raw = Vec::new();
    loop {
        let mut rec = vec![0u8; 5];
        sock.read_exact(&mut rec).map_err(io)?;
        let len = usize::from(u16::from_be_bytes([rec[3], rec[4]]));
        rec.resize(5 + len, 0);
        sock.read_exact(&mut rec[5..]).map_err(io)?;
        match c.read_record(&mut rec, &mut out) {
            Ok(ev) => {
                sock.write_all(&out[..ev.send]).map_err(io)?;
                if ev.connected {
                    let n = c
                        .write_app(request.as_bytes(), &mut out)
                        .map_err(Failure::Tls)?;
                    sock.write_all(&out[..n]).map_err(io)?;
                }
                raw.extend_from_slice(&rec[ev.app.clone()]);
                if ev.closed {
                    break;
                }
            }
            Err(e) => {
                let n = c.alert(e, &mut out);
                let _ = sock.write_all(&out[..n]);
                return Err(Failure::Tls(e));
            }
        }
    }
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("cabeçalho HTTP");
    let head = String::from_utf8_lossy(&raw[..at]).into_owned();
    let body = raw[at + 4..].to_vec();
    let want: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .and_then(|v| v.parse().ok())
        .expect("Content-Length");
    assert_eq!(body.len(), want, "corpo truncado");
    Ok(Outcome {
        body,
        ocsp: c.ocsp(),
        suite: c.suite(),
    })
}

fn server(o: Opts) -> Server {
    Server::start("127.0.0.1:0".parse().unwrap(), &o).unwrap()
}

fn text(o: &Outcome) -> String {
    String::from_utf8_lossy(&o.body).into_owned()
}

#[test]
fn handshake_hibrido_com_cada_tipo_de_chave() {
    for leaf in [Leaf::P256, Leaf::Rsa, Leaf::Ed25519] {
        let s = server(Opts {
            leaf,
            ..Opts::default()
        });
        let o = get(s.addr, Cli::default(), "/").unwrap_or_else(|e| panic!("{leaf:?}: {e:?}"));
        let t = text(&o);
        assert!(t.contains("kx=X25519MLKEM768"), "{leaf:?}: {t}");
        assert_eq!(o.ocsp, Some(Ocsp::Absent));
    }
}

#[test]
fn cada_suite_das_duas() {
    let mut cases = vec![(Suites::Chacha, otls::Suite::Chacha20Poly1305Sha256)];
    if otls::Suite::Aes256GcmSha384.available() {
        cases.push((Suites::Aes256, otls::Suite::Aes256GcmSha384));
    }
    for (suites, want) in cases {
        let s = server(Opts {
            suites,
            ..Opts::default()
        });
        let o = get(s.addr, Cli::default(), "/").unwrap();
        assert_eq!(o.suite, Some(want));
    }
}

#[test]
fn um_mebibyte_e_troca_de_chaves() {
    let s = server(Opts::default());
    let o = get(s.addr, Cli::default(), "/big").unwrap();
    assert_eq!(o.body.len(), 1 << 20);
    assert!(
        o.body
            .iter()
            .enumerate()
            .all(|(i, &b)| b == (i as u32 % 251) as u8)
    );
    // KeyUpdate do servidor antes da resposta.
    let o = get(s.addr, Cli::default(), "/rekey").unwrap();
    assert!(text(&o).contains("optimus tlshost ok"));
}

#[test]
fn servidor_so_com_tls12_e_recusado() {
    let s = server(Opts {
        tls12_only: true,
        ..Opts::default()
    });
    // `Tls12Only` se o servidor responde com ServerHello 1.2; `PeerAlert(70)`
    // (`protocol_version`) se recusa antes.
    match get(s.addr, Cli::default(), "/") {
        Err(Failure::Tls(e @ (Error::Tls12Only | Error::PeerAlert(70)))) => {
            eprintln!("TLS 1.2: {e:?}")
        }
        r => panic!("esperava recusa de TLS 1.2, veio {:?}", r.err()),
    }
}

#[test]
fn servidor_sem_o_grupo_hibrido_e_recusado() {
    let s = server(Opts {
        hybrid: false,
        ..Opts::default()
    });
    // O cliente só oferece `X25519MLKEM768` (ADR 0070, item 4): sem grupo em
    // comum, `handshake_failure` (40) ou `insufficient_security` (71).
    match get(s.addr, Cli::default(), "/") {
        Err(Failure::Tls(e @ (Error::PeerAlert(40 | 71) | Error::HandshakeFailure))) => {
            eprintln!("sem híbrido: {e:?}");
        }
        r => panic!("esperava recusa sem grupo híbrido, veio {:?}", r.err()),
    }
}

#[test]
fn nome_raiz_e_pin() {
    let s = server(Opts::default());
    let r = get(
        s.addr,
        Cli {
            name: "outro.optimus.test",
            ..Cli::default()
        },
        "/",
    );
    assert!(matches!(
        r,
        Err(Failure::Tls(Error::Certificate(VerifyError::NameMismatch)))
    ));
    let r = get(
        s.addr,
        Cli {
            anchors: &[],
            ..Cli::default()
        },
        "/",
    );
    assert!(matches!(
        r,
        Err(Failure::Tls(Error::Certificate(VerifyError::UnknownIssuer)))
    ));
    // `pin`: a chave certa passa sem raiz; a errada não.
    let spki = Certificate::parse(P256).unwrap().spki;
    let pin = optcrypt::sha256::hash(spki);
    let ok = get(
        s.addr,
        Cli {
            anchors: &[],
            pin: Some(pin),
            ..Cli::default()
        },
        "/",
    )
    .unwrap();
    assert_eq!(ok.ocsp, Some(Ocsp::Skipped));
    let mut bad = pin;
    bad[0] ^= 1;
    let r = get(
        s.addr,
        Cli {
            anchors: &[],
            pin: Some(bad),
            ..Cli::default()
        },
        "/",
    );
    assert!(matches!(r, Err(Failure::Tls(Error::BadCertificate))));
    // As outras folhas têm chaves diferentes: o pin da P-256 não vale nelas.
    let rsa = server(Opts {
        leaf: Leaf::Rsa,
        ..Opts::default()
    });
    let r = get(
        rsa.addr,
        Cli {
            pin: Some(pin),
            ..Cli::default()
        },
        "/",
    );
    assert!(matches!(r, Err(Failure::Tls(Error::BadCertificate))));
    let _ = (RSA, ED25519);
}

#[test]
fn ocsp_grampeado() {
    let good = server(Opts {
        staple: Some(STAPLE_GOOD),
        ..Opts::default()
    });
    let o = get(good.addr, Cli::default(), "/").unwrap();
    assert_eq!(o.ocsp, Some(Ocsp::Good));
    // Exigir, com resposta boa: passa.
    let o = get(
        good.addr,
        Cli {
            ocsp: OcspPolicy::Require,
            ..Cli::default()
        },
        "/",
    )
    .unwrap();
    assert_eq!(o.ocsp, Some(Ocsp::Good));

    let revoked = server(Opts {
        staple: Some(STAPLE_REVOKED),
        ..Opts::default()
    });
    assert!(matches!(
        get(revoked.addr, Cli::default(), "/"),
        Err(Failure::Tls(Error::Revoked))
    ));

    // Sem resposta: aceita por padrão, recusa com `Require`.
    let none = server(Opts::default());
    assert_eq!(
        get(none.addr, Cli::default(), "/").unwrap().ocsp,
        Some(Ocsp::Absent)
    );
    assert!(matches!(
        get(
            none.addr,
            Cli {
                ocsp: OcspPolicy::Require,
                ..Cli::default()
            },
            "/"
        ),
        Err(Failure::Tls(Error::StapleRequired))
    ));
    // Resposta de outra folha (série 0x201 não é a da RSA): inútil, e então
    // aceita por padrão e recusada com `Require`.
    let other = server(Opts {
        leaf: Leaf::Rsa,
        staple: Some(STAPLE_GOOD),
        ..Opts::default()
    });
    assert_eq!(
        get(other.addr, Cli::default(), "/").unwrap().ocsp,
        Some(Ocsp::Ignored(OcspError::NoMatch))
    );
    assert!(matches!(
        get(
            other.addr,
            Cli {
                ocsp: OcspPolicy::Require,
                ..Cli::default()
            },
            "/"
        ),
        Err(Failure::Tls(Error::Ocsp(OcspError::NoMatch)))
    ));
}

#[test]
fn servidor_que_pede_certificado_ao_cliente() {
    let s = server(Opts {
        client_auth: true,
        ..Opts::default()
    });
    // O `tlsd` responde com um `Certificate` vazio; o servidor recusa.
    let r = get(s.addr, Cli::default(), "/");
    eprintln!("certificado do cliente: {:?}", r.as_ref().err());
    assert!(
        matches!(r, Err(Failure::Tls(Error::PeerAlert(_)) | Failure::Io(_))),
        "{:?}",
        r.err()
    );
}
