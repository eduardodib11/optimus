//! Servidor TLS de host para os testes do `tlsd` (T-654 e T-657).
//!
//! `rustls` com o provedor `aws-lc-rs` fala TLS 1.3 com o grupo híbrido
//! `X25519MLKEM768`, o mesmo que o `tlsd` oferece (ADR 0070), e serve de
//! contraparte independente: o que o `otls` aceita aqui não foi escrito pelo
//! mesmo código. Cada [`Opts`] liga um servidor com um defeito ou uma
//! restrição de propósito (só TLS 1.2, sem o grupo híbrido, sem uma suíte,
//! com OCSP grampeado, pedindo certificado do cliente).
//!
//! O servidor responde um GET HTTP/1.1: `/` devolve uma linha com o grupo e a
//! suíte negociados, `/big` devolve 1 MiB, `/rekey` troca as chaves de
//! tráfego antes de responder (KeyUpdate). Os certificados são de teste (ver
//! `fixtures/gerar.sh`): uma CA de P-256 e três folhas, `tls.optimus.test`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{CipherSuite, NamedGroup, ServerConfig, ServerConnection, StreamOwned};

/// Raiz de teste (âncora do cliente).
pub const CA: &[u8] = include_bytes!("../fixtures/ca.der");
/// Folha P-256 e a chave PKCS#8.
pub const P256: &[u8] = include_bytes!("../fixtures/p256.der");
const P256_KEY: &[u8] = include_bytes!("../fixtures/p256.key.der");
/// Folha RSA 2048 (assina com `rsa_pss_rsae_sha256`).
pub const RSA: &[u8] = include_bytes!("../fixtures/rsa.der");
const RSA_KEY: &[u8] = include_bytes!("../fixtures/rsa.key.der");
/// Folha Ed25519.
pub const ED25519: &[u8] = include_bytes!("../fixtures/ed25519.der");
const ED25519_KEY: &[u8] = include_bytes!("../fixtures/ed25519.key.der");
/// OCSP da folha P-256: bom e revogado, assinados pela CA.
pub const STAPLE_GOOD: &[u8] = include_bytes!("../fixtures/staple-bom.der");
/// Ver [`STAPLE_GOOD`].
pub const STAPLE_REVOKED: &[u8] = include_bytes!("../fixtures/staple-revogado.der");

/// Nome nos certificados.
pub const NAME: &str = "tls.optimus.test";

/// Qual folha o servidor apresenta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaf {
    /// ECDSA P-256 (`ecdsa_secp256r1_sha256`).
    P256,
    /// RSA 2048 (`rsa_pss_rsae_sha256`).
    Rsa,
    /// Ed25519.
    Ed25519,
}

impl Leaf {
    /// O certificado em DER.
    #[must_use]
    pub fn der(self) -> &'static [u8] {
        match self {
            Self::P256 => P256,
            Self::Rsa => RSA,
            Self::Ed25519 => ED25519,
        }
    }

    fn key(self) -> &'static [u8] {
        match self {
            Self::P256 => P256_KEY,
            Self::Rsa => RSA_KEY,
            Self::Ed25519 => ED25519_KEY,
        }
    }
}

/// Suítes TLS 1.3 que o servidor aceita.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suites {
    /// As duas.
    Both,
    /// Só `TLS_CHACHA20_POLY1305_SHA256`.
    Chacha,
    /// Só `TLS_AES_256_GCM_SHA384`.
    Aes256,
}

/// Como o servidor se comporta.
#[derive(Clone, Copy, Debug)]
pub struct Opts {
    /// Folha apresentada.
    pub leaf: Leaf,
    /// Só TLS 1.2 (o cliente do `tlsd` tem de recusar).
    pub tls12_only: bool,
    /// Oferece o grupo híbrido; sem ele só `x25519`.
    pub hybrid: bool,
    /// Suítes TLS 1.3.
    pub suites: Suites,
    /// Resposta OCSP a grampear.
    pub staple: Option<&'static [u8]>,
    /// Pede certificado ao cliente (o `tlsd` responde com um vazio).
    pub client_auth: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            leaf: Leaf::P256,
            tls12_only: false,
            hybrid: true,
            suites: Suites::Both,
            staple: None,
            client_auth: false,
        }
    }
}

/// Configuração do `rustls` para `o`.
///
/// # Panics
///
/// Se os certificados embutidos forem inválidos (erro de build).
#[must_use]
pub fn config(o: &Opts) -> Arc<ServerConfig> {
    let mut p = aws_lc_rs::default_provider();
    p.kx_groups.retain(|g| match g.name() {
        NamedGroup::X25519MLKEM768 => o.hybrid,
        NamedGroup::X25519 => true,
        _ => false,
    });
    p.cipher_suites.retain(|s| {
        let tls13 = matches!(
            s.suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384
                | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | CipherSuite::TLS13_AES_128_GCM_SHA256
        );
        if o.tls12_only {
            return !tls13;
        }
        match (s.suite(), o.suites) {
            (CipherSuite::TLS13_AES_256_GCM_SHA384, Suites::Both | Suites::Aes256)
            | (CipherSuite::TLS13_CHACHA20_POLY1305_SHA256, Suites::Both | Suites::Chacha) => true,
            _ => !tls13 && o.suites == Suites::Both,
        }
    });
    let versions: &[&rustls::SupportedProtocolVersion] = if o.tls12_only {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let builder = ServerConfig::builder_with_provider(Arc::new(p))
        .with_protocol_versions(versions)
        .expect("versões e suítes");
    let builder = if o.client_auth {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(CA.to_vec()))
            .expect("raiz de teste");
        let v = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(aws_lc_rs::default_provider()),
        )
        .build()
        .expect("verificador de cliente");
        builder.with_client_cert_verifier(v)
    } else {
        builder.with_no_client_auth()
    };
    let chain = vec![CertificateDer::from(o.leaf.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(o.leaf.key().to_vec()));
    let cfg = match o.staple {
        Some(s) => builder.with_single_cert_with_ocsp(chain, key, s.to_vec()),
        None => builder.with_single_cert(chain, key),
    };
    Arc::new(cfg.expect("certificado de teste"))
}

/// Atende uma conexão: lê o pedido, responde e fecha com `close_notify`.
///
/// # Errors
///
/// Erro de E/S ou de TLS da conexão (o handshake que o cliente recusou
/// aparece aqui; quem serve só registra).
pub fn handle(stream: TcpStream, cfg: Arc<ServerConfig>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let conn = ServerConnection::new(cfg).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, stream);
    let mut req = Vec::new();
    let mut buf = [0u8; 2048];
    while !req.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tls.read(&mut buf)?;
        if n == 0 || req.len() > 16 * 1024 {
            return Ok(());
        }
        req.extend_from_slice(&buf[..n]);
    }
    let path = std::str::from_utf8(&req)
        .ok()
        .and_then(|t| t.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    let kx = tls
        .conn
        .negotiated_key_exchange_group()
        .map_or_else(|| "?".to_owned(), |g| format!("{:?}", g.name()));
    let suite = tls
        .conn
        .negotiated_cipher_suite()
        .map_or_else(|| "?".to_owned(), |s| format!("{:?}", s.suite()));
    if path == "/rekey" {
        tls.conn.refresh_traffic_keys().map_err(io::Error::other)?;
    }
    let body: Vec<u8> = if path == "/big" {
        (0..1 << 20).map(|i: u32| (i % 251) as u8).collect()
    } else {
        format!("optimus tlshost ok\nkx={kx}\nsuite={suite}\n").into_bytes()
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(head.as_bytes())?;
    tls.write_all(&body)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

/// Um servidor rodando numa thread; para ao sair de escopo.
pub struct Server {
    /// Onde escuta (porta 0 pede uma livre).
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    /// Escuta em `addr` com `o`.
    ///
    /// # Errors
    ///
    /// Se não conseguir abrir a porta.
    pub fn start(addr: SocketAddr, o: &Opts) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let cfg = config(o);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        let cfg = Arc::clone(&cfg);
                        std::thread::spawn(move || {
                            let _ = conn.set_nonblocking(false);
                            let _ = handle(conn, cfg);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Ok(Self {
            addr,
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
