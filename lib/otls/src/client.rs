//! Cliente TLS 1.3 sem E/S (ADR 0070; T-653).
//!
//! Quem chama entrega registros inteiros ([`Client::read_record`]) e manda
//! adiante os bytes que o cliente escreve em `out`. O cliente oferece
//! `X25519MLKEM768` e, só se a política deixar, `x25519` puro (item 4); sem
//! PSK, 0-RTT nem `HelloRetryRequest`. Valida a cadeia com o `ox509` (ou só
//! a chave, no modo `pin`, item 7) e confere o `CertificateVerify` e o
//! `Finished`. Erro de decifração ou de assinatura não diz o motivo ao par
//! (item 11): o alerta é o genérico da RFC.

use core::ops::Range;

use alloc::boxed::Box;
use alloc::vec;
use optcrypt::mlkem768::{self, CT_LEN, DK_LEN};
use optcrypt::secret::Secret;
use optcrypt::x25519;
use ox509::ocsp::{self, OcspError};
use ox509::verify::{Anchors, ServerName, SignatureVerifier, key_fits, verify_server};
use ox509::{Certificate, Chain, Hash, PublicKey, SignatureAlgorithm};

use crate::msg::{self, Reader, Writer, group, kind, scheme};
use crate::record::{HEADER_LEN, MAX_PLAINTEXT, RecordKeys, content, parse_header};
use crate::schedule::{EarlySecret, HandshakeSecret, Traffic, Transcript};
use crate::{Error, Suite};

/// Maior mensagem de handshake aceita (a cadeia inteira vem numa só).
pub const MAX_HANDSHAKE: usize = 32 * 1024;
/// Maior `SubjectPublicKeyInfo` guardado da folha (RSA 4096 tem ~550).
const MAX_SPKI: usize = 1024;
/// Maior `ClientHello` (a partilha híbrida tem 1 216 bytes).
const MAX_CLIENT_HELLO: usize = 2048;
/// Maior nome de servidor (um nome DNS tem até 253 bytes).
pub const MAX_NAME: usize = 253;

/// O nome do servidor, por cópia.
#[derive(Clone, Copy)]
struct Name {
    buf: [u8; MAX_NAME],
    len: u8,
    dns: bool,
}

impl Name {
    /// Nome vazio e IP vazio, que nenhuma folha casa: o que sobra de um nome
    /// grande demais (a conexão falha na verificação).
    fn new(n: ServerName<'_>) -> Self {
        let mut s = Self {
            buf: [0; MAX_NAME],
            len: 0,
            dns: false,
        };
        let (bytes, dns) = match n {
            ServerName::Dns(d) => (d.as_bytes(), true),
            ServerName::Ip(i) => (i, false),
        };
        if let Some(dst) = s.buf.get_mut(..bytes.len()) {
            dst.copy_from_slice(bytes);
            s.len = u8::try_from(bytes.len()).unwrap_or(0);
            s.dns = dns;
        }
        s
    }

    fn get(&self) -> ServerName<'_> {
        let b = &self.buf[..usize::from(self.len)];
        if self.dns {
            ServerName::Dns(core::str::from_utf8(b).unwrap_or(""))
        } else {
            ServerName::Ip(b)
        }
    }
}

/// O que sobra da [`Config`] depois de copiar o nome.
struct Policy<'a> {
    anchors: Anchors<'a>,
    now: i64,
    allow_classic: bool,
    pin: Option<[u8; 32]>,
    ocsp: OcspPolicy,
}

/// O que fazer sem uma resposta OCSP boa (ADR 0071, item 6).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OcspPolicy {
    /// Aceita sem resposta, como os navegadores fazem com certificados sem
    /// `must-staple`; só a revogação provada recusa.
    #[default]
    Opportunistic,
    /// Exige uma resposta boa de toda folha.
    Require,
}

/// O que o OCSP grampeado disse desta conexão.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ocsp {
    /// Modo `pin`: não há cadeia, logo não há revogação a conferir.
    Skipped,
    /// O servidor não grampeou (aceito pela política).
    Absent,
    /// Havia resposta, mas não valeu (aceita pela política).
    Ignored(OcspError),
    /// Resposta válida: o certificado não está revogado.
    Good,
}

/// Política da conexão.
///
/// O cliente copia o nome (até [`MAX_NAME`] bytes): só `'a`, as âncoras,
/// vive o quanto a conexão, e o `tlsd` guarda a conexão sem guardar o
/// buffer de onde o nome veio.
#[derive(Clone, Copy)]
pub struct Config<'a, 'n> {
    /// Nome pedido; também vai no SNI quando é DNS.
    pub name: ServerName<'n>,
    /// Âncoras de confiança (`data/trust/roots.der`).
    pub anchors: Anchors<'a>,
    /// Hora de parede confiável do `timed`, segundos desde 1970.
    pub now: i64,
    /// Oferecer também `x25519` puro (queda visível, nunca padrão).
    pub allow_classic: bool,
    /// SHA-256 do SPKI do servidor: confere só a chave (modo `pin`).
    pub pin: Option<[u8; 32]>,
    /// Política do OCSP grampeado.
    pub ocsp: OcspPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Start,
    ServerHello,
    EncryptedExtensions,
    CertificateOrRequest,
    Certificate,
    CertificateVerify,
    Finished,
    Connected,
    Closed,
    Failed,
}

/// O que um registro lido produziu.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    /// Bytes escritos em `out` para mandar ao servidor.
    pub send: usize,
    /// Dados da aplicação, no próprio registro (`record[app]`).
    pub app: Range<usize>,
    /// O handshake acabou de terminar.
    pub connected: bool,
    /// O servidor fechou (`close_notify`).
    pub closed: bool,
}

/// Estado do handshake, separado do buffer de remontagem para que uma
/// mensagem do buffer seja lida enquanto o estado muda.
struct Inner<'a, V> {
    cfg: Policy<'a>,
    name: Name,
    verifier: V,
    state: State,
    session_id: [u8; 32],
    hello: [u8; MAX_CLIENT_HELLO],
    hello_len: usize,
    suites: [Suite; 2],
    n_suites: usize,
    mlkem_dk: Secret<DK_LEN>,
    x25519_sk: Secret<32>,
    suite: Option<Suite>,
    transcript: Option<Transcript>,
    hs: Option<HandshakeSecret>,
    c_traffic: Option<Traffic>,
    s_traffic: Option<Traffic>,
    read: Option<RecordKeys>,
    write: Option<RecordKeys>,
    cert_request: Option<([u8; 255], usize)>,
    spki: [u8; MAX_SPKI],
    spki_len: usize,
    ocsp: Option<Ocsp>,
}

/// Cliente TLS 1.3.
pub struct Client<'a, V> {
    inner: Inner<'a, V>,
    /// Remontagem das mensagens de handshake, na heap: o cliente fica
    /// pequeno para mudar de lugar na pilha curta de um processo.
    buf: Box<[u8]>,
    len: usize,
}

impl<'a, V: SignatureVerifier> Client<'a, V> {
    /// Cliente novo; `rng` enche buffers com bytes do `keyd`.
    ///
    /// O buffer de remontagem (32 KiB, cabe uma cadeia inteira) vai para a
    /// heap; o resto do cliente tem uns 8 KiB.
    pub fn new(cfg: Config<'a, '_>, verifier: V, rng: &mut impl FnMut(&mut [u8])) -> Self {
        let mut seed = Secret::<64>::zeroed();
        rng(seed.expose_mut());
        let (ek, mlkem_dk) = mlkem768::keygen(&seed);
        let mut x25519_sk = Secret::<32>::zeroed();
        rng(x25519_sk.expose_mut());
        let mut random = [0u8; 32];
        let mut session_id = [0u8; 32];
        rng(&mut random);
        rng(&mut session_id);
        let mut suites = [Suite::Chacha20Poly1305Sha256; 2];
        let mut n = 0;
        for s in [Suite::Aes256GcmSha384, Suite::Chacha20Poly1305Sha256] {
            if s.available() {
                suites[n] = s;
                n += 1;
            }
        }
        let name = Name::new(cfg.name);
        let mut inner = Inner {
            cfg: Policy {
                anchors: cfg.anchors,
                now: cfg.now,
                allow_classic: cfg.allow_classic,
                pin: cfg.pin,
                ocsp: cfg.ocsp,
            },
            name,
            verifier,
            state: State::Start,
            session_id,
            hello: [0; MAX_CLIENT_HELLO],
            hello_len: 0,
            suites,
            n_suites: n,
            mlkem_dk,
            x25519_sk,
            suite: None,
            transcript: None,
            hs: None,
            c_traffic: None,
            s_traffic: None,
            read: None,
            write: None,
            cert_request: None,
            spki: [0; MAX_SPKI],
            spki_len: 0,
            ocsp: None,
        };
        inner.hello_len = inner.build_hello(&random, &ek).unwrap_or(0);
        Self {
            inner,
            buf: vec![0; MAX_HANDSHAKE].into_boxed_slice(),
            len: 0,
        }
    }

    /// Escreve o registro do `ClientHello` em `out`.
    ///
    /// # Errors
    ///
    /// `UnexpectedMessage` fora do início; `Internal` se `out` não couber.
    pub fn start(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let i = &mut self.inner;
        if i.state != State::Start || i.hello_len == 0 {
            return Err(Error::UnexpectedMessage);
        }
        i.state = State::ServerHello;
        // Versão legada 0x0301 no primeiro registro (seção 5.1).
        plain_record(out, content::HANDSHAKE, 0x0301, &i.hello[..i.hello_len])
    }

    /// Lê um registro inteiro (`record` tem cabeçalho e conteúdo) e escreve
    /// em `out` o que precisa ser mandado de volta.
    ///
    /// # Errors
    ///
    /// Qualquer [`Error`]: a conexão fica perdida; mande [`Client::alert`].
    pub fn read_record(&mut self, record: &mut [u8], out: &mut [u8]) -> Result<Event, Error> {
        let r = self.read_inner(record, out);
        if r.is_err() {
            self.inner.state = State::Failed;
        }
        r
    }

    fn read_inner(&mut self, record: &mut [u8], out: &mut [u8]) -> Result<Event, Error> {
        let header: &[u8; HEADER_LEN] = record.first_chunk().ok_or(Error::Decode)?;
        let (outer, len) = parse_header(header).map_err(Error::from)?;
        if record.len() != HEADER_LEN + len {
            return Err(Error::Decode);
        }
        let state = self.inner.state;
        if matches!(state, State::Start | State::Closed | State::Failed) {
            return Err(Error::UnexpectedMessage);
        }
        let mut ev = Event::default();
        match outer {
            // `change_cipher_spec` de compatibilidade: só durante o handshake.
            content::CHANGE_CIPHER_SPEC => {
                if record[HEADER_LEN..] != [1]
                    || matches!(state, State::ServerHello | State::Connected)
                {
                    return Err(Error::UnexpectedMessage);
                }
                return Ok(ev);
            }
            content::HANDSHAKE | content::ALERT if self.inner.read.is_none() => {
                if outer == content::ALERT {
                    return Err(alert(&record[HEADER_LEN..]));
                }
                self.push(HEADER_LEN..record.len(), record)?;
            }
            content::APPLICATION_DATA => {
                let keys = self.inner.read.as_mut().ok_or(Error::UnexpectedMessage)?;
                let (inner, pt) = keys.open(record).map_err(Error::from)?;
                let range = HEADER_LEN..HEADER_LEN + pt.len();
                match inner {
                    content::HANDSHAKE if !pt.is_empty() => self.push(range, record)?,
                    content::ALERT => {
                        if record[range.clone()] == [1, 0] {
                            self.inner.state = State::Closed;
                            ev.closed = true;
                            return Ok(ev);
                        }
                        return Err(alert(&record[range]));
                    }
                    content::APPLICATION_DATA if state == State::Connected => {
                        ev.app = range;
                        return Ok(ev);
                    }
                    _ => return Err(Error::UnexpectedMessage),
                }
            }
            _ => return Err(Error::UnexpectedMessage),
        }
        // Processa as mensagens completas do buffer.
        let mut at = 0;
        while self.len - at >= 4 {
            let n = 4
                + (usize::from(self.buf[at + 1]) << 16
                    | usize::from(self.buf[at + 2]) << 8
                    | usize::from(self.buf[at + 3]));
            if self.len - at < n {
                break;
            }
            let msg = &self.buf[at..at + n];
            at += n;
            let key_change = self.inner.handle(msg, out, &mut ev)?;
            // Mensagem que troca a chave tem de fechar o registro (5.1).
            if key_change && at != self.len {
                return Err(Error::UnexpectedMessage);
            }
        }
        self.buf.copy_within(at..self.len, 0);
        self.len -= at;
        Ok(ev)
    }

    fn push(&mut self, range: Range<usize>, record: &[u8]) -> Result<(), Error> {
        let data = &record[range];
        let dst = self
            .buf
            .get_mut(self.len..self.len + data.len())
            .ok_or(Error::TooLarge)?;
        dst.copy_from_slice(data);
        self.len += data.len();
        Ok(())
    }

    /// Cifra `data` (até [`MAX_PLAINTEXT`] por registro) em `out`.
    ///
    /// # Errors
    ///
    /// `UnexpectedMessage` antes do handshake; erro do registro.
    pub fn write_app(&mut self, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if self.inner.state != State::Connected {
            return Err(Error::UnexpectedMessage);
        }
        let mut n = 0;
        for chunk in data.chunks(MAX_PLAINTEXT) {
            n += self
                .inner
                .seal(content::APPLICATION_DATA, chunk, &mut out[n..])?;
        }
        Ok(n)
    }

    /// `close_notify` em `out`.
    ///
    /// # Errors
    ///
    /// Erro do registro.
    pub fn close(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.inner.alert_record(1, 0, out)?;
        self.inner.state = State::Closed;
        Ok(n)
    }

    /// Alerta fatal de `e` em `out` (zero bytes se o erro veio do par).
    pub fn alert(&mut self, e: Error, out: &mut [u8]) -> usize {
        self.inner.state = State::Failed;
        match e.alert() {
            Some(d) => self.inner.alert_record(2, d, out).unwrap_or(0),
            None => 0,
        }
    }

    /// O handshake terminou.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.inner.state == State::Connected
    }

    /// Suíte negociada.
    #[must_use]
    pub fn suite(&self) -> Option<Suite> {
        self.inner.suite
    }

    /// O que o OCSP grampeado disse; `None` até o `Certificate` chegar.
    #[must_use]
    pub fn ocsp(&self) -> Option<Ocsp> {
        self.inner.ocsp
    }
}

impl<V: SignatureVerifier> Inner<'_, V> {
    fn build_hello(
        &mut self,
        random: &[u8; 32],
        ek: &[u8; mlkem768::EK_LEN],
    ) -> Result<usize, Error> {
        let xpub = x25519::public_key(&self.x25519_sk);
        let mut hybrid = [0u8; mlkem768::EK_LEN + 32];
        hybrid[..mlkem768::EK_LEN].copy_from_slice(ek);
        hybrid[mlkem768::EK_LEN..].copy_from_slice(&xpub);
        let shares_all = [
            (group::X25519_MLKEM768, &hybrid[..]),
            (group::X25519, &xpub[..]),
        ];
        let shares = if self.cfg.allow_classic {
            &shares_all[..]
        } else {
            &shares_all[..1]
        };
        let mut ids = [0u16; 2];
        for (d, s) in ids.iter_mut().zip(&self.suites[..self.n_suites]) {
            *d = s.id();
        }
        let ch = msg::ClientHello {
            random,
            session_id: &self.session_id,
            suites: &ids[..self.n_suites],
            server_name: match self.name.get() {
                ServerName::Dns(d) => Some(d),
                ServerName::Ip(_) => None,
            },
            shares,
        };
        let mut w = Writer::new(&mut self.hello);
        ch.write(&mut w)?;
        Ok(w.len())
    }

    /// Uma mensagem inteira (com cabeçalho). Devolve `true` se ela troca a
    /// chave de leitura.
    fn handle(&mut self, m: &[u8], out: &mut [u8], ev: &mut Event) -> Result<bool, Error> {
        let (k, body) = (m[0], &m[4..]);
        match (self.state, k) {
            (State::ServerHello, kind::SERVER_HELLO) => {
                self.server_hello(m, body)?;
                Ok(true)
            }
            (State::EncryptedExtensions, kind::ENCRYPTED_EXTENSIONS) => {
                msg::encrypted_extensions(body)?;
                self.add(m);
                self.state = State::CertificateOrRequest;
                Ok(false)
            }
            (State::CertificateOrRequest, kind::CERTIFICATE_REQUEST) => {
                let mut r = Reader::new(body);
                let ctx = r.vec(1)?;
                r.vec(2)?;
                r.finish()?;
                let mut c = [0u8; 255];
                c[..ctx.len()].copy_from_slice(ctx);
                self.cert_request = Some((c, ctx.len()));
                self.add(m);
                self.state = State::Certificate;
                Ok(false)
            }
            (State::CertificateOrRequest | State::Certificate, kind::CERTIFICATE) => {
                self.certificate(body)?;
                self.add(m);
                self.state = State::CertificateVerify;
                Ok(false)
            }
            (State::CertificateVerify, kind::CERTIFICATE_VERIFY) => {
                self.certificate_verify(body)?;
                self.add(m);
                self.state = State::Finished;
                Ok(false)
            }
            (State::Finished, kind::FINISHED) => {
                self.finished(m, body, out, ev)?;
                Ok(true)
            }
            (State::Connected, kind::NEW_SESSION_TICKET) => Ok(false),
            (State::Connected, kind::KEY_UPDATE) => {
                self.key_update(body, out, ev)?;
                Ok(true)
            }
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn add(&mut self, m: &[u8]) {
        if let Some(t) = self.transcript.as_mut() {
            t.update(m);
        }
    }

    // Nomes curtos à moda da RFC (c/s = cliente/servidor, t = transcrição).
    #[allow(clippy::many_single_char_names)]
    fn server_hello(&mut self, m: &[u8], body: &[u8]) -> Result<(), Error> {
        let sh = msg::ServerHello::parse(body)?;
        if sh.version.is_none() || sh.downgrade {
            return Err(Error::Tls12Only);
        }
        if sh.version != Some(0x0304) || sh.session_id != self.session_id {
            return Err(Error::IllegalParameter);
        }
        // Só ofertamos grupos que já mandamos: um HRR não tem saída.
        if sh.retry {
            return Err(Error::HandshakeFailure);
        }
        let suite = Suite::from_id(sh.suite)
            .filter(|s| self.suites[..self.n_suites].contains(s))
            .ok_or(Error::IllegalParameter)?;
        let (g, share) = sh.share.ok_or(Error::MissingExtension)?;
        let mut shared = [0u8; 64];
        let n = match g {
            group::X25519_MLKEM768 => {
                let ct: &[u8; CT_LEN] = share
                    .get(..CT_LEN)
                    .and_then(|c| c.try_into().ok())
                    .ok_or(Error::IllegalParameter)?;
                let x = &share[CT_LEN..];
                let ss = mlkem768::decaps(&self.mlkem_dk, ct).map_err(|_| Error::Internal)?;
                let xs = self.dh(x)?;
                shared[..32].copy_from_slice(ss.expose());
                shared[32..].copy_from_slice(xs.expose());
                64
            }
            group::X25519 if self.cfg.allow_classic => {
                let xs = self.dh(share)?;
                shared[..32].copy_from_slice(xs.expose());
                32
            }
            _ => return Err(Error::IllegalParameter),
        };
        // As chaves efêmeras não servem para mais nada.
        self.mlkem_dk = Secret::zeroed();
        self.x25519_sk = Secret::zeroed();
        let mut t = Transcript::new(suite);
        t.update(&self.hello[..self.hello_len]);
        t.update(m);
        let (hs, c, s) = EarlySecret::new(suite).handshake(&shared[..n], &t.current());
        optcrypt::secret::wipe(&mut shared);
        self.read = Some(s.record_keys().ok_or(Error::Internal)?);
        self.write = Some(c.record_keys().ok_or(Error::Internal)?);
        self.hs = Some(hs);
        self.c_traffic = Some(c);
        self.s_traffic = Some(s);
        self.transcript = Some(t);
        self.suite = Some(suite);
        self.state = State::EncryptedExtensions;
        Ok(())
    }

    fn dh(&self, peer: &[u8]) -> Result<Secret<32>, Error> {
        let peer: &[u8; 32] = peer.try_into().map_err(|_| Error::IllegalParameter)?;
        x25519::diffie_hellman(&self.x25519_sk, peer).map_err(|_| Error::IllegalParameter)
    }

    fn certificate(&mut self, body: &[u8]) -> Result<(), Error> {
        let (list, n) = msg::certificate(body)?;
        let staple = msg::certificate_staple(body)?;
        let chain = Chain::parse(list[..n].iter().copied()).map_err(|_| Error::BadCertificate)?;
        let leaf = chain.leaf();
        if let Some(pin) = self.cfg.pin {
            if !optcrypt::secret::ct_eq(&optcrypt::sha256::hash(leaf.spki), &pin) {
                return Err(Error::BadCertificate);
            }
            self.ocsp = Some(Ocsp::Skipped);
        } else {
            let anchor = verify_server(
                &chain,
                &self.cfg.anchors,
                self.name.get(),
                self.cfg.now,
                &self.verifier,
            )
            .map_err(Error::Certificate)?;
            self.ocsp = Some(self.revocation(&chain, &anchor, staple)?);
        }
        let spki = self
            .spki
            .get_mut(..leaf.spki.len())
            .ok_or(Error::UnsupportedCertificate)?;
        spki.copy_from_slice(leaf.spki);
        self.spki_len = leaf.spki.len();
        Ok(())
    }

    /// Revogação pelo OCSP grampeado (ADR 0071, item 6): só a revogação
    /// provada recusa, a menos que a política ou o `must-staple` exijam uma
    /// resposta boa.
    fn revocation(
        &self,
        chain: &Chain<'_>,
        anchor: &Certificate<'_>,
        staple: Option<&[u8]>,
    ) -> Result<Ocsp, Error> {
        let leaf = chain.leaf();
        let required = self.cfg.ocsp == OcspPolicy::Require || leaf.extensions.must_staple;
        let Some(resp) = staple else {
            return if required {
                Err(Error::StapleRequired)
            } else {
                Ok(Ocsp::Absent)
            };
        };
        // O emissor da folha é quem a assinou: uma intermediária entregue
        // ou a âncora do caminho. O `verify_server` já provou que existe.
        let issuer = chain
            .iter()
            .skip(1)
            .chain(core::iter::once(anchor))
            .find(|c| {
                c.subject == leaf.issuer
                    && key_fits(leaf.signature_algorithm, &c.public_key)
                    && self.verifier.verify(
                        leaf.signature_algorithm,
                        &c.public_key,
                        leaf.tbs,
                        leaf.signature,
                    )
            });
        let result = match issuer {
            Some(i) => ocsp::validate(resp, leaf, i, self.cfg.now, &self.verifier),
            None => Err(OcspError::UnauthorizedSigner),
        };
        match result {
            Ok(ocsp::Status::Good) => Ok(Ocsp::Good),
            Ok(ocsp::Status::Revoked { .. }) => Err(Error::Revoked),
            Ok(ocsp::Status::Unknown) => Self::useless(OcspError::UnknownCertificate, required),
            Err(e) => Self::useless(e, required),
        }
    }

    /// Resposta que não vale: erro se a política exige uma boa; senão é como
    /// se o servidor não a tivesse mandado (um atacante no caminho poderia
    /// simplesmente tirá-la).
    fn useless(e: OcspError, required: bool) -> Result<Ocsp, Error> {
        if required {
            Err(Error::Ocsp(e))
        } else {
            Ok(Ocsp::Ignored(e))
        }
    }

    fn certificate_verify(&mut self, body: &[u8]) -> Result<(), Error> {
        let (s, sig) = msg::certificate_verify(body)?;
        let alg = match s {
            scheme::ECDSA_P256_SHA256 => SignatureAlgorithm::Ecdsa(Hash::Sha256),
            scheme::RSA_PSS_SHA256 => SignatureAlgorithm::RsaPss(Hash::Sha256),
            scheme::RSA_PSS_SHA384 => SignatureAlgorithm::RsaPss(Hash::Sha384),
            scheme::ED25519 => SignatureAlgorithm::Ed25519,
            _ => return Err(Error::IllegalParameter),
        };
        let key =
            PublicKey::from_spki(&self.spki[..self.spki_len]).map_err(|_| Error::BadCertificate)?;
        if !key_fits(alg, &key) {
            return Err(Error::IllegalParameter);
        }
        let hash = self.transcript.as_ref().ok_or(Error::Internal)?.current();
        let mut buf = [0u8; 64 + 34 + 48];
        let input = msg::verify_input(hash.as_bytes(), &mut buf);
        if self.verifier.verify(alg, &key, input, sig) {
            Ok(())
        } else {
            Err(Error::DecryptError)
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn finished(
        &mut self,
        m: &[u8],
        body: &[u8],
        out: &mut [u8],
        ev: &mut Event,
    ) -> Result<(), Error> {
        let mut t = self.transcript.take().ok_or(Error::Internal)?;
        let s = self.s_traffic.take().ok_or(Error::Internal)?;
        if !s.verify_finished(&t.current(), body) {
            return Err(Error::DecryptError);
        }
        t.update(m);
        let hs = self.hs.take().ok_or(Error::Internal)?;
        let (_master, c_ap, s_ap) = hs.application(&t.current());
        // Voo do cliente: CCS de compatibilidade e, com a chave de handshake
        // do cliente, `Certificate` vazio (se pedido) e `Finished`.
        let mut n = plain_record(out, content::CHANGE_CIPHER_SPEC, 0x0303, &[1])?;
        let mut flight = [0u8; 4 + 1 + 255 + 3 + 4 + 48];
        let mut cert_len = 0;
        if let Some((ctx, len)) = self.cert_request {
            let mut w = Writer::new(&mut flight);
            w.put(&[kind::CERTIFICATE])?;
            let b = w.open(3)?;
            w.uint(1, len)?;
            w.put(&ctx[..len])?;
            w.uint(3, 0)?;
            w.close(b)?;
            cert_len = w.len();
            t.update(&flight[..cert_len]);
        }
        let c = self.c_traffic.take().ok_or(Error::Internal)?;
        let fin = c.finished(&t.current());
        let fin = fin.as_bytes();
        let end = cert_len + 4 + fin.len();
        flight[cert_len..cert_len + 4].copy_from_slice(&[
            kind::FINISHED,
            0,
            0,
            u8::try_from(fin.len()).unwrap_or(0),
        ]);
        flight[cert_len + 4..end].copy_from_slice(fin);
        n += self.seal(content::HANDSHAKE, &flight[..end], &mut out[n..])?;
        self.read = Some(s_ap.record_keys().ok_or(Error::Internal)?);
        self.write = Some(c_ap.record_keys().ok_or(Error::Internal)?);
        self.c_traffic = Some(c_ap);
        self.s_traffic = Some(s_ap);
        self.state = State::Connected;
        ev.send += n;
        ev.connected = true;
        Ok(())
    }

    fn key_update(&mut self, body: &[u8], out: &mut [u8], ev: &mut Event) -> Result<(), Error> {
        let request = match body {
            [0] => false,
            [1] => true,
            _ => return Err(Error::IllegalParameter),
        };
        let s = self.s_traffic.take().ok_or(Error::Internal)?.update();
        self.read = Some(s.record_keys().ok_or(Error::Internal)?);
        self.s_traffic = Some(s);
        if request {
            let n = self.seal(
                content::HANDSHAKE,
                &[kind::KEY_UPDATE, 0, 0, 1, 0],
                &mut out[ev.send..],
            )?;
            ev.send += n;
            let c = self.c_traffic.take().ok_or(Error::Internal)?.update();
            self.write = Some(c.record_keys().ok_or(Error::Internal)?);
            self.c_traffic = Some(c);
        }
        Ok(())
    }

    fn seal(&mut self, kind: u8, data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let keys = self.write.as_mut().ok_or(Error::Internal)?;
        out.get_mut(HEADER_LEN..HEADER_LEN + data.len())
            .ok_or(Error::Internal)?
            .copy_from_slice(data);
        keys.seal(kind, out, data.len()).map_err(Error::from)
    }

    fn alert_record(&mut self, level: u8, desc: u8, out: &mut [u8]) -> Result<usize, Error> {
        if self.write.is_some() {
            self.seal(content::ALERT, &[level, desc], out)
        } else {
            plain_record(out, content::ALERT, 0x0303, &[level, desc])
        }
    }
}

/// Registro em claro.
fn plain_record(out: &mut [u8], kind: u8, version: u16, data: &[u8]) -> Result<usize, Error> {
    let n = HEADER_LEN + data.len();
    let dst = out.get_mut(..n).ok_or(Error::Internal)?;
    dst[0] = kind;
    dst[1..3].copy_from_slice(&version.to_be_bytes());
    dst[3..5].copy_from_slice(
        &u16::try_from(data.len())
            .map_err(|_| Error::Internal)?
            .to_be_bytes(),
    );
    dst[HEADER_LEN..].copy_from_slice(data);
    Ok(n)
}

/// Alerta recebido.
fn alert(body: &[u8]) -> Error {
    match body {
        [_, d] => Error::PeerAlert(*d),
        _ => Error::Decode,
    }
}
