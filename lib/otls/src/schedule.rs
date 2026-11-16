//! Agenda de chaves do TLS 1.3 (RFC 8446, seção 7.1), sem PSK.
//!
//! Os estágios são tipos: [`EarlySecret`] → [`HandshakeSecret`] →
//! [`MasterSecret`], cada um consumindo o anterior, então não há como
//! derivar fora de ordem nem reaproveitar um segredo velho. Todo segredo
//! vive num `Secret` do `optcrypt` (zerado ao sair de escopo, sem `Debug`).

use optcrypt::hkdf;
use optcrypt::hmac::{HmacSha256, HmacSha384};
use optcrypt::secret::{Secret, ct_eq};
use optcrypt::sha256::Sha256;
use optcrypt::sha512::Sha384;

use crate::Suite;
use crate::record::RecordKeys;

/// Maior saída de hash (SHA-384).
pub const MAX_HASH: usize = 48;

/// Saída de hash de tamanho variável (32 ou 48 bytes). Não é segredo.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Digest {
    buf: [u8; MAX_HASH],
    len: usize,
}

impl Digest {
    /// Os bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    fn from(b: &[u8]) -> Self {
        let mut buf = [0; MAX_HASH];
        buf[..b.len()].copy_from_slice(b);
        Self { buf, len: b.len() }
    }
}

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Hash da transcrição do handshake, com o hash da suíte.
#[derive(Clone)]
pub enum Transcript {
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    Sha256(Sha256),
    /// `TLS_AES_256_GCM_SHA384`.
    Sha384(Sha384),
}

impl Transcript {
    /// Transcrição vazia.
    #[must_use]
    pub fn new(suite: Suite) -> Self {
        match suite {
            Suite::Chacha20Poly1305Sha256 => Self::Sha256(Sha256::new()),
            Suite::Aes256GcmSha384 => Self::Sha384(Sha384::new()),
        }
    }

    /// Acrescenta uma mensagem de handshake inteira (com o cabeçalho).
    pub fn update(&mut self, msg: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(msg),
            Self::Sha384(h) => h.update(msg),
        }
    }

    /// Hash até aqui, sem fechar a transcrição.
    #[must_use]
    pub fn current(&self) -> Digest {
        match self.clone() {
            Self::Sha256(h) => Digest::from(&h.finalize()),
            Self::Sha384(h) => Digest::from(&h.finalize()),
        }
    }
}

/// Segredo de 32 ou 48 bytes da suíte.
struct Prk {
    bytes: Secret<MAX_HASH>,
    suite: Suite,
}

impl Prk {
    fn len(&self) -> usize {
        self.suite.hash_len()
    }

    fn expose(&self) -> &[u8] {
        &self.bytes.expose()[..self.len()]
    }

    /// HKDF-Extract(`salt`, `ikm`); `salt` vazio vale zeros.
    fn extract(suite: Suite, salt: &[u8], ikm: &[u8]) -> Self {
        let mut bytes = Secret::<MAX_HASH>::zeroed();
        match suite {
            Suite::Chacha20Poly1305Sha256 => {
                let p = hkdf::sha256::extract(salt, ikm);
                bytes.expose_mut()[..32].copy_from_slice(p.expose());
            }
            Suite::Aes256GcmSha384 => {
                let p = hkdf::sha384::extract(salt, ikm);
                bytes.expose_mut().copy_from_slice(p.expose());
            }
        }
        Self { bytes, suite }
    }

    /// HKDF-Expand-Label(`self`, `label`, `context`, `out.len()`).
    fn expand_label(&self, label: &[u8], context: &[u8], out: &mut [u8]) {
        // HkdfLabel: u16 tamanho, opaque label<7..255> ("tls13 " + rótulo),
        // opaque context<0..255>. Rótulos e contextos daqui são curtos.
        let mut info = [0u8; 2 + 1 + 6 + 32 + 1 + MAX_HASH];
        let n = 2 + 1 + 6 + label.len();
        assert!(label.len() <= 32 && context.len() <= MAX_HASH && out.len() <= 255);
        info[..2].copy_from_slice(&u16::try_from(out.len()).unwrap_or(0).to_be_bytes());
        info[2] = u8::try_from(6 + label.len()).unwrap_or(0);
        info[3..9].copy_from_slice(b"tls13 ");
        info[9..n].copy_from_slice(label);
        info[n] = u8::try_from(context.len()).unwrap_or(0);
        info[n + 1..n + 1 + context.len()].copy_from_slice(context);
        let info = &info[..n + 1 + context.len()];
        // `out` tem no máximo 255 bytes: `expand` não falha.
        let r = match self.suite {
            Suite::Chacha20Poly1305Sha256 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(self.expose());
                hkdf::sha256::expand(&Secret::take(&mut k), info, out)
            }
            Suite::Aes256GcmSha384 => {
                let mut k = [0u8; 48];
                k.copy_from_slice(self.expose());
                hkdf::sha384::expand(&Secret::take(&mut k), info, out)
            }
        };
        debug_assert!(r.is_ok());
    }

    /// Derive-Secret(`self`, `label`, transcrição) com o hash já calculado.
    fn derive(&self, label: &[u8], hash: &Digest) -> Self {
        let mut out = Secret::<MAX_HASH>::zeroed();
        self.expand_label(label, hash.as_bytes(), &mut out.expose_mut()[..self.len()]);
        Self {
            bytes: out,
            suite: self.suite,
        }
    }

    /// `Derive-Secret(., "derived", "")`: o sal do próximo Extract.
    fn derived_salt(&self) -> Self {
        let empty = Transcript::new(self.suite).current();
        self.derive(b"derived", &empty)
    }
}

/// Segredo inicial, sem PSK: HKDF-Extract(0, 0).
pub struct EarlySecret(Prk);

impl EarlySecret {
    /// Primeiro estágio para `suite`.
    #[must_use]
    pub fn new(suite: Suite) -> Self {
        let zeros = [0u8; MAX_HASH];
        Self(Prk::extract(suite, &[], &zeros[..suite.hash_len()]))
    }

    /// Mistura o segredo do (EC)DHE e deriva os segredos de tráfego do
    /// handshake; `hello_hash` é o hash de ClientHello..ServerHello.
    #[must_use]
    pub fn handshake(
        self,
        shared: &[u8],
        hello_hash: &Digest,
    ) -> (HandshakeSecret, Traffic, Traffic) {
        let salt = self.0.derived_salt();
        let hs = Prk::extract(self.0.suite, salt.expose(), shared);
        let c = Traffic(hs.derive(b"c hs traffic", hello_hash));
        let s = Traffic(hs.derive(b"s hs traffic", hello_hash));
        (HandshakeSecret(hs), c, s)
    }
}

/// Segredo do handshake.
pub struct HandshakeSecret(Prk);

impl HandshakeSecret {
    /// Deriva o segredo mestre e os segredos de tráfego da aplicação;
    /// `finished_hash` é o hash de ClientHello..Finished do servidor.
    #[must_use]
    pub fn application(self, finished_hash: &Digest) -> (MasterSecret, Traffic, Traffic) {
        let suite = self.0.suite;
        let salt = self.0.derived_salt();
        let zeros = [0u8; MAX_HASH];
        let ms = Prk::extract(suite, salt.expose(), &zeros[..suite.hash_len()]);
        let c = Traffic(ms.derive(b"c ap traffic", finished_hash));
        let s = Traffic(ms.derive(b"s ap traffic", finished_hash));
        (MasterSecret(ms), c, s)
    }
}

/// Segredo mestre. Sem retomada nem exportador no M6 (ADR 0070, item 5):
/// existe só para fechar a agenda e ser zerado.
pub struct MasterSecret(#[allow(dead_code)] Prk);

/// Segredo de tráfego de um sentido.
pub struct Traffic(Prk);

impl Traffic {
    /// Suíte do segredo.
    #[must_use]
    pub fn suite(&self) -> Suite {
        self.0.suite
    }

    /// Chave e IV do registro: `Expand-Label(., "key"|"iv", "", n)`.
    #[must_use]
    pub fn record_keys(&self) -> Option<RecordKeys> {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        self.0.expand_label(b"key", &[], &mut key);
        self.0.expand_label(b"iv", &[], &mut iv);
        RecordKeys::new(self.0.suite, &mut key, iv)
    }

    /// `verify_data` do Finished (seção 4.4.4) sobre `hash`.
    #[must_use]
    pub fn finished(&self, hash: &Digest) -> Digest {
        let mut fk = Secret::<MAX_HASH>::zeroed();
        let n = self.0.len();
        self.0
            .expand_label(b"finished", &[], &mut fk.expose_mut()[..n]);
        let key = &fk.expose()[..n];
        match self.0.suite {
            Suite::Chacha20Poly1305Sha256 => {
                let mut h = HmacSha256::new(key);
                h.update(hash.as_bytes());
                Digest::from(&h.finalize())
            }
            Suite::Aes256GcmSha384 => {
                let mut h = HmacSha384::new(key);
                h.update(hash.as_bytes());
                Digest::from(&h.finalize())
            }
        }
    }

    /// Confere o Finished recebido em tempo constante.
    #[must_use]
    pub fn verify_finished(&self, hash: &Digest, received: &[u8]) -> bool {
        ct_eq(self.finished(hash).as_bytes(), received)
    }

    /// Próximo segredo após `KeyUpdate` (seção 7.2).
    #[must_use]
    pub fn update(&self) -> Self {
        let mut out = Secret::<MAX_HASH>::zeroed();
        let n = self.0.len();
        self.0
            .expand_label(b"traffic upd", &[], &mut out.expose_mut()[..n]);
        Self(Prk {
            bytes: out,
            suite: self.0.suite,
        })
    }

    #[cfg(test)]
    pub(crate) fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    #[cfg(test)]
    pub(crate) fn expand(&self, label: &[u8], out: &mut [u8]) {
        self.0.expand_label(label, &[], out);
    }
}

#[cfg(test)]
pub(crate) fn test_digest(b: &[u8]) -> Digest {
    Digest::from(b)
}

#[cfg(test)]
pub(crate) fn early_expose(e: &EarlySecret) -> &[u8] {
    e.0.expose()
}

#[cfg(test)]
pub(crate) fn hs_expose(e: &HandshakeSecret) -> &[u8] {
    e.0.expose()
}

#[cfg(test)]
pub(crate) fn ms_expose(e: &MasterSecret) -> &[u8] {
    e.0.expose()
}
