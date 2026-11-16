//! Mensagens de handshake do TLS 1.3 que o cliente escreve e lê (RFC 8446,
//! seção 4), sem alocar. A leitura é estrita: tamanhos conferidos, sem byte
//! sobrando, extensão repetida ou desconhecida onde a RFC não deixa.

use crate::Error;

/// Tipos de mensagem de handshake.
pub mod kind {
    /// `client_hello`.
    pub const CLIENT_HELLO: u8 = 1;
    /// `server_hello` (e `HelloRetryRequest`).
    pub const SERVER_HELLO: u8 = 2;
    /// `new_session_ticket`.
    pub const NEW_SESSION_TICKET: u8 = 4;
    /// `encrypted_extensions`.
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    /// `certificate`.
    pub const CERTIFICATE: u8 = 11;
    /// `certificate_request`.
    pub const CERTIFICATE_REQUEST: u8 = 13;
    /// `certificate_verify`.
    pub const CERTIFICATE_VERIFY: u8 = 15;
    /// `finished`.
    pub const FINISHED: u8 = 20;
    /// `key_update`.
    pub const KEY_UPDATE: u8 = 24;
}

/// Extensões usadas.
pub mod ext {
    /// `server_name`.
    pub const SERVER_NAME: u16 = 0;
    /// `supported_groups`.
    pub const SUPPORTED_GROUPS: u16 = 10;
    /// `signature_algorithms`.
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    /// `supported_versions`.
    pub const SUPPORTED_VERSIONS: u16 = 43;
    /// `signature_algorithms_cert`.
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = 50;
    /// `key_share`.
    pub const KEY_SHARE: u16 = 51;
}

/// Grupos de troca de chaves (ADR 0070, item 4).
pub mod group {
    /// `X25519MLKEM768` (draft-ietf-tls-ecdhe-mlkem): ML-KEM-768 e X25519.
    pub const X25519_MLKEM768: u16 = 0x11EC;
    /// `x25519`, só se a política do cliente deixar.
    pub const X25519: u16 = 0x001D;
}

/// Esquemas de assinatura do `CertificateVerify` (ADR 0071, item 1).
pub mod scheme {
    /// `ecdsa_secp256r1_sha256`.
    pub const ECDSA_P256_SHA256: u16 = 0x0403;
    /// `rsa_pss_rsae_sha256`.
    pub const RSA_PSS_SHA256: u16 = 0x0804;
    /// `rsa_pss_rsae_sha384`.
    pub const RSA_PSS_SHA384: u16 = 0x0805;
    /// `ed25519`.
    pub const ED25519: u16 = 0x0807;
    /// Aceitos no `CertificateVerify`.
    pub const VERIFY: [u16; 4] = [ECDSA_P256_SHA256, RSA_PSS_SHA256, RSA_PSS_SHA384, ED25519];
    /// Aceitos nos certificados (`signature_algorithms_cert`): os de cima,
    /// ECDSA P-256 com SHA-384, PSS com SHA-512 e PKCS#1 v1.5.
    pub const CERT: [u16; 9] = [
        ECDSA_P256_SHA256,
        0x0503,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        0x0806,
        0x0401,
        0x0501,
        0x0601,
        ED25519,
    ];
}

/// `random` do `HelloRetryRequest` (seção 4.1.3).
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Cursor de leitura com tamanhos de 1, 2 e 3 bytes.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Cursor sobre `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// `true` no fim.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Próximos `n` bytes.
    ///
    /// # Errors
    ///
    /// `Decode` se não houver.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.data.len() < n {
            return Err(Error::Decode);
        }
        let (a, b) = self.data.split_at(n);
        self.data = b;
        Ok(a)
    }

    /// Inteiro de `n` bytes (1 a 3), grande-endian.
    ///
    /// # Errors
    ///
    /// `Decode` se não houver.
    pub fn uint(&mut self, n: usize) -> Result<usize, Error> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0, |acc, &b| acc << 8 | usize::from(b)))
    }

    /// `u8`.
    ///
    /// # Errors
    ///
    /// `Decode` se não houver.
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// `u16`.
    ///
    /// # Errors
    ///
    /// `Decode` se não houver.
    pub fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Vetor com prefixo de tamanho de `n` bytes.
    ///
    /// # Errors
    ///
    /// `Decode` se o tamanho passar do que sobra.
    pub fn vec(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let len = self.uint(n)?;
        self.take(len)
    }

    /// Exige o fim.
    ///
    /// # Errors
    ///
    /// `Decode` se sobrar byte.
    pub fn finish(&self) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Decode)
        }
    }
}

/// Escrita num buffer fixo; estoura com `Internal`.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    /// Escrita do início de `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Bytes escritos.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` se nada foi escrito.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Acrescenta `b`.
    ///
    /// # Errors
    ///
    /// `Internal` se não couber.
    pub fn put(&mut self, b: &[u8]) -> Result<(), Error> {
        let end = self.len + b.len();
        self.buf
            .get_mut(self.len..end)
            .ok_or(Error::Internal)?
            .copy_from_slice(b);
        self.len = end;
        Ok(())
    }

    /// Acrescenta `v` em `n` bytes.
    ///
    /// # Errors
    ///
    /// `Internal` se não couber ou não representar.
    pub fn uint(&mut self, n: usize, v: usize) -> Result<(), Error> {
        if n < 8 && v >> (8 * n) != 0 {
            return Err(Error::Internal);
        }
        let bytes = v.to_be_bytes();
        self.put(&bytes[bytes.len() - n..])
    }

    /// Reserva um prefixo de tamanho de `n` bytes; devolve onde fica.
    ///
    /// # Errors
    ///
    /// `Internal` se não couber.
    pub fn open(&mut self, n: usize) -> Result<(usize, usize), Error> {
        let at = self.len;
        self.put(&[0; 4][..n])?;
        Ok((at, n))
    }

    /// Fecha o prefixo de [`Writer::open`] com o tamanho escrito depois dele.
    ///
    /// # Errors
    ///
    /// `Internal` se o tamanho não couber no prefixo.
    pub fn close(&mut self, (at, n): (usize, usize)) -> Result<(), Error> {
        let len = self.len - at - n;
        if n < 8 && len >> (8 * n) != 0 {
            return Err(Error::Internal);
        }
        let bytes = len.to_be_bytes();
        self.buf[at..at + n].copy_from_slice(&bytes[bytes.len() - n..]);
        Ok(())
    }
}

/// O que o `ClientHello` oferece.
pub struct ClientHello<'a> {
    /// `random`.
    pub random: &'a [u8; 32],
    /// `legacy_session_id` (32 bytes, modo de compatibilidade).
    pub session_id: &'a [u8; 32],
    /// Suítes, em ordem de preferência.
    pub suites: &'a [u16],
    /// Nome para o SNI (`None` para endereço IP, seção 3 da RFC 6066).
    pub server_name: Option<&'a str>,
    /// Partilhas de chave: (grupo, chave pública).
    pub shares: &'a [(u16, &'a [u8])],
}

impl ClientHello<'_> {
    /// Escreve a mensagem inteira (com o cabeçalho de handshake).
    ///
    /// # Errors
    ///
    /// `Internal` se não couber em `w`.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.put(&[kind::CLIENT_HELLO])?;
        let body = w.open(3)?;
        w.put(&[0x03, 0x03])?;
        w.put(self.random)?;
        w.uint(1, 32)?;
        w.put(self.session_id)?;
        w.uint(2, 2 * self.suites.len())?;
        for &s in self.suites {
            w.uint(2, usize::from(s))?;
        }
        w.put(&[1, 0])?;
        let exts = w.open(2)?;
        if let Some(name) = self.server_name {
            w.uint(2, usize::from(ext::SERVER_NAME))?;
            let e = w.open(2)?;
            let list = w.open(2)?;
            w.put(&[0])?;
            w.uint(2, name.len())?;
            w.put(name.as_bytes())?;
            w.close(list)?;
            w.close(e)?;
        }
        Self::list(w, ext::SUPPORTED_GROUPS, 2, self.shares.iter().map(|s| s.0))?;
        Self::list(w, ext::SIGNATURE_ALGORITHMS, 2, scheme::VERIFY.into_iter())?;
        Self::list(
            w,
            ext::SIGNATURE_ALGORITHMS_CERT,
            2,
            scheme::CERT.into_iter(),
        )?;
        Self::list(w, ext::SUPPORTED_VERSIONS, 1, [0x0304].into_iter())?;
        w.uint(2, usize::from(ext::KEY_SHARE))?;
        let e = w.open(2)?;
        let list = w.open(2)?;
        for (g, key) in self.shares {
            w.uint(2, usize::from(*g))?;
            w.uint(2, key.len())?;
            w.put(key)?;
        }
        w.close(list)?;
        w.close(e)?;
        w.close(exts)?;
        w.close(body)
    }

    /// Extensão que é uma lista de `u16` com prefixo de `n` bytes.
    fn list(
        w: &mut Writer<'_>,
        id: u16,
        n: usize,
        items: impl Iterator<Item = u16>,
    ) -> Result<(), Error> {
        w.uint(2, usize::from(id))?;
        let e = w.open(2)?;
        let l = w.open(n)?;
        for i in items {
            w.uint(2, usize::from(i))?;
        }
        w.close(l)?;
        w.close(e)
    }
}

/// `ServerHello` lido.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerHello<'a> {
    /// É um `HelloRetryRequest`.
    pub retry: bool,
    /// Os 8 últimos bytes do `random` marcam TLS 1.2 ou anterior
    /// (seção 4.1.3).
    pub downgrade: bool,
    /// `legacy_session_id_echo`.
    pub session_id: &'a [u8],
    /// Suíte escolhida.
    pub suite: u16,
    /// `supported_versions` escolhida (`None` se ausente: TLS 1.2).
    pub version: Option<u16>,
    /// `key_share`: (grupo, partilha). No HRR a partilha vem vazia.
    pub share: Option<(u16, &'a [u8])>,
}

impl<'a> ServerHello<'a> {
    /// Lê o corpo da mensagem (sem o cabeçalho de handshake).
    ///
    /// # Errors
    ///
    /// `Decode` se mal formado; `IllegalParameter` para compressão ou
    /// extensão repetida; `UnsupportedExtension` para extensão que o
    /// cliente não ofereceu.
    pub fn parse(body: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let _legacy_version = r.u16()?;
        let random = r.take(32)?;
        let session_id = r.vec(1)?;
        let suite = r.u16()?;
        if r.u8()? != 0 {
            return Err(Error::IllegalParameter);
        }
        let retry = random == HRR_RANDOM;
        let tail = &random[24..];
        let downgrade = tail[..7] == *b"DOWNGRD" && tail[7] <= 1;
        let mut out = Self {
            retry,
            downgrade,
            session_id,
            suite,
            version: None,
            share: None,
        };
        // TLS 1.2 sem extensões termina aqui.
        if r.is_empty() {
            return Ok(out);
        }
        let mut exts = Reader::new(r.vec(2)?);
        r.finish()?;
        let mut seen = 0u8;
        while !exts.is_empty() {
            let id = exts.u16()?;
            let mut e = Reader::new(exts.vec(2)?);
            let bit = match id {
                ext::SUPPORTED_VERSIONS => {
                    out.version = Some(e.u16()?);
                    1
                }
                ext::KEY_SHARE => {
                    let g = e.u16()?;
                    out.share = Some((g, if retry { &[][..] } else { e.vec(2)? }));
                    2
                }
                // O cookie do HRR é aceito e ignorado: o HRR é recusado.
                44 if retry => {
                    e.vec(2)?;
                    4
                }
                _ => return Err(Error::UnsupportedExtension),
            };
            e.finish()?;
            if seen & bit != 0 {
                return Err(Error::IllegalParameter);
            }
            seen |= bit;
        }
        Ok(out)
    }
}

/// Confere `EncryptedExtensions`: só `server_name` (vazio) e
/// `supported_groups`, que o cliente ofereceu, sem repetição.
///
/// # Errors
///
/// `Decode`, `IllegalParameter` ou `UnsupportedExtension`.
pub fn encrypted_extensions(body: &[u8]) -> Result<(), Error> {
    let mut r = Reader::new(body);
    let mut exts = Reader::new(r.vec(2)?);
    r.finish()?;
    let mut seen = 0u8;
    while !exts.is_empty() {
        let id = exts.u16()?;
        let data = exts.vec(2)?;
        let bit = match id {
            ext::SERVER_NAME if data.is_empty() => 1,
            ext::SUPPORTED_GROUPS => {
                let mut e = Reader::new(data);
                let list = e.vec(2)?;
                e.finish()?;
                if list.len() % 2 != 0 {
                    return Err(Error::Decode);
                }
                2
            }
            ext::SERVER_NAME => return Err(Error::Decode),
            _ => return Err(Error::UnsupportedExtension),
        };
        if seen & bit != 0 {
            return Err(Error::IllegalParameter);
        }
        seen |= bit;
    }
    Ok(())
}

/// `Certificate`: contexto (vazio para o servidor) e a lista de
/// certificados em DER, folha primeiro. As extensões de cada entrada (OCSP,
/// SCT) são lidas e ignoradas até a T-655.
///
/// # Errors
///
/// `Decode` se mal formado ou vazio; `BadCertificate` acima de
/// `ox509::MAX_CHAIN`;
/// `IllegalParameter` com contexto não vazio.
pub fn certificate(body: &[u8]) -> Result<([&[u8]; ox509::MAX_CHAIN], usize), Error> {
    let mut r = Reader::new(body);
    if !r.vec(1)?.is_empty() {
        return Err(Error::IllegalParameter);
    }
    let mut list = Reader::new(r.vec(3)?);
    r.finish()?;
    let mut out: [&[u8]; ox509::MAX_CHAIN] = [&[]; ox509::MAX_CHAIN];
    let mut n = 0;
    while !list.is_empty() {
        let cert = list.vec(3)?;
        list.vec(2)?;
        if cert.is_empty() {
            return Err(Error::Decode);
        }
        *out.get_mut(n).ok_or(Error::BadCertificate)? = cert;
        n += 1;
    }
    if n == 0 {
        return Err(Error::Decode);
    }
    Ok((out, n))
}

/// `CertificateVerify`: esquema e assinatura.
///
/// # Errors
///
/// `Decode` se mal formado.
pub fn certificate_verify(body: &[u8]) -> Result<(u16, &[u8]), Error> {
    let mut r = Reader::new(body);
    let s = r.u16()?;
    let sig = r.vec(2)?;
    r.finish()?;
    Ok((s, sig))
}

/// O texto assinado pelo `CertificateVerify` do servidor (seção 4.4.3):
/// 64 espaços, o rótulo, um zero e o hash da transcrição.
pub fn verify_input<'b>(hash: &[u8], buf: &'b mut [u8; 64 + 34 + 48]) -> &'b [u8] {
    const LABEL: &[u8] = b"TLS 1.3, server CertificateVerify\0";
    buf[..64].fill(0x20);
    buf[64..64 + LABEL.len()].copy_from_slice(LABEL);
    let n = 64 + LABEL.len();
    buf[n..n + hash.len()].copy_from_slice(hash);
    &buf[..n + hash.len()]
}
