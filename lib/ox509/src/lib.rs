//! `ox509`: parser de certificados X.509 do `tlsd` (ADR 0071; T-650).
//!
//! O certificado vem da rede e é dado não confiável. O parser lê DER
//! estrito ([`der`]), não aloca (todo campo é uma fatia da entrada), não
//! recorre (a gramática fixa a profundidade em 6 níveis) e recusa
//! certificados acima de [`MAX_CERT_LEN`], com mais de
//! [`ext::MAX_EXTENSIONS`] extensões ou extensões repetidas. Campos que o
//! `tlsd` não usa são pulados com validação de limites.
//!
//! Aqui só se lê. A validação da cadeia (assinaturas, validade, uso de
//! chave, nome) é da T-651.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod der;
pub mod ext;
mod oid;

use der::{Reader, tag};
pub use ext::Extensions;

/// Maior certificado aceito, em bytes.
pub const MAX_CERT_LEN: usize = 16 * 1024;
/// Maior cadeia aceita, folha incluída (ADR 0071, item 4).
pub const MAX_CHAIN: usize = 8;

/// Motivo de um certificado ser recusado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Codificação DER ou estrutura inválida.
    Malformed,
    /// Passou de um limite (tamanho, extensões, cadeia).
    TooLarge,
    /// Versão diferente de v1 e v3.
    Version,
    /// O algoritmo do `TBSCertificate` difere do externo.
    AlgorithmMismatch,
    /// A mesma extensão aparece duas vezes.
    DuplicateExtension,
    /// Cadeia vazia.
    EmptyChain,
}

/// Função de hash de uma assinatura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// Algoritmo de assinatura (ADR 0071, item 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA com o hash dado.
    Ecdsa(Hash),
    /// RSA PKCS#1 v1.5 com o hash dado.
    RsaPkcs1(Hash),
    /// RSA-PSS com MGF1 do mesmo hash e sal do tamanho do hash.
    RsaPss(Hash),
    /// Ed25519.
    Ed25519,
    /// Outro: o certificado é lido (uma raiz antiga pode ter assinatura
    /// SHA-1, que ninguém confere), mas a validação recusa verificá-lo.
    Unsupported,
}

/// Chave pública do `SubjectPublicKeyInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKey<'a> {
    /// P-256, ponto não comprimido (`04 ‖ x ‖ y`, 65 bytes).
    EcP256(&'a [u8]),
    /// RSA: módulo e expoente, sem zeros à esquerda.
    Rsa {
        /// Módulo `n`.
        n: &'a [u8],
        /// Expoente público `e`.
        e: &'a [u8],
    },
    /// Ed25519, 32 bytes.
    Ed25519(&'a [u8]),
    /// Outro algoritmo ou curva (P-384 de algumas raízes, por exemplo).
    Unsupported,
}

/// Um certificado lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// O certificado inteiro em DER.
    pub raw: &'a [u8],
    /// O `TBSCertificate` em DER: a parte assinada.
    pub tbs: &'a [u8],
    /// Versão (1 ou 3).
    pub version: u8,
    /// Número de série (conteúdo do INTEGER).
    pub serial: &'a [u8],
    /// Algoritmo de assinatura.
    pub signature_algorithm: SignatureAlgorithm,
    /// Emissor, `Name` em DER.
    pub issuer: &'a [u8],
    /// Titular, `Name` em DER.
    pub subject: &'a [u8],
    /// Início da validade, segundos desde 1970 (UTC).
    pub not_before: i64,
    /// Fim da validade, segundos desde 1970 (UTC).
    pub not_after: i64,
    /// `SubjectPublicKeyInfo` em DER (para o `pin`, ADR 0070, item 7).
    pub spki: &'a [u8],
    /// Chave pública.
    pub public_key: PublicKey<'a>,
    /// Valor da assinatura (conteúdo da BIT STRING).
    pub signature: &'a [u8],
    /// Extensões v3.
    pub extensions: Extensions<'a>,
}

impl<'a> Certificate<'a> {
    /// Lê um certificado em DER, que ocupa `data` inteiro.
    ///
    /// # Errors
    ///
    /// Ver [`Error`].
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() > MAX_CERT_LEN {
            return Err(Error::TooLarge);
        }
        let outer = der::single(data, tag::SEQUENCE)?;
        let mut c = Reader::new(outer.value);
        let tbs = c.expect(tag::SEQUENCE)?;
        let alg_outer = c.expect(tag::SEQUENCE)?;
        let signature = der::bit_string_bytes(c.expect(tag::BIT_STRING)?.value)?;
        c.finish()?;

        let mut t = Reader::new(tbs.value);
        let version = match t.optional(0xA0)? {
            Some(v) => match der::small_uint(der::single(v.value, tag::INTEGER)?.value)? {
                // DER omite o v1 padrão; v2 não tem as extensões que usamos.
                2 => 3,
                _ => return Err(Error::Version),
            },
            None => 1,
        };
        let serial = der::integer(t.expect(tag::INTEGER)?.value)?;
        if serial.len() > 21 {
            return Err(Error::Malformed);
        }
        let alg_inner = t.expect(tag::SEQUENCE)?;
        if alg_inner.raw != alg_outer.raw {
            return Err(Error::AlgorithmMismatch);
        }
        let issuer = name(&mut t)?;
        let mut validity = t.sequence()?;
        let not_before = der::time(&validity.any()?)?;
        let not_after = der::time(&validity.any()?)?;
        validity.finish()?;
        let subject = name(&mut t)?;
        let spki = t.expect(tag::SEQUENCE)?;
        let public_key = public_key(spki.value)?;
        let mut extensions = Extensions::default();
        if version == 3 {
            // `issuerUniqueID` [1] e `subjectUniqueID` [2], obsoletos.
            t.optional(0x81)?;
            t.optional(0x82)?;
            if let Some(e) = t.optional(0xA3)? {
                extensions = Extensions::parse(der::single(e.value, tag::SEQUENCE)?.value)?;
            }
        }
        t.finish()?;
        Ok(Self {
            raw: data,
            tbs: tbs.raw,
            version,
            serial,
            signature_algorithm: signature_algorithm(alg_outer.value)?,
            issuer,
            subject,
            not_before,
            not_after,
            spki: spki.raw,
            public_key,
            signature,
            extensions,
        })
    }
}

/// `Name`: SEQUENCE OF SET OF SEQUENCE { OID, valor }. Devolve o DER.
fn name<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let n = r.expect(tag::SEQUENCE)?;
    let mut rdns = Reader::new(n.value);
    while !rdns.is_empty() {
        let mut set = Reader::new(rdns.expect(tag::SET)?.value);
        if set.is_empty() {
            return Err(Error::Malformed);
        }
        while !set.is_empty() {
            let mut atv = set.sequence()?;
            der::oid(atv.expect(tag::OID)?.value)?;
            atv.any()?;
            atv.finish()?;
        }
    }
    Ok(n.raw)
}

/// `AlgorithmIdentifier` da assinatura (conteúdo da SEQUENCE).
fn signature_algorithm(alg: &[u8]) -> Result<SignatureAlgorithm, Error> {
    use SignatureAlgorithm as S;
    let mut r = Reader::new(alg);
    let id = der::oid(r.expect(tag::OID)?.value)?;
    let params = if r.is_empty() { None } else { Some(r.any()?) };
    r.finish()?;
    let null = params.is_some_and(|p| p.tag == tag::NULL && p.value.is_empty());
    let absent = params.is_none();
    Ok(match id {
        oid::ECDSA_SHA256 if absent => S::Ecdsa(Hash::Sha256),
        oid::ECDSA_SHA384 if absent => S::Ecdsa(Hash::Sha384),
        oid::RSA_SHA256 if null || absent => S::RsaPkcs1(Hash::Sha256),
        oid::RSA_SHA384 if null || absent => S::RsaPkcs1(Hash::Sha384),
        oid::RSA_SHA512 if null || absent => S::RsaPkcs1(Hash::Sha512),
        oid::ED25519 if absent => S::Ed25519,
        oid::RSA_PSS => match params {
            Some(p) if p.tag == tag::SEQUENCE => pss(p.value).map_or(S::Unsupported, S::RsaPss),
            _ => return Err(Error::Malformed),
        },
        oid::ECDSA_SHA256 | oid::ECDSA_SHA384 | oid::ED25519 => return Err(Error::Malformed),
        _ => S::Unsupported,
    })
}

/// `RSASSA-PSS-params` (RFC 4055): só hash, MGF1 do mesmo hash e sal do
/// tamanho do hash; o `trailerField` padrão é omitido pelo DER.
fn pss(p: &[u8]) -> Option<Hash> {
    let mut r = Reader::new(p);
    let hash = hash_alg(Reader::new(r.expect(0xA0).ok()?.value).sequence().ok()?)?;
    let mut mgf = Reader::new(r.expect(0xA1).ok()?.value).sequence().ok()?;
    if mgf.expect(tag::OID).ok()?.value != oid::MGF1 || hash_alg(mgf.sequence().ok()?)? != hash {
        return None;
    }
    mgf.finish().ok()?;
    let salt = Reader::new(r.expect(0xA2).ok()?.value)
        .expect(tag::INTEGER)
        .ok()?;
    r.finish().ok()?;
    let want = match hash {
        Hash::Sha256 => 32,
        Hash::Sha384 => 48,
        Hash::Sha512 => 64,
    };
    (der::small_uint(salt.value).ok()? == want).then_some(hash)
}

/// `AlgorithmIdentifier` de hash, com parâmetro NULL ou ausente.
fn hash_alg(mut r: Reader<'_>) -> Option<Hash> {
    let id = r.expect(tag::OID).ok()?.value;
    r.optional(tag::NULL).ok()?;
    r.finish().ok()?;
    match id {
        oid::SHA256 => Some(Hash::Sha256),
        oid::SHA384 => Some(Hash::Sha384),
        oid::SHA512 => Some(Hash::Sha512),
        _ => None,
    }
}

/// `SubjectPublicKeyInfo` (conteúdo da SEQUENCE).
fn public_key(spki: &[u8]) -> Result<PublicKey<'_>, Error> {
    let mut info = Reader::new(spki);
    let mut alg = info.sequence()?;
    let key = der::bit_string_bytes(info.expect(tag::BIT_STRING)?.value)?;
    info.finish()?;
    let id = der::oid(alg.expect(tag::OID)?.value)?;
    let param = if alg.is_empty() {
        None
    } else {
        Some(alg.any()?)
    };
    alg.finish()?;
    Ok(match (id, param) {
        (oid::EC_PUBLIC_KEY, Some(p)) if p.tag == tag::OID => {
            if p.value != oid::P256 {
                return Ok(PublicKey::Unsupported);
            }
            if key.len() != 65 || key[0] != 0x04 {
                return Err(Error::Malformed);
            }
            PublicKey::EcP256(key)
        }
        (oid::RSA_ENCRYPTION, Some(p)) if p.tag == tag::NULL && p.value.is_empty() => {
            let mut rsa = der::single(key, tag::SEQUENCE).map(|s| Reader::new(s.value))?;
            let n = positive(rsa.expect(tag::INTEGER)?.value)?;
            let e = positive(rsa.expect(tag::INTEGER)?.value)?;
            rsa.finish()?;
            PublicKey::Rsa { n, e }
        }
        (oid::ED25519, None) if key.len() == 32 => PublicKey::Ed25519(key),
        (oid::EC_PUBLIC_KEY | oid::RSA_ENCRYPTION | oid::ED25519, _) => {
            return Err(Error::Malformed);
        }
        _ => PublicKey::Unsupported,
    })
}

/// INTEGER positivo, sem o zero de sinal.
fn positive(v: &[u8]) -> Result<&[u8], Error> {
    match der::integer(v)? {
        [0x00, rest @ ..] if !rest.is_empty() => Ok(rest),
        [b, ..] if *b & 0x80 == 0 && *b != 0 => Ok(v),
        _ => Err(Error::Malformed),
    }
}

/// Cadeia como o servidor a entrega: a folha primeiro.
#[derive(Clone, Copy, Debug)]
pub struct Chain<'a> {
    certs: [Option<Certificate<'a>>; MAX_CHAIN],
    len: usize,
}

impl<'a> Chain<'a> {
    /// Lê cada certificado de `list`, na ordem.
    ///
    /// # Errors
    ///
    /// `EmptyChain`, `TooLarge` com mais de [`MAX_CHAIN`] certificados, ou o
    /// erro do primeiro certificado inválido.
    pub fn parse<I: IntoIterator<Item = &'a [u8]>>(list: I) -> Result<Self, Error> {
        let mut out = Self {
            certs: [None; MAX_CHAIN],
            len: 0,
        };
        for der in list {
            if out.len == MAX_CHAIN {
                return Err(Error::TooLarge);
            }
            out.certs[out.len] = Some(Certificate::parse(der)?);
            out.len += 1;
        }
        if out.len == 0 {
            return Err(Error::EmptyChain);
        }
        Ok(out)
    }

    /// A folha.
    #[must_use]
    pub fn leaf(&self) -> &Certificate<'a> {
        self.iter()
            .next()
            .unwrap_or_else(|| unreachable!("cadeia vazia"))
    }

    /// Os certificados, da folha para cima.
    pub fn iter(&self) -> impl Iterator<Item = &Certificate<'a>> {
        self.certs[..self.len].iter().flatten()
    }

    /// Quantos certificados.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Sempre `false`: `parse` recusa cadeia vazia.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests;
