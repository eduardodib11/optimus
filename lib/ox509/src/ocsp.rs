//! Resposta OCSP grampeada (RFC 6960 e RFC 6066, seção 8; ADR 0071, item 6;
//! T-655).
//!
//! O servidor entrega a resposta junto do certificado (`status_request`);
//! o `tlsd` não busca nada na rede (item 7). A resposta vem da rede e é dado
//! não confiável: o DER é lido com o leitor estrito do [`crate::der`], sem
//! alocar, e nada do que ela diz vale antes de a assinatura conferir.
//!
//! [`validate`] devolve o [`Status`] do certificado se, e só se:
//!
//! 1. a resposta é `successful` e do tipo `id-pkix-ocsp-basic`;
//! 2. a assinatura confere com a chave do **emissor** do certificado ou com
//!    a de um respondedor delegado: um certificado do próprio emissor, com
//!    `id-kp-OCSPSigning`, dentro da validade (RFC 6960, 4.2.2.2);
//! 3. há uma resposta única para o **número de série** do certificado. O
//!    `CertID` também leva dois *hashes* (nome e chave do emissor, quase
//!    sempre SHA-1); como o signatário já foi provado ser o emissor ou um
//!    delegado dele, o número de série basta para saber de qual certificado
//!    se fala, e esta camada não precisa de SHA-1;
//! 4. `thisUpdate` não está no futuro (com [`SKEW`] de folga) e `nextUpdate`
//!    não passou; sem `nextUpdate`, a resposta vale por [`MAX_AGE`].
//!
//! A assinatura em si é de quem chama ([`SignatureVerifier`]), como na
//! validação da cadeia.

use crate::der::{self, Reader, tag};
use crate::verify::{SignatureVerifier, key_fits};
use crate::{Certificate, Error, SignatureAlgorithm, ext, oid};

/// Maior resposta aceita, em bytes (a resposta com certificado de
/// respondedor passa de 1 KiB; 8 KiB deixa folga e limita o parser).
pub const MAX_RESPONSE: usize = 8 * 1024;
/// Máximo de respostas únicas examinadas.
pub const MAX_SINGLE: usize = 16;
/// Máximo de certificados de respondedor examinados.
pub const MAX_RESPONDER_CERTS: usize = 4;
/// Folga do relógio para `thisUpdate`, em segundos.
pub const SKEW: i64 = 300;
/// Quanto vale uma resposta sem `nextUpdate`, em segundos (7 dias).
pub const MAX_AGE: i64 = 7 * 86_400;

/// O que o emissor diz do certificado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Não revogado.
    Good,
    /// Revogado.
    Revoked {
        /// Instante da revogação, segundos desde 1970.
        at: i64,
        /// `CRLReason`, se informado.
        reason: Option<u8>,
    },
    /// O respondedor não conhece o certificado.
    Unknown,
}

/// Motivo de a resposta não valer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OcspError {
    /// DER inválido ou estrutura fora do perfil.
    Parse(Error),
    /// `responseStatus` diferente de `successful` (o código).
    Unsuccessful(u8),
    /// `responseType` que não é `id-pkix-ocsp-basic`.
    BadType,
    /// Nenhuma resposta única para o número de série do certificado.
    NoMatch,
    /// `thisUpdate` no futuro.
    NotYetValid,
    /// `nextUpdate` já passou (ou a resposta sem ele é velha demais).
    Stale,
    /// A assinatura não confere com o emissor nem com um delegado.
    BadSignature,
    /// Havia certificado de respondedor, mas nenhum autorizado pelo emissor.
    UnauthorizedSigner,
    /// Algoritmo ou chave fora da ADR 0071.
    UnsupportedSignature,
    /// A resposta vale, mas diz `unknown`: [`validate`] devolve
    /// [`Status::Unknown`], e quem decide a política usa este erro para
    /// tratar o caso como resposta inútil.
    UnknownCertificate,
}

impl From<Error> for OcspError {
    fn from(e: Error) -> Self {
        Self::Parse(e)
    }
}

/// A parte útil de uma resposta já lida (nada conferido ainda).
struct Parsed<'a> {
    tbs: &'a [u8],
    alg: SignatureAlgorithm,
    signature: &'a [u8],
    /// Conteúdo do `[0] EXPLICIT SEQUENCE OF Certificate`, se houver.
    certs: Option<&'a [u8]>,
    status: Status,
    this_update: i64,
    next_update: Option<i64>,
}

/// Valida `response` (DER do `OCSPResponse`) como o estado de `leaf`, cujo
/// emissor é `issuer`, no instante `now` (segundos desde 1970, do `timed`).
///
/// # Errors
///
/// Ver [`OcspError`]. A ordem dos testes é a da lista do módulo: o status
/// só é devolvido depois da assinatura e da validade.
pub fn validate(
    response: &[u8],
    leaf: &Certificate<'_>,
    issuer: &Certificate<'_>,
    now: i64,
    v: &impl SignatureVerifier,
) -> Result<Status, OcspError> {
    let p = parse(response, leaf.serial)?;
    check_signature(&p, issuer, now, v)?;
    if p.this_update > now.saturating_add(SKEW) {
        return Err(OcspError::NotYetValid);
    }
    let stale = match p.next_update {
        Some(n) => now > n,
        None => now.saturating_sub(p.this_update) > MAX_AGE,
    };
    if stale {
        return Err(OcspError::Stale);
    }
    Ok(p.status)
}

/// `ENUMERATED` (etiqueta universal 10).
const ENUMERATED: u8 = 0x0A;

fn parse<'a>(response: &'a [u8], serial: &[u8]) -> Result<Parsed<'a>, OcspError> {
    if response.len() > MAX_RESPONSE {
        return Err(Error::TooLarge.into());
    }
    let mut top = Reader::new(der::single(response, tag::SEQUENCE)?.value);
    let code = match top.expect(ENUMERATED)?.value {
        [c] => *c,
        _ => return Err(Error::Malformed.into()),
    };
    if code != 0 {
        return Err(OcspError::Unsuccessful(code));
    }
    let bytes = top.expect(0xA0)?;
    top.finish()?;
    let mut wrapper = Reader::new(der::single(bytes.value, tag::SEQUENCE)?.value);
    if der::oid(wrapper.expect(tag::OID)?.value)? != oid::OCSP_BASIC {
        return Err(OcspError::BadType);
    }
    let basic = der::single(wrapper.expect(tag::OCTET_STRING)?.value, tag::SEQUENCE)?;
    wrapper.finish()?;

    let mut parts = Reader::new(basic.value);
    let tbs = parts.expect(tag::SEQUENCE)?;
    let alg = parts.expect(tag::SEQUENCE)?;
    let signature = der::bit_string_bytes(parts.expect(tag::BIT_STRING)?.value)?;
    let certs = match parts.optional(0xA0)? {
        Some(c) => Some(der::single(c.value, tag::SEQUENCE)?.value),
        None => None,
    };
    parts.finish()?;
    let alg = crate::signature_algorithm(alg.value)?;

    let mut data = Reader::new(tbs.value);
    // `version` [0] é DEFAULT v1: o DER o omite (como no certificado).
    if !matches!(data.peek_tag(), Some(0xA1 | 0xA2)) {
        return Err(Error::Malformed.into());
    }
    data.any()?; // `responderID`: o signatário vem da assinatura, não daqui.
    generalized(&mut data)?; // `producedAt`.
    let mut singles = data.sequence()?;
    data.optional(0xA1)?; // `responseExtensions`: sem nonce no TLS; ignoradas.
    data.finish()?;

    let mut found = None;
    let mut n = 0;
    while !singles.is_empty() {
        n += 1;
        if n > MAX_SINGLE {
            return Err(Error::TooLarge.into());
        }
        let single = single_response(&mut singles)?;
        if found.is_none() && single.serial == serial {
            found = Some(single);
        }
    }
    let hit = found.ok_or(OcspError::NoMatch)?;
    Ok(Parsed {
        tbs: tbs.raw,
        alg,
        signature,
        certs,
        status: hit.status,
        this_update: hit.this_update,
        next_update: hit.next_update,
    })
}

/// `GeneralizedTime` (o OCSP não usa `UTCTime`).
fn generalized(r: &mut Reader<'_>) -> Result<i64, Error> {
    der::time(&r.expect(tag::GENERALIZED_TIME)?)
}

struct Single<'a> {
    serial: &'a [u8],
    status: Status,
    this_update: i64,
    next_update: Option<i64>,
}

/// `SingleResponse` (RFC 6960, 4.2.1).
fn single_response<'a>(list: &mut Reader<'a>) -> Result<Single<'a>, Error> {
    let mut single = list.sequence()?;
    let mut id = single.sequence()?;
    // `hashAlgorithm`: só a forma é conferida (veja o módulo).
    let mut hash = id.sequence()?;
    der::oid(hash.expect(tag::OID)?.value)?;
    hash.optional(tag::NULL)?;
    hash.finish()?;
    id.expect(tag::OCTET_STRING)?;
    id.expect(tag::OCTET_STRING)?;
    let serial = der::integer(id.expect(tag::INTEGER)?.value)?;
    id.finish()?;

    let st = single.any()?;
    let status = match (st.tag, st.value) {
        (0x80, []) => Status::Good,
        (0x82, []) => Status::Unknown,
        (0xA1, body) => {
            let mut info = Reader::new(body);
            let at = generalized(&mut info)?;
            let reason = match info.optional(0xA0)? {
                Some(tagged) => match der::single(tagged.value, ENUMERATED)?.value {
                    [code] => Some(*code),
                    _ => return Err(Error::Malformed),
                },
                None => None,
            };
            info.finish()?;
            Status::Revoked { at, reason }
        }
        _ => return Err(Error::Malformed),
    };
    let this_update = generalized(&mut single)?;
    let next_update = match single.optional(0xA0)? {
        Some(next) => {
            let mut inner = Reader::new(next.value);
            let at = generalized(&mut inner)?;
            inner.finish()?;
            Some(at)
        }
        None => None,
    };
    single.optional(0xA1)?; // `singleExtensions`.
    single.finish()?;
    Ok(Single {
        serial,
        status,
        this_update,
        next_update,
    })
}

/// A assinatura vale para o emissor ou para um respondedor que ele autorizou.
fn check_signature(
    p: &Parsed<'_>,
    issuer: &Certificate<'_>,
    now: i64,
    v: &impl SignatureVerifier,
) -> Result<(), OcspError> {
    let direct = key_fits(p.alg, &issuer.public_key);
    if direct && v.verify(p.alg, &issuer.public_key, p.tbs, p.signature) {
        return Ok(());
    }
    let mut seen = 0;
    let mut authorized = false;
    let mut certs = Reader::new(p.certs.unwrap_or(&[]));
    while !certs.is_empty() {
        seen += 1;
        if seen > MAX_RESPONDER_CERTS {
            return Err(Error::TooLarge.into());
        }
        let cert = Certificate::parse(certs.any()?.raw)?;
        if !delegated(&cert, issuer, now, v) {
            continue;
        }
        authorized = true;
        if key_fits(p.alg, &cert.public_key)
            && v.verify(p.alg, &cert.public_key, p.tbs, p.signature)
        {
            return Ok(());
        }
    }
    Err(if seen > 0 && !authorized {
        OcspError::UnauthorizedSigner
    } else if !direct && matches!(p.alg, SignatureAlgorithm::Unsupported) {
        OcspError::UnsupportedSignature
    } else {
        OcspError::BadSignature
    })
}

/// `cert` é um respondedor delegado do `issuer` (RFC 6960, 4.2.2.2).
fn delegated(
    cert: &Certificate<'_>,
    issuer: &Certificate<'_>,
    now: i64,
    v: &impl SignatureVerifier,
) -> bool {
    let e = &cert.extensions;
    cert.issuer == issuer.subject
        && now >= cert.not_before
        && now <= cert.not_after
        && !e.unknown_critical
        && e.ext_key_usage.is_some_and(|k| k.ocsp_signing)
        && e.key_usage
            .is_none_or(|k| k & ext::key_usage::DIGITAL_SIGNATURE != 0)
        && key_fits(cert.signature_algorithm, &issuer.public_key)
        && v.verify(
            cert.signature_algorithm,
            &issuer.public_key,
            cert.tbs,
            cert.signature,
        )
}

#[cfg(test)]
#[path = "ocsp_tests.rs"]
mod tests;
