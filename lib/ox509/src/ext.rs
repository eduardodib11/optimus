//! Extensões v3 que a validação usa (ADR 0071, item 4). As demais são
//! puladas; uma desconhecida marcada como crítica fica registrada para a
//! validação recusar o certificado.

use crate::der::{self, Reader, tag};
use crate::{Error, oid};

/// Máximo de extensões num certificado.
pub const MAX_EXTENSIONS: usize = 32;

/// Bits do `keyUsage` (RFC 5280, 4.2.1.3): o bit `n` do ASN.1 é `1 << n`.
pub mod key_usage {
    /// `digitalSignature`.
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    /// `keyCertSign`.
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    /// `cRLSign`.
    pub const CRL_SIGN: u16 = 1 << 6;
}

/// Extensões lidas de um certificado.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Extensions<'a> {
    /// `basicConstraints`: `Some` se presente.
    pub basic_constraints: Option<BasicConstraints>,
    /// `keyUsage`: `Some(bits)` se presente.
    pub key_usage: Option<u16>,
    /// `extKeyUsage`: `Some` se presente.
    pub ext_key_usage: Option<ExtKeyUsage>,
    /// `subjectAltName`.
    pub subject_alt_name: Option<GeneralNames<'a>>,
    /// `nameConstraints`.
    pub name_constraints: Option<NameConstraints<'a>>,
    /// `subjectKeyIdentifier`.
    pub subject_key_id: Option<&'a [u8]>,
    /// `keyIdentifier` do `authorityKeyIdentifier`.
    pub authority_key_id: Option<&'a [u8]>,
    /// TLS Feature (RFC 7633) com `status_request`: o `must-staple`.
    pub must_staple: bool,
    /// Alguma extensão desconhecida veio marcada como crítica.
    pub unknown_critical: bool,
}

/// `basicConstraints` (RFC 5280, 4.2.1.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicConstraints {
    /// O certificado é de uma CA.
    pub ca: bool,
    /// `pathLenConstraint` (saturado em 255).
    pub path_len: Option<u8>,
}

/// `extKeyUsage` (RFC 5280, 4.2.1.12), só o que o `tlsd` consulta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtKeyUsage {
    /// `id-kp-serverAuth`.
    pub server_auth: bool,
    /// `anyExtendedKeyUsage`.
    pub any: bool,
}

/// Lista `GeneralNames` já validada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneralNames<'a> {
    content: &'a [u8],
}

/// Um `GeneralName` (RFC 5280, 4.2.1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeneralName<'a> {
    /// `dNSName` (ASCII).
    Dns(&'a str),
    /// `iPAddress`: 4 ou 16 bytes, ou 8 ou 32 (endereço e máscara) nas
    /// restrições de nome.
    Ip(&'a [u8]),
    /// `directoryName`: o `Name` em DER.
    Directory(&'a [u8]),
    /// Outra forma, que o `tlsd` não interpreta.
    Other(u8),
}

impl<'a> GeneralNames<'a> {
    fn parse(content: &'a [u8], subtrees: bool) -> Result<Self, Error> {
        let mut r = Reader::new(content);
        if r.is_empty() {
            return Err(Error::Malformed);
        }
        while !r.is_empty() {
            if subtrees {
                subtree(&mut r)?;
            } else {
                general_name(r.any()?, false)?;
            }
        }
        Ok(Self { content })
    }

    /// Os nomes, em ordem.
    pub fn iter(&self) -> impl Iterator<Item = GeneralName<'a>> + 'a {
        let mut r = Reader::new(self.content);
        // Já validado em `parse`: `any` e `general_name` não falham aqui.
        core::iter::from_fn(move || general_name(r.any().ok()?, false).ok())
    }
}

/// `nameConstraints` (RFC 5280, 4.2.1.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameConstraints<'a> {
    permitted: Option<&'a [u8]>,
    excluded: Option<&'a [u8]>,
}

impl<'a> NameConstraints<'a> {
    /// Bases das subárvores permitidas (`None` se o campo não existe).
    #[must_use]
    pub fn permitted(&self) -> Option<impl Iterator<Item = GeneralName<'a>> + 'a> {
        self.permitted.map(subtrees)
    }

    /// Bases das subárvores excluídas.
    #[must_use]
    pub fn excluded(&self) -> Option<impl Iterator<Item = GeneralName<'a>> + 'a> {
        self.excluded.map(subtrees)
    }
}

fn subtrees(content: &[u8]) -> impl Iterator<Item = GeneralName<'_>> {
    let mut r = Reader::new(content);
    core::iter::from_fn(move || subtree(&mut r).ok())
}

/// `GeneralSubtree`: a RFC 5280 exige `minimum` 0 e `maximum` ausente, isto
/// é, só a base.
fn subtree<'a>(r: &mut Reader<'a>) -> Result<GeneralName<'a>, Error> {
    let mut s = r.sequence()?;
    let base = general_name(s.any()?, true)?;
    s.finish()?;
    Ok(base)
}

fn general_name(e: der::Tlv<'_>, constraint: bool) -> Result<GeneralName<'_>, Error> {
    Ok(match e.tag {
        0x82 => GeneralName::Dns(ascii(e.value)?),
        0x87 => {
            let ok = if constraint { [8, 32] } else { [4, 16] };
            if !ok.contains(&e.value.len()) {
                return Err(Error::Malformed);
            }
            GeneralName::Ip(e.value)
        }
        0xA4 => GeneralName::Directory(der::single(e.value, tag::SEQUENCE)?.raw),
        0x81 | 0x86 | 0x88 | 0xA0 | 0xA3 | 0xA5 => GeneralName::Other(e.tag),
        _ => return Err(Error::Malformed),
    })
}

fn ascii(v: &[u8]) -> Result<&str, Error> {
    if v.is_ascii() {
        core::str::from_utf8(v).map_err(|_| Error::Malformed)
    } else {
        Err(Error::Malformed)
    }
}

impl<'a> Extensions<'a> {
    /// Lê o `[3] EXPLICIT Extensions` (o conteúdo da SEQUENCE).
    pub(crate) fn parse(list: &'a [u8]) -> Result<Self, Error> {
        let mut out = Self::default();
        let mut seen: [&[u8]; MAX_EXTENSIONS] = [&[]; MAX_EXTENSIONS];
        let mut n = 0;
        let mut r = Reader::new(list);
        if r.is_empty() {
            return Err(Error::Malformed);
        }
        while !r.is_empty() {
            let mut e = r.sequence()?;
            let id = der::oid(e.expect(tag::OID)?.value)?;
            let critical = match e.optional(tag::BOOLEAN)? {
                // DER pede omitir o FALSE padrão, mas emissores reais o
                // codificam; o valor é o mesmo.
                Some(b) => der::boolean(b.value)?,
                None => false,
            };
            let value = e.expect(tag::OCTET_STRING)?.value;
            e.finish()?;
            if n == MAX_EXTENSIONS {
                return Err(Error::TooLarge);
            }
            if seen[..n].contains(&id) {
                return Err(Error::DuplicateExtension);
            }
            seen[n] = id;
            n += 1;
            if !out.apply(id, value)? && critical {
                out.unknown_critical = true;
            }
        }
        Ok(out)
    }

    /// Interpreta uma extensão conhecida; `false` se for desconhecida.
    fn apply(&mut self, id: &[u8], value: &'a [u8]) -> Result<bool, Error> {
        match id {
            oid::BASIC_CONSTRAINTS => {
                let mut s = der::single(value, tag::SEQUENCE).map(|e| Reader::new(e.value))?;
                let ca = match s.optional(tag::BOOLEAN)? {
                    Some(b) => der::boolean(b.value)?,
                    None => false,
                };
                let path_len = match s.optional(tag::INTEGER)? {
                    Some(i) => Some(u8::try_from(der::small_uint(i.value)?).unwrap_or(u8::MAX)),
                    None => None,
                };
                s.finish()?;
                self.basic_constraints = Some(BasicConstraints { ca, path_len });
            }
            oid::KEY_USAGE => self.key_usage = Some(key_usage_bits(value)?),
            oid::EXT_KEY_USAGE => {
                let mut s = der::single(value, tag::SEQUENCE).map(|e| Reader::new(e.value))?;
                let mut eku = ExtKeyUsage {
                    server_auth: false,
                    any: false,
                };
                if s.is_empty() {
                    return Err(Error::Malformed);
                }
                while !s.is_empty() {
                    match der::oid(s.expect(tag::OID)?.value)? {
                        oid::KP_SERVER_AUTH => eku.server_auth = true,
                        oid::ANY_EXT_KEY_USAGE => eku.any = true,
                        _ => {}
                    }
                }
                self.ext_key_usage = Some(eku);
            }
            oid::SUBJECT_ALT_NAME => {
                let seq = der::single(value, tag::SEQUENCE)?;
                self.subject_alt_name = Some(GeneralNames::parse(seq.value, false)?);
            }
            oid::NAME_CONSTRAINTS => {
                let mut s = der::single(value, tag::SEQUENCE).map(|e| Reader::new(e.value))?;
                let permitted = s.optional(0xA0)?.map(|e| e.value);
                let excluded = s.optional(0xA1)?.map(|e| e.value);
                s.finish()?;
                if permitted.is_none() && excluded.is_none() {
                    return Err(Error::Malformed);
                }
                for t in [permitted, excluded].into_iter().flatten() {
                    GeneralNames::parse(t, true)?;
                }
                self.name_constraints = Some(NameConstraints {
                    permitted,
                    excluded,
                });
            }
            oid::SUBJECT_KEY_ID => {
                self.subject_key_id = Some(der::single(value, tag::OCTET_STRING)?.value);
            }
            oid::AUTHORITY_KEY_ID => {
                let mut s = der::single(value, tag::SEQUENCE).map(|e| Reader::new(e.value))?;
                self.authority_key_id = s.optional(0x80)?.map(|e| e.value);
                // `authorityCertIssuer` [1] e `authorityCertSerialNumber` [2].
                s.optional(0xA1)?;
                s.optional(0x82)?;
                s.finish()?;
            }
            oid::TLS_FEATURE => {
                let mut s = der::single(value, tag::SEQUENCE).map(|e| Reader::new(e.value))?;
                while !s.is_empty() {
                    // 5 é `status_request` (RFC 7633, seção 4).
                    if der::small_uint(s.expect(tag::INTEGER)?.value) == Ok(5) {
                        self.must_staple = true;
                    }
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

/// BIT STRING do `keyUsage`: até 9 bits, bits não usados zerados.
fn key_usage_bits(value: &[u8]) -> Result<u16, Error> {
    let v = der::single(value, tag::BIT_STRING)?.value;
    let (&unused, bytes) = v.split_first().ok_or(Error::Malformed)?;
    let last = bytes.last().copied().unwrap_or(0);
    if unused > 7 || bytes.len() > 2 || (bytes.is_empty() && unused != 0) {
        return Err(Error::Malformed);
    }
    if last & ((1u8 << unused) - 1) != 0 {
        return Err(Error::Malformed);
    }
    let mut bits = 0u16;
    for (i, &b) in bytes.iter().enumerate() {
        bits |= u16::from(b.reverse_bits()) << (8 * i);
    }
    Ok(bits)
}
