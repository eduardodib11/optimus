//! Validação de cadeia de servidor TLS (ADR 0071, itens 4, 5 e 7; T-651).
//!
//! Monta o caminho da folha até uma âncora usando só o que o servidor
//! entregou (sem AIA), em qualquer ordem, com orçamento fixo de assinaturas
//! conferidas. Cada elo confere validade, `basicConstraints` e profundidade,
//! `keyUsage`, `extKeyUsage serverAuth`, `nameConstraints` e extensões
//! críticas desconhecidas; a folha confere o nome do servidor só pelo
//! `subjectAltName` (sem CN). A âncora vale pela presença no conjunto: dela
//! só se aplicam as restrições de nome.
//!
//! A assinatura em si é de quem chama ([`SignatureVerifier`]): o `tlsd` liga
//! o `optcrypt`; esta camada só escolhe o algoritmo e a chave.

use crate::ext::{GeneralName, key_usage};
use crate::{Certificate, Chain, Error, MAX_CHAIN, PublicKey, SignatureAlgorithm};

/// Máximo de âncoras no conjunto.
pub const MAX_ANCHORS: usize = 512;
/// Máximo de assinaturas conferidas ao montar um caminho.
pub const SIGNATURE_BUDGET: usize = 32;
/// Faixa de tamanho de módulo RSA aceita, em bits (ADR 0071, item 1).
pub const RSA_BITS: core::ops::RangeInclusive<usize> = 2048..=4096;

/// Confere uma assinatura.
pub trait SignatureVerifier {
    /// `true` se `signature` sobre `message` vale para `key` com `alg`.
    /// Só é chamado com combinações aceitas pela ADR 0071.
    fn verify(
        &self,
        alg: SignatureAlgorithm,
        key: &PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

/// Motivo de a cadeia ser recusada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Certificado ilegível.
    Parse(Error),
    /// Fora da validade (`now` antes do início).
    NotYetValid,
    /// Fora da validade (`now` depois do fim).
    Expired,
    /// Nenhum caminho até uma âncora.
    UnknownIssuer,
    /// Assinatura inválida no único caminho possível.
    BadSignature,
    /// Algoritmo, curva ou tamanho de chave fora da ADR 0071.
    UnsupportedSignature,
    /// Emissor sem `basicConstraints` de CA, ou folha que é CA.
    CaUsage,
    /// `pathLenConstraint` estourado.
    PathLen,
    /// `keyUsage` sem o bit necessário.
    KeyUsage,
    /// `extKeyUsage` sem `serverAuth`.
    ExtKeyUsage,
    /// O nome pedido não está no `subjectAltName`.
    NameMismatch,
    /// Nome fora das restrições de uma CA, ou restrição que não sabemos
    /// avaliar.
    NameConstraints,
    /// Extensão crítica desconhecida.
    UnknownCriticalExtension,
    /// Nome do servidor mal formado.
    BadServerName,
}

impl From<Error> for VerifyError {
    fn from(e: Error) -> Self {
        Self::Parse(e)
    }
}

/// Nome que o cliente pediu (ADR 0070, item 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerName<'a> {
    /// Nome DNS, ASCII (rótulos IDNA já convertidos).
    Dns(&'a str),
    /// Endereço IPv4 (4 bytes) ou IPv6 (16 bytes).
    Ip(&'a [u8]),
}

/// Conjunto de âncoras: certificados DER concatenados (`data/trust/roots.der`).
#[derive(Clone, Copy, Debug)]
pub struct Anchors<'a> {
    data: &'a [u8],
}

impl<'a> Anchors<'a> {
    /// Confere que `data` é uma sequência de certificados legíveis.
    ///
    /// # Errors
    ///
    /// O erro do primeiro certificado ilegível, ou `TooLarge` acima de
    /// [`MAX_ANCHORS`].
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let mut r = crate::der::Reader::new(data);
        let mut n = 0;
        while !r.is_empty() {
            Certificate::parse(r.any()?.raw)?;
            n += 1;
            if n > MAX_ANCHORS {
                return Err(Error::TooLarge);
            }
        }
        Ok(Self { data })
    }

    /// As âncoras, em ordem.
    pub fn iter(&self) -> impl Iterator<Item = Certificate<'a>> + 'a {
        let mut r = crate::der::Reader::new(self.data);
        // Já conferido em `parse`.
        core::iter::from_fn(move || Certificate::parse(r.any().ok()?.raw).ok())
    }
}

/// Valida `chain` (folha primeiro) para `name` no instante `now` (segundos
/// desde 1970, do `timed`). Devolve a âncora do caminho aceito.
///
/// # Errors
///
/// Ver [`VerifyError`]. Com mais de um caminho possível, devolve o erro do
/// caminho que chegou mais perto da âncora.
pub fn verify_server<'a>(
    chain: &Chain<'_>,
    anchors: &Anchors<'a>,
    name: ServerName<'_>,
    now: i64,
    v: &impl SignatureVerifier,
) -> Result<Certificate<'a>, VerifyError> {
    let leaf = chain.leaf();
    check_name(name)?;
    check_validity(leaf, now)?;
    if leaf.extensions.unknown_critical {
        return Err(VerifyError::UnknownCriticalExtension);
    }
    if leaf.extensions.basic_constraints.is_some_and(|b| b.ca) {
        return Err(VerifyError::CaUsage);
    }
    if leaf
        .extensions
        .key_usage
        .is_some_and(|k| k & key_usage::DIGITAL_SIGNATURE == 0)
    {
        return Err(VerifyError::KeyUsage);
    }
    if leaf
        .extensions
        .ext_key_usage
        .is_some_and(|e| !e.server_auth)
    {
        return Err(VerifyError::ExtKeyUsage);
    }
    if !san_matches(leaf, name) {
        return Err(VerifyError::NameMismatch);
    }
    let mut search = Search {
        chain,
        anchors,
        now,
        v,
        path: [*leaf; MAX_CHAIN],
        budget: SIGNATURE_BUDGET,
        best: (0, VerifyError::UnknownIssuer),
    };
    search.extend(1).ok_or(search.best.1)
}

struct Search<'c, 'a, 'p, V> {
    chain: &'p Chain<'c>,
    anchors: &'p Anchors<'a>,
    now: i64,
    v: &'p V,
    /// `path[0]` é a folha; `path[..len]` é o caminho atual.
    path: [Certificate<'c>; MAX_CHAIN],
    budget: usize,
    /// Erro do caminho mais longo que falhou.
    best: (usize, VerifyError),
}

impl<'a, V: SignatureVerifier> Search<'_, 'a, '_, V> {
    fn fail(&mut self, len: usize, e: VerifyError) {
        if len >= self.best.0 {
            self.best = (len, e);
        }
    }

    /// Procura emissor para `path[len - 1]`: primeiro as âncoras, depois as
    /// intermediárias entregues. Recursão limitada a [`MAX_CHAIN`] níveis.
    fn extend(&mut self, len: usize) -> Option<Certificate<'a>> {
        let child = self.path[len - 1];
        for anchor in self.anchors.iter() {
            if anchor.subject != child.issuer || !key_ids_match(&child, &anchor) {
                continue;
            }
            match self.link(&child, &anchor) {
                Ok(()) => match self.constraints(len, &anchor) {
                    Ok(()) => return Some(anchor),
                    Err(e) => self.fail(len, e),
                },
                Err(e) => self.fail(len, e),
            }
            if self.budget == 0 {
                return None;
            }
        }
        if len == MAX_CHAIN {
            self.fail(len, VerifyError::Parse(Error::TooLarge));
            return None;
        }
        for cand in self.chain.iter().skip(1) {
            if cand.subject != child.issuer || !key_ids_match(&child, cand) {
                continue;
            }
            // Um certificado não aparece duas vezes no caminho.
            if self.path[..len].iter().any(|p| p.raw == cand.raw) {
                continue;
            }
            let step = self
                .link(&child, cand)
                .and_then(|()| self.issuer_checks(len, cand))
                .and_then(|()| self.constraints(len, cand));
            match step {
                Ok(()) => {
                    self.path[len] = *cand;
                    if let Some(a) = self.extend(len + 1) {
                        return Some(a);
                    }
                }
                Err(e) => self.fail(len, e),
            }
            if self.budget == 0 {
                return None;
            }
        }
        None
    }

    /// Assinatura de `issuer` sobre `child`.
    fn link(
        &mut self,
        child: &Certificate<'_>,
        issuer: &Certificate<'_>,
    ) -> Result<(), VerifyError> {
        let alg = child.signature_algorithm;
        if !key_fits(alg, &issuer.public_key) {
            return Err(VerifyError::UnsupportedSignature);
        }
        if self.budget == 0 {
            return Err(VerifyError::UnknownIssuer);
        }
        self.budget -= 1;
        if self
            .v
            .verify(alg, &issuer.public_key, child.tbs, child.signature)
        {
            Ok(())
        } else {
            Err(VerifyError::BadSignature)
        }
    }

    /// Regras de CA intermediária (não âncora) em `path[len]`.
    fn issuer_checks(&self, len: usize, ca: &Certificate<'_>) -> Result<(), VerifyError> {
        check_validity(ca, self.now)?;
        let e = &ca.extensions;
        if e.unknown_critical {
            return Err(VerifyError::UnknownCriticalExtension);
        }
        let bc = match e.basic_constraints {
            Some(b) if b.ca && ca.version == 3 => b,
            _ => return Err(VerifyError::CaUsage),
        };
        if e.key_usage
            .is_some_and(|k| k & key_usage::KEY_CERT_SIGN == 0)
        {
            return Err(VerifyError::KeyUsage);
        }
        if e.ext_key_usage.is_some_and(|k| !k.server_auth && !k.any) {
            return Err(VerifyError::ExtKeyUsage);
        }
        // Intermediárias abaixo desta: `path[1..len]`, menos as auto-emitidas.
        let below = self.path[1..len]
            .iter()
            .filter(|c| c.issuer != c.subject)
            .count();
        if bc.path_len.is_some_and(|p| below > usize::from(p)) {
            return Err(VerifyError::PathLen);
        }
        Ok(())
    }

    /// Restrições de nome de `ca` sobre a folha e as intermediárias abaixo.
    fn constraints(&self, len: usize, ca: &Certificate<'_>) -> Result<(), VerifyError> {
        let Some(nc) = ca.extensions.name_constraints else {
            return Ok(());
        };
        let all = nc
            .permitted()
            .into_iter()
            .flatten()
            .chain(nc.excluded().into_iter().flatten());
        if all
            .into_iter()
            .any(|g| !matches!(g, GeneralName::Dns(_) | GeneralName::Ip(_)))
        {
            // Só DNS e IP são avaliados; o resto falha fechado.
            return Err(VerifyError::NameConstraints);
        }
        for cert in &self.path[..len] {
            let Some(san) = cert.extensions.subject_alt_name else {
                continue;
            };
            for name in san.iter() {
                let permitted = nc.permitted().map(|mut p| {
                    let mut same_kind = false;
                    let ok = p.any(|c| {
                        same_kind |= core::mem::discriminant(&c) == core::mem::discriminant(&name);
                        within(&name, &c, false)
                    });
                    ok || !same_kind
                });
                let excluded = nc
                    .excluded()
                    .is_some_and(|mut x| x.any(|c| within(&name, &c, true)));
                if permitted == Some(false) || excluded {
                    return Err(VerifyError::NameConstraints);
                }
            }
        }
        Ok(())
    }
}

/// O `keyIdentifier` do AKI do filho, se houver, bate com o SKI do emissor.
fn key_ids_match(child: &Certificate<'_>, issuer: &Certificate<'_>) -> bool {
    match (
        child.extensions.authority_key_id,
        issuer.extensions.subject_key_id,
    ) {
        (Some(a), Some(s)) => a == s,
        _ => true,
    }
}

fn check_validity(c: &Certificate<'_>, now: i64) -> Result<(), VerifyError> {
    if now < c.not_before {
        Err(VerifyError::NotYetValid)
    } else if now > c.not_after {
        Err(VerifyError::Expired)
    } else {
        Ok(())
    }
}

/// Combinações de algoritmo e chave da ADR 0071, item 1 (o `tlsd` usa no
/// `CertificateVerify`).
#[must_use]
pub fn key_fits(alg: SignatureAlgorithm, key: &PublicKey<'_>) -> bool {
    match (alg, key) {
        (SignatureAlgorithm::Ecdsa(h), PublicKey::EcP256(_)) => h != crate::Hash::Sha512,
        (
            SignatureAlgorithm::RsaPkcs1(_) | SignatureAlgorithm::RsaPss(_),
            PublicKey::Rsa { n, .. },
        ) => RSA_BITS.contains(&rsa_bits(n)),
        (SignatureAlgorithm::Ed25519, PublicKey::Ed25519(_)) => true,
        _ => false,
    }
}

/// Bits do módulo (sem zeros à esquerda, como `PublicKey::Rsa` guarda).
fn rsa_bits(n: &[u8]) -> usize {
    n.first()
        .map_or(0, |&b| n.len() * 8 - b.leading_zeros() as usize)
}

/// Nome DNS de referência: rótulos de 1 a 63 letras, dígitos ou hífen, sem
/// hífen nas pontas, até 253 bytes, pelo menos dois rótulos.
fn check_name(name: ServerName<'_>) -> Result<(), VerifyError> {
    let ok = match name {
        ServerName::Ip(ip) => ip.len() == 4 || ip.len() == 16,
        ServerName::Dns(d) => {
            d.len() <= 253
                && d.contains('.')
                && d.split('.').all(|l| {
                    (1..=63).contains(&l.len())
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        }
    };
    if ok {
        Ok(())
    } else {
        Err(VerifyError::BadServerName)
    }
}

fn san_matches(leaf: &Certificate<'_>, name: ServerName<'_>) -> bool {
    let Some(san) = leaf.extensions.subject_alt_name else {
        return false;
    };
    san.iter().any(|g| match (g, name) {
        (GeneralName::Dns(p), ServerName::Dns(r)) => dns_matches(p, r),
        (GeneralName::Ip(p), ServerName::Ip(r)) => p == r,
        _ => false,
    })
}

/// Nome apresentado contra o de referência (RFC 6125): sem diferença de
/// caixa; curinga só como rótulo inteiro mais à esquerda, cobrindo um
/// rótulo, e com pelo menos dois rótulos depois dele.
fn dns_matches(presented: &str, reference: &str) -> bool {
    match presented.strip_prefix("*.") {
        Some(base) => {
            base.split('.').count() >= 2
                && !base.contains('*')
                && reference
                    .split_once('.')
                    .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(base))
        }
        None => !presented.contains('*') && presented.eq_ignore_ascii_case(reference),
    }
}

/// `name` está dentro da subárvore `c` (RFC 5280, 4.2.1.10). Com
/// `overlap`, um curinga conta se qualquer nome que ele cobre cair na
/// subárvore (para as exclusões).
fn within(name: &GeneralName<'_>, c: &GeneralName<'_>, overlap: bool) -> bool {
    match (name, c) {
        (GeneralName::Dns(n), GeneralName::Dns(c)) => match n.strip_prefix("*.") {
            Some(base) => {
                // Os nomes cobertos são `x.base`: estão na subárvore se
                // `base` estiver, ou (nas exclusões) se a subárvore estiver
                // abaixo de `base`.
                dns_subtree(base, c.trim_start_matches('.'))
                    || (overlap && dns_subtree(c.trim_start_matches('.'), base))
            }
            None => match c.strip_prefix('.') {
                Some(c) => n.len() > c.len() && dns_subtree(n, c),
                None => dns_subtree(n, c),
            },
        },
        (GeneralName::Ip(n), GeneralName::Ip(c)) if c.len() == 2 * n.len() => {
            let (addr, mask) = c.split_at(n.len());
            n.iter()
                .zip(addr)
                .zip(mask)
                .all(|((n, a), m)| n & m == a & m)
        }
        _ => false,
    }
}

/// `n` é `c` ou um subdomínio dele (sem diferença de caixa). `c` vazio
/// cobre tudo.
fn dns_subtree(n: &str, c: &str) -> bool {
    if c.is_empty() {
        return true;
    }
    if n.len() < c.len() {
        return false;
    }
    let (head, tail) = n.split_at(n.len() - c.len());
    tail.eq_ignore_ascii_case(c) && (head.is_empty() || head.ends_with('.'))
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
