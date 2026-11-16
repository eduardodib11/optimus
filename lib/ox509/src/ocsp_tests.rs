//! Testes da resposta OCSP com respostas de verdade, geradas com o OpenSSL
//! 3.0 (`testdata/gerar-ocsp.sh`) e conferidas com a ECDSA P-256 do
//! `optcrypt`: o que falha aqui falha pela assinatura de fato.

use super::*;
use crate::{Certificate, Hash};

macro_rules! der {
    ($f:literal) => {
        include_bytes!(concat!("../testdata/ocsp-", $f, ".der")) as &[u8]
    };
}

const CA: &[u8] = der!("ca");
const BOM: &[u8] = der!("folha-bom");
const REVOGADO: &[u8] = der!("folha-revogado");
const MS: &[u8] = der!("folha-ms");
const DESCONHECIDO: &[u8] = der!("folha-desconhecido");
const R_BOM: &[u8] = der!("resp-bom");
const R_REVOGADO: &[u8] = der!("resp-revogado");
const R_MS: &[u8] = der!("resp-ms");
const R_DELEGADA: &[u8] = der!("resp-delegada");
const R_DESCONHECIDO: &[u8] = der!("resp-desconhecido");
const R_CURTA: &[u8] = der!("resp-curta");
const R_ESTRANHO: &[u8] = der!("resp-estranho");
/// Outra CA, que não emitiu nada daqui.
const OUTRA_CA: &[u8] = include_bytes!("../testdata/teste-root.der");

/// 2026-11-15 10:39:05Z, a revogação do `folha-revogado`.
const REVOKED_AT: i64 = 1_794_739_145;
/// 2026-11-16 10:39:18Z, o `thisUpdate` de todas as respostas.
const THIS_UPDATE: i64 = 1_794_825_558;
/// Um dia depois: as respostas valem (a `curta` dura uma hora).
const NOW: i64 = THIS_UPDATE + 86_400;

/// ECDSA P-256 e SHA-256 de verdade, a única combinação dos testes.
struct Real;

impl SignatureVerifier for Real {
    fn verify(
        &self,
        alg: SignatureAlgorithm,
        key: &crate::PublicKey<'_>,
        msg: &[u8],
        sig: &[u8],
    ) -> bool {
        match (alg, key) {
            (SignatureAlgorithm::Ecdsa(Hash::Sha256), crate::PublicKey::EcP256(pk)) => {
                optcrypt::p256::verify_sha256(pk, msg, sig)
            }
            _ => false,
        }
    }
}

fn check(resp: &[u8], leaf: &[u8], issuer: &[u8], now: i64) -> Result<Status, OcspError> {
    let leaf = Certificate::parse(leaf).unwrap();
    let issuer = Certificate::parse(issuer).unwrap();
    validate(resp, &leaf, &issuer, now, &Real)
}

#[test]
fn bom_e_assinado_pelo_emissor() {
    assert_eq!(check(R_BOM, BOM, CA, NOW), Ok(Status::Good));
    assert_eq!(check(R_MS, MS, CA, NOW), Ok(Status::Good));
}

#[test]
fn revogado_traz_instante_e_motivo() {
    assert_eq!(
        check(R_REVOGADO, REVOGADO, CA, NOW),
        Ok(Status::Revoked {
            at: REVOKED_AT,
            reason: Some(1)
        })
    );
}

#[test]
fn desconhecido_e_dito_como_tal() {
    assert_eq!(
        check(R_DESCONHECIDO, DESCONHECIDO, CA, NOW),
        Ok(Status::Unknown)
    );
}

#[test]
fn respondedor_delegado_do_emissor() {
    assert_eq!(check(R_DELEGADA, BOM, CA, NOW), Ok(Status::Good));
    // Outro emissor: o delegado não é dele.
    assert_eq!(
        check(R_DELEGADA, BOM, OUTRA_CA, NOW),
        Err(OcspError::UnauthorizedSigner)
    );
    // O respondedor fora da validade não vale (um ano e meio depois).
    assert_eq!(
        check(R_DELEGADA, BOM, CA, THIS_UPDATE + 550 * 86_400),
        Err(OcspError::UnauthorizedSigner)
    );
}

#[test]
fn assinatura_de_quem_nao_e_o_emissor() {
    assert_eq!(
        check(R_ESTRANHO, BOM, CA, NOW),
        Err(OcspError::BadSignature)
    );
}

#[test]
fn resposta_de_outro_certificado() {
    assert_eq!(check(R_BOM, REVOGADO, CA, NOW), Err(OcspError::NoMatch));
    assert_eq!(check(R_REVOGADO, BOM, CA, NOW), Err(OcspError::NoMatch));
}

#[test]
fn validade_da_resposta() {
    // `curta`: nextUpdate uma hora depois do thisUpdate.
    assert_eq!(
        check(R_CURTA, BOM, CA, THIS_UPDATE + 1800),
        Ok(Status::Good)
    );
    assert_eq!(
        check(R_CURTA, BOM, CA, THIS_UPDATE + 3700),
        Err(OcspError::Stale)
    );
    // No futuro, passada a folga do relógio.
    assert_eq!(
        check(R_BOM, BOM, CA, THIS_UPDATE - SKEW - 5),
        Err(OcspError::NotYetValid)
    );
    assert_eq!(
        check(R_BOM, BOM, CA, THIS_UPDATE - SKEW + 5),
        Ok(Status::Good)
    );
}

/// 2026-11-16 10:41:36Z, o `thisUpdate` da resposta sem `nextUpdate`.
const SEM_NEXT_UPDATE: i64 = 1_794_825_696;

#[test]
fn sem_next_update_vale_por_sete_dias() {
    let resp = der!("resp-sem-next");
    let ok = SEM_NEXT_UPDATE + MAX_AGE;
    assert_eq!(check(resp, BOM, CA, ok), Ok(Status::Good));
    assert_eq!(check(resp, BOM, CA, ok + 1), Err(OcspError::Stale));
}

#[test]
fn resposta_que_nao_e_sucesso() {
    // `tryLater` (3), sem `responseBytes`.
    let r = [0x30, 0x03, 0x0A, 0x01, 0x03];
    assert_eq!(check(&r, BOM, CA, NOW), Err(OcspError::Unsuccessful(3)));
}

#[test]
fn tipo_de_resposta_desconhecido() {
    let mut r = R_BOM.to_vec();
    let at = r
        .windows(oid::OCSP_BASIC.len())
        .position(|w| w == oid::OCSP_BASIC)
        .unwrap();
    r[at + oid::OCSP_BASIC.len() - 1] = 2;
    assert_eq!(check(&r, BOM, CA, NOW), Err(OcspError::BadType));
}

#[test]
fn resposta_grande_demais() {
    let r = vec![0u8; MAX_RESPONSE + 1];
    assert_eq!(
        check(&r, BOM, CA, NOW),
        Err(OcspError::Parse(Error::TooLarge))
    );
}

#[test]
fn mudar_qualquer_byte_assinado_derruba_a_resposta() {
    let leaf = Certificate::parse(BOM).unwrap();
    let p = parse(R_BOM, leaf.serial).unwrap();
    let from = p.tbs.as_ptr() as usize - R_BOM.as_ptr() as usize;
    for i in from..from + p.tbs.len() {
        let mut r = R_BOM.to_vec();
        r[i] ^= 0x01;
        assert!(check(&r, BOM, CA, NOW).is_err(), "byte {i}");
    }
}

#[test]
fn assinatura_adulterada_ou_truncada() {
    let leaf = Certificate::parse(BOM).unwrap();
    let p = parse(R_BOM, leaf.serial).unwrap();
    let at = p.signature.as_ptr() as usize - R_BOM.as_ptr() as usize;
    for i in at..at + p.signature.len() {
        let mut r = R_BOM.to_vec();
        r[i] ^= 0x80;
        assert!(check(&r, BOM, CA, NOW).is_err(), "byte {i}");
    }
}

#[test]
fn entrada_ruim_nao_derruba_nem_passa() {
    for resp in [R_BOM, R_DELEGADA, R_REVOGADO] {
        // Todo prefixo é recusado.
        for n in 0..resp.len() {
            assert!(check(&resp[..n], BOM, CA, NOW).is_err(), "prefixo {n}");
        }
        // Nenhum byte trocado derruba o teste; e um 0x00 no lugar de
        // um byte assinado nunca vira `Good` por engano.
        for i in 0..resp.len() {
            let mut r = resp.to_vec();
            r[i] ^= 0xFF;
            let _ = check(&r, BOM, CA, NOW);
        }
    }
}

#[test]
fn certificado_malformado_no_respondedor() {
    // O certificado do respondedor com o fim cortado: a resposta toda é
    // recusada, não ignorada (só vale a pena olhar o `certs` se a
    // assinatura direta falhou, como na `estranho`).
    let mut r = R_DELEGADA.to_vec();
    let leaf = Certificate::parse(BOM).unwrap();
    let issuer = Certificate::parse(CA).unwrap();
    let cert = Certificate::parse(der!("respondedor")).unwrap();
    let at = r
        .windows(cert.raw.len())
        .position(|w| w == cert.raw)
        .unwrap();
    // Troca a etiqueta da SEQUENCE do certificado por INTEGER.
    r[at] = 0x02;
    assert!(matches!(
        validate(&r, &leaf, &issuer, NOW, &Real),
        Err(OcspError::Parse(_))
    ));
}
