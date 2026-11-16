//! O verificador contra assinaturas de verdade: as cadeias de teste do
//! `ox509` (ECDSA, RSA-PSS e Ed25519) e as intermediárias reais da Let's
//! Encrypt (RSA PKCS#1 v1.5 de 4096 bits e ECDSA P-384, que fica de fora).

use ox509::verify::{Anchors, ServerName, VerifyError, verify_server};
use ox509::{Certificate, Chain, SignatureAlgorithm};

use super::*;

macro_rules! der {
    ($f:literal) => {
        include_bytes!(concat!("../../ox509/testdata/", $f, ".der")) as &[u8]
    };
}

/// 2026-12-01: dentro da validade dos certificados de teste.
const NOW: i64 = 1_796_083_200;

fn chain(list: &[&[u8]], roots: &[&[u8]], name: ServerName<'_>) -> Result<(), VerifyError> {
    let roots = roots.concat();
    let a = Anchors::parse(&roots).unwrap();
    let c = Chain::parse(list.iter().copied()).unwrap();
    verify_server(&c, &a, name, NOW, &Optcrypt).map(|_| ())
}

#[test]
fn ecdsa_rsa_pss_e_ed25519_em_cadeias_inteiras() {
    // Raiz ECDSA → intermediária RSA 2048 (ECDSA/SHA-256) → folha (RSA-PSS).
    let dns = ServerName::Dns("optimus.test");
    assert_eq!(
        chain(
            &[der!("teste-leaf"), der!("teste-int")],
            &[der!("teste-root")],
            dns
        ),
        Ok(())
    );
    // Ed25519.
    assert_eq!(
        chain(
            &[der!("teste-edleaf")],
            &[der!("teste-edca")],
            ServerName::Dns("casa.lan")
        ),
        Ok(())
    );
    // Cadeia da CA do OCSP: ECDSA P-256 direto.
    assert_eq!(
        chain(
            &[der!("ocsp-folha-bom")],
            &[der!("ocsp-ca")],
            ServerName::Dns("ocsp.optimus.test")
        ),
        Ok(())
    );
}

#[test]
fn assinatura_adulterada_nao_passa() {
    let roots = der!("teste-root");
    for (leaf, name) in [
        (der!("teste-leaf"), "optimus.test"),
        (der!("teste-edleaf"), "casa.lan"),
    ] {
        let mut bad = leaf.to_vec();
        // O último byte do certificado está na assinatura.
        *bad.last_mut().unwrap() ^= 1;
        let anchors = if name == "casa.lan" {
            der!("teste-edca")
        } else {
            roots
        };
        let a = Anchors::parse(anchors).unwrap();
        let int = der!("teste-int");
        let c = Chain::parse([&bad[..], int]).unwrap();
        let r = verify_server(&c, &a, ServerName::Dns(name), NOW, &Optcrypt);
        assert!(r.is_err(), "{name}: {r:?}");
    }
}

#[test]
fn rsa_pkcs1_de_4096_bits() {
    // R11 (RSA) foi emitida pela raiz X1 (RSA 4096) com sha256WithRSA.
    let x1 = Certificate::parse(der!("isrg-root-x1")).unwrap();
    let r11 = Certificate::parse(der!("le-r11")).unwrap();
    assert_eq!(
        r11.signature_algorithm,
        SignatureAlgorithm::RsaPkcs1(ox509::Hash::Sha256)
    );
    assert!(Optcrypt.verify(
        r11.signature_algorithm,
        &x1.public_key,
        r11.tbs,
        r11.signature
    ));
    // O X1 também assina a si mesma.
    assert!(Optcrypt.verify(x1.signature_algorithm, &x1.public_key, x1.tbs, x1.signature));
    // Texto, assinatura ou chave trocados.
    let mut tbs = r11.tbs.to_vec();
    tbs[10] ^= 1;
    assert!(!Optcrypt.verify(r11.signature_algorithm, &x1.public_key, &tbs, r11.signature));
    let mut sig = r11.signature.to_vec();
    sig[0] ^= 1;
    assert!(!Optcrypt.verify(r11.signature_algorithm, &x1.public_key, r11.tbs, &sig));
    assert!(!Optcrypt.verify(
        r11.signature_algorithm,
        &r11.public_key,
        r11.tbs,
        r11.signature
    ));
}

#[test]
fn combinacao_que_nao_cabe_nao_passa() {
    let root = Certificate::parse(der!("teste-root")).unwrap();
    let int = Certificate::parse(der!("teste-int")).unwrap();
    // ECDSA com chave RSA, RSA com chave EC, algoritmo desconhecido.
    assert!(!Optcrypt.verify(
        root.signature_algorithm,
        &int.public_key,
        int.tbs,
        int.signature
    ));
    assert!(!Optcrypt.verify(
        SignatureAlgorithm::Ed25519,
        &root.public_key,
        int.tbs,
        int.signature
    ));
    assert!(!Optcrypt.verify(
        SignatureAlgorithm::Unsupported,
        &root.public_key,
        int.tbs,
        int.signature
    ));
}

#[test]
fn ocsp_de_verdade_com_o_verificador_real() {
    use ox509::ocsp::{OcspError, Status, validate};
    let ca = Certificate::parse(der!("ocsp-ca")).unwrap();
    let now = 1_794_825_558 + 86_400;
    for (leaf, resp, want) in [
        ("ocsp-folha-bom", "ocsp-resp-bom", Ok(Status::Good)),
        ("ocsp-folha-bom", "ocsp-resp-delegada", Ok(Status::Good)),
        (
            "ocsp-folha-revogado",
            "ocsp-resp-revogado",
            Ok(Status::Revoked {
                at: 1_794_739_145,
                reason: Some(1),
            }),
        ),
        (
            "ocsp-folha-bom",
            "ocsp-resp-estranho",
            Err(OcspError::BadSignature),
        ),
    ] {
        let leaf = std::fs::read(format!(
            "{}/../ox509/testdata/{leaf}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let resp = std::fs::read(format!(
            "{}/../ox509/testdata/{resp}.der",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let leaf = Certificate::parse(&leaf).unwrap();
        assert_eq!(validate(&resp, &leaf, &ca, now, &Optcrypt), want);
    }
}
