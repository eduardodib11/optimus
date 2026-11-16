use super::*;
use ext::{GeneralName, key_usage};

const X1: &[u8] = include_bytes!("../testdata/isrg-root-x1.der");
const X2: &[u8] = include_bytes!("../testdata/isrg-root-x2.der");
const R11: &[u8] = include_bytes!("../testdata/le-r11.der");
const E7: &[u8] = include_bytes!("../testdata/le-e7.der");
const ROOT: &[u8] = include_bytes!("../testdata/teste-root.der");
const INT: &[u8] = include_bytes!("../testdata/teste-int.der");
const LEAF: &[u8] = include_bytes!("../testdata/teste-leaf.der");
const EDCA: &[u8] = include_bytes!("../testdata/teste-edca.der");
const EDLEAF: &[u8] = include_bytes!("../testdata/teste-edleaf.der");

const ALL: &[&[u8]] = &[X1, X2, R11, E7, ROOT, INT, LEAF, EDCA, EDLEAF];

#[test]
fn raiz_isrg_x1() {
    let c = Certificate::parse(X1).unwrap();
    assert_eq!(c.version, 3);
    assert_eq!(
        c.signature_algorithm,
        SignatureAlgorithm::RsaPkcs1(Hash::Sha256)
    );
    assert_eq!(c.issuer, c.subject);
    // 2015-06-04 11:04:38 e 2035-06-04 11:04:38 UTC.
    assert_eq!(c.not_before, 1_433_415_878);
    assert_eq!(c.not_after, 2_064_567_878);
    let PublicKey::Rsa { n, e } = c.public_key else {
        panic!("{:?}", c.public_key)
    };
    assert_eq!((n.len(), e), (512, &[1, 0, 1][..]));
    let bc = c.extensions.basic_constraints.unwrap();
    assert!(bc.ca && bc.path_len.is_none());
    assert_eq!(
        c.extensions.key_usage,
        Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN)
    );
    assert!(c.extensions.subject_key_id.is_some());
    assert!(!c.extensions.unknown_critical);
}

#[test]
fn raiz_x2_p384_e_lida_mas_nao_suportada() {
    let c = Certificate::parse(X2).unwrap();
    assert_eq!(c.public_key, PublicKey::Unsupported);
    assert_eq!(
        c.signature_algorithm,
        SignatureAlgorithm::Ecdsa(Hash::Sha384)
    );
}

#[test]
fn intermediarias_reais_apontam_para_a_raiz() {
    for (int, root) in [(R11, X1), (E7, X2)] {
        let i = Certificate::parse(int).unwrap();
        let r = Certificate::parse(root).unwrap();
        assert_eq!(i.issuer, r.subject);
        assert_eq!(i.extensions.authority_key_id, r.extensions.subject_key_id);
        let bc = i.extensions.basic_constraints.unwrap();
        assert_eq!((bc.ca, bc.path_len), (true, Some(0)));
        assert!(i.extensions.ext_key_usage.unwrap().server_auth);
    }
}

#[test]
fn folha_de_teste_com_pss_san_e_must_staple() {
    let c = Certificate::parse(LEAF).unwrap();
    assert_eq!(
        c.signature_algorithm,
        SignatureAlgorithm::RsaPss(Hash::Sha256)
    );
    assert!(matches!(c.public_key, PublicKey::EcP256(k) if k.len() == 65));
    assert_eq!(c.serial, &[0x00, 0xD1]);
    let e = c.extensions;
    assert!(e.must_staple);
    assert_eq!(e.key_usage, Some(key_usage::DIGITAL_SIGNATURE));
    assert!(!e.basic_constraints.unwrap().ca);
    let names: Vec<_> = e.subject_alt_name.unwrap().iter().collect();
    assert_eq!(
        names,
        [
            GeneralName::Dns("optimus.test"),
            GeneralName::Dns("*.optimus.test"),
            GeneralName::Ip(&[10, 0, 2, 2]),
            GeneralName::Ip(&[0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
        ]
    );
    assert_eq!(c.not_after - c.not_before, 365 * 86_400);
}

#[test]
fn cadeia_de_teste() {
    let chain = Chain::parse([LEAF, INT, ROOT]).unwrap();
    assert_eq!(chain.len(), 3);
    let v: Vec<_> = chain.iter().collect();
    assert_eq!(v[0].issuer, v[1].subject);
    assert_eq!(v[1].issuer, v[2].subject);
    assert!(matches!(v[1].public_key, PublicKey::Rsa { n, .. } if n.len() == 256));
    assert_eq!(
        v[2].signature_algorithm,
        SignatureAlgorithm::Ecdsa(Hash::Sha256)
    );
    assert_eq!(chain.leaf().raw, LEAF);
}

#[test]
fn ed25519_e_restricoes_de_nome() {
    let ca = Certificate::parse(EDCA).unwrap();
    assert_eq!(ca.signature_algorithm, SignatureAlgorithm::Ed25519);
    assert!(matches!(ca.public_key, PublicKey::Ed25519(k) if k.len() == 32));
    let nc = ca.extensions.name_constraints.unwrap();
    let p: Vec<_> = nc.permitted().unwrap().collect();
    assert_eq!(
        p,
        [
            GeneralName::Dns(".lan"),
            GeneralName::Ip(&[10, 0, 0, 0, 255, 0, 0, 0])
        ]
    );
    let x: Vec<_> = nc.excluded().unwrap().collect();
    assert_eq!(x, [GeneralName::Dns("mau.lan")]);
    let leaf = Certificate::parse(EDLEAF).unwrap();
    assert_eq!(leaf.signature_algorithm, SignatureAlgorithm::Ed25519);
    let eku = leaf.extensions.ext_key_usage.unwrap();
    assert!(eku.server_auth && !eku.any);
    assert!(leaf.extensions.basic_constraints.is_none());
}

#[test]
fn limites_da_cadeia() {
    assert_eq!(Chain::parse([]).unwrap_err(), Error::EmptyChain);
    assert_eq!(
        Chain::parse([LEAF; MAX_CHAIN + 1]).unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(Chain::parse([LEAF; MAX_CHAIN]).unwrap().len(), MAX_CHAIN);
    let mut ruim = LEAF.to_vec();
    ruim.push(0);
    assert_eq!(Chain::parse([LEAF, &ruim]).unwrap_err(), Error::Malformed);
}

#[test]
fn certificado_grande_demais() {
    let v = vec![0x30; MAX_CERT_LEN + 1];
    assert_eq!(Certificate::parse(&v).unwrap_err(), Error::TooLarge);
}

/// Nenhum prefixo nem byte trocado derruba o parser (o fuzzing faz o resto).
#[test]
fn truncados_e_mutados_nao_entram_em_panico() {
    for &der in ALL {
        for n in 0..der.len() {
            assert!(Certificate::parse(&der[..n]).is_err(), "prefixo {n}");
        }
        let mut m = der.to_vec();
        for i in 0..m.len() {
            for x in [0x01, 0x80, 0xFF] {
                m[i] ^= x;
                let _ = Certificate::parse(&m);
                m[i] ^= x;
            }
        }
    }
}

/// Troca a primeira ocorrência de `from` por `to` (mesmo tamanho).
fn patch(der: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let i = der.windows(from.len()).position(|w| w == from).unwrap();
    let mut v = der.to_vec();
    v[i..i + to.len()].copy_from_slice(to);
    v
}

#[test]
fn algoritmo_interno_diferente_do_externo() {
    // O OID ecdsa-with-SHA256 aparece primeiro no TBS; vira SHA-384 só lá.
    let v = patch(ROOT, oid::ECDSA_SHA256, oid::ECDSA_SHA384);
    assert_eq!(
        Certificate::parse(&v).unwrap_err(),
        Error::AlgorithmMismatch
    );
}

#[test]
fn extensao_repetida() {
    // keyUsage (55 1D 0F) vira basicConstraints (55 1D 13): duas iguais.
    let v = patch(
        ROOT,
        &[0x06, 0x03, 0x55, 0x1D, 0x0F],
        &[0x06, 0x03, 0x55, 0x1D, 0x13],
    );
    assert_eq!(
        Certificate::parse(&v).unwrap_err(),
        Error::DuplicateExtension
    );
}

#[test]
fn extensao_critica_desconhecida_fica_marcada() {
    // keyUsage (crítica) vira o OID 2.5.29.99, que ninguém conhece.
    let v = patch(
        ROOT,
        &[0x06, 0x03, 0x55, 0x1D, 0x0F],
        &[0x06, 0x03, 0x55, 0x1D, 0x63],
    );
    let c = Certificate::parse(&v).unwrap();
    assert!(c.extensions.unknown_critical);
    assert!(c.extensions.key_usage.is_none());
}

#[test]
fn versao_2_recusada() {
    let v = patch(
        LEAF,
        &[0xA0, 0x03, 0x02, 0x01, 0x02],
        &[0xA0, 0x03, 0x02, 0x01, 0x01],
    );
    assert_eq!(Certificate::parse(&v).unwrap_err(), Error::Version);
}

mod der_estrito {
    use super::super::Error;
    use super::super::der::*;

    fn one(b: &[u8]) -> Result<Tlv<'_>, Error> {
        let mut r = Reader::new(b);
        let e = r.any()?;
        r.finish()?;
        Ok(e)
    }

    #[test]
    fn comprimentos() {
        assert_eq!(one(&[0x04, 0x01, 0xAA]).unwrap().value, &[0xAA]);
        // Comprimento indefinido do BER.
        assert_eq!(one(&[0x30, 0x80, 0, 0]).unwrap_err(), Error::Malformed);
        // Forma longa onde a curta bastava.
        assert_eq!(
            one(&[0x04, 0x81, 0x01, 0xAA]).unwrap_err(),
            Error::Malformed
        );
        let mut v = vec![0x04, 0x82, 0x00, 0x80];
        v.extend([0; 0x80]);
        assert_eq!(one(&v).unwrap_err(), Error::Malformed);
        let mut v = vec![0x04, 0x81, 0x80];
        v.extend([0; 0x80]);
        assert_eq!(one(&v).unwrap().value.len(), 0x80);
        // Três bytes de comprimento passam do limite.
        assert_eq!(one(&[0x04, 0x83, 1, 0, 0]).unwrap_err(), Error::TooLarge);
        // Truncado e etiqueta longa.
        assert_eq!(one(&[0x04, 0x02, 0xAA]).unwrap_err(), Error::Malformed);
        assert_eq!(one(&[0x1F, 0x01, 0x00]).unwrap_err(), Error::Malformed);
    }

    #[test]
    fn inteiros_booleanos_e_oids() {
        assert!(integer(&[]).is_err());
        assert!(integer(&[0x00, 0x7F]).is_err());
        assert!(integer(&[0xFF, 0x80]).is_err());
        assert!(integer(&[0x00, 0x80]).is_ok());
        assert_eq!(small_uint(&[0x00]), Ok(0));
        assert_eq!(small_uint(&[0x01, 0x00]), Ok(256));
        assert_eq!(small_uint(&[0x80]), Err(Error::Malformed));
        assert_eq!(
            small_uint(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::TooLarge)
        );
        assert_eq!(boolean(&[0x01]), Err(Error::Malformed));
        assert_eq!(boolean(&[0xFF]), Ok(true));
        assert!(oid(&[0x2B, 0x65, 0x70]).is_ok());
        assert!(oid(&[]).is_err());
        assert!(oid(&[0x2B, 0x80, 0x01]).is_err());
        assert!(oid(&[0x2B, 0x81]).is_err());
        assert!(bit_string_bytes(&[0x01, 0xFE]).is_err());
    }

    fn t(tag: u8, s: &str) -> Result<i64, Error> {
        time(&Tlv {
            tag,
            value: s.as_bytes(),
            raw: &[],
        })
    }

    #[test]
    fn datas() {
        assert_eq!(t(0x17, "700101000000Z"), Ok(0));
        assert_eq!(t(0x17, "491231235959Z"), Ok(2_524_607_999));
        assert_eq!(t(0x17, "500101000000Z"), Ok(-631_152_000));
        assert_eq!(t(0x18, "20000229120000Z"), Ok(951_825_600));
        assert_eq!(t(0x18, "99991231235959Z"), Ok(253_402_300_799));
        for bad in [
            "19000229000000Z",
            "20231301000000Z",
            "20230431000000Z",
            "20230101240000Z",
            "20230101000060Z",
            "20230101000000+",
            "2023010100000Z",
            "2023010100000aZ",
        ] {
            assert!(t(0x18, bad).is_err(), "{bad}");
        }
        assert!(t(0x17, "7001010000Z").is_err());
        assert!(t(0x04, "700101000000Z").is_err());
    }
}
