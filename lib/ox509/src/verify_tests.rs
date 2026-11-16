//! Testes da validação de cadeia. As assinaturas são conferidas por um
//! verificador de mentira que só aceita os pares (emissor, filho) que o
//! teste declara: a lógica de caminho fica testada sem cripto. O teste com
//! as primitivas do `optcrypt` entra com as T-623 a T-625.

use super::*;
use crate::{Certificate, Chain, Hash};

macro_rules! der {
    ($f:literal) => {
        include_bytes!(concat!("../testdata/teste-", $f, ".der")) as &[u8]
    };
}

const ROOT: &[u8] = der!("root");
const INT: &[u8] = der!("int");
const LEAF: &[u8] = der!("leaf");
const INT2: &[u8] = der!("int2");
const LEAF2: &[u8] = der!("leaf2");
const CLIENTE: &[u8] = der!("cliente");
const VITIMA: &[u8] = der!("vitima");
const EDCA: &[u8] = der!("edca");
const EDLEAF: &[u8] = der!("edleaf");
const EDMAU: &[u8] = der!("edmau");
const EDFORA: &[u8] = der!("edfora");
const EDCURINGA: &[u8] = der!("edcuringa");

/// 2026-12-01: dentro da validade de todos os certificados de teste.
const NOW: i64 = 1_796_083_200;

/// Aceita a assinatura se o par (chave do emissor, TBS do filho) foi
/// declarado.
struct Pairs(Vec<(Vec<u8>, Vec<u8>)>);

fn key_bytes(k: &PublicKey<'_>) -> Vec<u8> {
    match k {
        PublicKey::EcP256(b) | PublicKey::Ed25519(b) => b.to_vec(),
        PublicKey::Rsa { n, .. } => n.to_vec(),
        PublicKey::Unsupported => Vec::new(),
    }
}

impl Pairs {
    /// Cada par é (emissor, filho), em DER.
    fn new(pairs: &[(&[u8], &[u8])]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(i, c)| {
                    let i = Certificate::parse(i).unwrap();
                    let c = Certificate::parse(c).unwrap();
                    (key_bytes(&i.public_key), c.tbs.to_vec())
                })
                .collect(),
        )
    }

    fn all() -> Self {
        Self::new(&[
            (ROOT, ROOT),
            (ROOT, INT),
            (INT, LEAF),
            (INT, INT2),
            (INT, CLIENTE),
            (INT2, LEAF2),
            (LEAF, VITIMA),
            (EDCA, EDLEAF),
            (EDCA, EDMAU),
            (EDCA, EDFORA),
            (EDCA, EDCURINGA),
        ])
    }
}

impl SignatureVerifier for Pairs {
    fn verify(&self, _: SignatureAlgorithm, key: &PublicKey<'_>, msg: &[u8], _: &[u8]) -> bool {
        let k = key_bytes(key);
        self.0.iter().any(|(pk, tbs)| *pk == k && tbs == msg)
    }
}

fn anchors(list: &[&[u8]]) -> Vec<u8> {
    list.concat()
}

fn run(
    chain: &[&[u8]],
    roots: &[&[u8]],
    name: ServerName<'_>,
    now: i64,
) -> Result<(), VerifyError> {
    let roots = anchors(roots);
    let a = Anchors::parse(&roots).unwrap();
    let c = Chain::parse(chain.iter().copied()).unwrap();
    verify_server(&c, &a, name, now, &Pairs::all()).map(|_| ())
}

fn dns(s: &str) -> ServerName<'_> {
    ServerName::Dns(s)
}

#[test]
fn cadeia_boa_passa() {
    let roots = anchors(&[EDCA, ROOT]);
    let a = Anchors::parse(&roots).unwrap();
    let c = Chain::parse([LEAF, INT]).unwrap();
    let anchor = verify_server(&c, &a, dns("optimus.test"), NOW, &Pairs::all()).unwrap();
    assert_eq!(anchor.raw, ROOT);
    // Curinga, IP e caixa diferente.
    for n in [
        dns("www.optimus.test"),
        dns("OPTIMUS.Test"),
        ServerName::Ip(&[10, 0, 2, 2]),
    ] {
        assert_eq!(run(&[LEAF, INT], &[ROOT], n, NOW), Ok(()), "{n:?}");
    }
    // Ordem trocada e raiz entregue junto: o caminho é montado do mesmo jeito.
    assert_eq!(
        run(&[LEAF, ROOT, INT], &[ROOT], dns("optimus.test"), NOW),
        Ok(())
    );
    // Ed25519 com restrições de nome satisfeitas, inclusive curinga e IP.
    assert_eq!(run(&[EDLEAF], &[EDCA], dns("casa.lan"), NOW), Ok(()));
    assert_eq!(
        run(&[EDCURINGA], &[EDCA], dns("x.lan.casa.lan"), NOW),
        Ok(())
    );
}

#[test]
fn validade() {
    let leaf = Certificate::parse(LEAF).unwrap();
    let r = |now| run(&[LEAF, INT], &[ROOT], dns("optimus.test"), now);
    assert_eq!(r(leaf.not_before - 1), Err(VerifyError::NotYetValid));
    assert_eq!(r(leaf.not_after + 1), Err(VerifyError::Expired));
    assert_eq!(r(leaf.not_after), Ok(()));
    // A intermediária vence depois da folha; a raiz não é conferida.
    let int = Certificate::parse(INT).unwrap();
    assert!(int.not_after > leaf.not_after);
}

#[test]
fn nome_errado() {
    for n in [
        dns("outro.test"),
        dns("a.b.optimus.test"),
        dns("optimus.test.br"),
        ServerName::Ip(&[10, 0, 2, 3]),
    ] {
        assert_eq!(
            run(&[LEAF, INT], &[ROOT], n, NOW),
            Err(VerifyError::NameMismatch),
            "{n:?}"
        );
    }
    for n in [
        "optimus",
        "-a.test",
        "a..test",
        "a_b.test",
        "*.optimus.test",
        "",
    ] {
        assert_eq!(
            run(&[LEAF, INT], &[ROOT], dns(n), NOW),
            Err(VerifyError::BadServerName),
            "{n}"
        );
    }
}

#[test]
fn raiz_desconhecida_ou_intermediaria_faltando() {
    assert_eq!(
        run(&[LEAF, INT], &[EDCA], dns("optimus.test"), NOW),
        Err(VerifyError::UnknownIssuer)
    );
    assert_eq!(
        run(&[LEAF], &[ROOT], dns("optimus.test"), NOW),
        Err(VerifyError::UnknownIssuer)
    );
}

#[test]
fn assinatura_ruim() {
    let roots = anchors(&[ROOT]);
    let a = Anchors::parse(&roots).unwrap();
    let c = Chain::parse([LEAF, INT]).unwrap();
    let sem_folha = Pairs::new(&[(ROOT, INT)]);
    assert_eq!(
        verify_server(&c, &a, dns("optimus.test"), NOW, &sem_folha),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn folha_que_assina_outro_certificado() {
    // A folha não é CA: o que ela emite não vale, mesmo com assinatura boa.
    assert_eq!(
        run(
            &[VITIMA, LEAF, INT],
            &[ROOT],
            dns("vitima.optimus.test"),
            NOW
        ),
        Err(VerifyError::CaUsage)
    );
}

#[test]
fn path_len_estourado() {
    // A intermediária RSA tem `pathlen:0` e emitiu outra CA.
    assert_eq!(
        run(&[LEAF2, INT2, INT], &[ROOT], dns("fundo.optimus.test"), NOW),
        Err(VerifyError::PathLen)
    );
}

#[test]
fn uso_de_chave_de_cliente() {
    assert_eq!(
        run(&[CLIENTE, INT], &[ROOT], dns("optimus.test"), NOW),
        Err(VerifyError::ExtKeyUsage)
    );
}

#[test]
fn restricoes_de_nome() {
    assert_eq!(
        run(&[EDMAU], &[EDCA], dns("mau.lan"), NOW),
        Err(VerifyError::NameConstraints)
    );
    assert_eq!(
        run(&[EDFORA], &[EDCA], dns("casa.com"), NOW),
        Err(VerifyError::NameConstraints)
    );
}

#[test]
fn extensao_critica_desconhecida() {
    // keyUsage (crítica) da folha vira 2.5.29.99.
    let i = LEAF
        .windows(5)
        .position(|w| w == [0x06, 0x03, 0x55, 0x1D, 0x0F])
        .unwrap();
    let mut v = LEAF.to_vec();
    v[i + 4] = 0x63;
    assert_eq!(
        run(&[&v, INT], &[ROOT], dns("optimus.test"), NOW),
        Err(VerifyError::UnknownCriticalExtension)
    );
}

#[test]
fn algoritmo_e_chave() {
    let ec = Certificate::parse(ROOT).unwrap().public_key;
    let rsa = Certificate::parse(INT).unwrap().public_key;
    let ed = Certificate::parse(EDCA).unwrap().public_key;
    assert!(key_fits(SignatureAlgorithm::Ecdsa(Hash::Sha256), &ec));
    assert!(key_fits(SignatureAlgorithm::Ecdsa(Hash::Sha384), &ec));
    assert!(!key_fits(SignatureAlgorithm::Ecdsa(Hash::Sha512), &ec));
    assert!(key_fits(SignatureAlgorithm::RsaPss(Hash::Sha256), &rsa));
    assert!(!key_fits(SignatureAlgorithm::RsaPkcs1(Hash::Sha256), &ec));
    assert!(key_fits(SignatureAlgorithm::Ed25519, &ed));
    assert!(!key_fits(SignatureAlgorithm::Unsupported, &ed));
    let n = [0xFF; 128];
    assert!(!key_fits(
        SignatureAlgorithm::RsaPkcs1(Hash::Sha256),
        &PublicKey::Rsa { n: &n, e: &[3] }
    ));
    assert_eq!(rsa_bits(&[0x01, 0]), 9);
}

#[test]
fn nomes_dns() {
    assert!(dns_matches("*.a.b", "x.a.b"));
    assert!(!dns_matches("*.a.b", "a.b"));
    assert!(!dns_matches("*.b", "a.b"));
    assert!(!dns_matches("x*.a.b", "xy.a.b"));
    assert!(dns_subtree("a.lan", "lan"));
    assert!(!dns_subtree("alan", "lan"));
    assert!(dns_subtree("x", ""));
    let d = GeneralName::Dns;
    assert!(within(&d("lan"), &d("lan"), false));
    assert!(!within(&d("lan"), &d(".lan"), false));
    assert!(within(&d("a.lan"), &d(".lan"), false));
    // Curinga que cobre um nome excluído.
    assert!(within(&d("*.lan"), &d("mau.lan"), true));
    assert!(!within(&d("*.lan"), &d("mau.lan"), false));
    let ip = GeneralName::Ip;
    assert!(within(
        &ip(&[10, 9, 9, 9]),
        &ip(&[10, 0, 0, 0, 255, 0, 0, 0]),
        false
    ));
    assert!(!within(
        &ip(&[11, 0, 0, 1]),
        &ip(&[10, 0, 0, 0, 255, 0, 0, 0]),
        false
    ));
}

#[test]
fn ancoras() {
    let v = anchors(&[ROOT, EDCA]);
    let a = Anchors::parse(&v).unwrap();
    assert_eq!(a.iter().count(), 2);
    assert!(Anchors::parse(&v[..v.len() - 1]).is_err());
    assert_eq!(Anchors::parse(&[]).unwrap().iter().count(), 0);
}
