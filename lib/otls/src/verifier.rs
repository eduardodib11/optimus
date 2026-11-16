//! O [`SignatureVerifier`] do `tlsd` sobre o `optcrypt` (T-651, parte 3).
//!
//! Serve às duas pontas: a assinatura de cada elo da cadeia (`message` é o
//! `TBSCertificate`) e o `CertificateVerify` (`message` é o texto assinado da
//! seção 4.4.3). O `ox509` já escolheu o algoritmo e filtrou chave e
//! combinação (`key_fits`); aqui só se calcula o hash do algoritmo e se
//! chama a primitiva. Só verificação, dados públicos.

use optcrypt::rsa;
use ox509::verify::SignatureVerifier;
use ox509::{Hash, PublicKey, SignatureAlgorithm};

/// Verificador com as primitivas do `optcrypt`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Optcrypt;

fn rsa_hash(h: Hash) -> rsa::Hash {
    match h {
        Hash::Sha256 => rsa::Hash::Sha256,
        Hash::Sha384 => rsa::Hash::Sha384,
        Hash::Sha512 => rsa::Hash::Sha512,
    }
}

impl SignatureVerifier for Optcrypt {
    fn verify(
        &self,
        alg: SignatureAlgorithm,
        key: &PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        match (alg, key) {
            (SignatureAlgorithm::Ecdsa(h), PublicKey::EcP256(pk)) => {
                let d = rsa_hash(h).digest(&[message]);
                optcrypt::p256::verify_der(pk, &d[..rsa_hash(h).out_len()], signature)
            }
            (SignatureAlgorithm::RsaPkcs1(h), PublicKey::Rsa { n, e }) => {
                let h = rsa_hash(h);
                rsa::PublicKey::new(n, e).is_ok_and(|k| {
                    k.verify_pkcs1v15(h, &h.digest(&[message])[..h.out_len()], signature)
                })
            }
            // Sal do tamanho do hash (ADR 0071; o `ox509` só lê esse perfil
            // e o TLS 1.3 o exige no `rsa_pss_rsae_*`).
            (SignatureAlgorithm::RsaPss(h), PublicKey::Rsa { n, e }) => {
                let h = rsa_hash(h);
                rsa::PublicKey::new(n, e).is_ok_and(|k| {
                    k.verify_pss(
                        h,
                        &h.digest(&[message])[..h.out_len()],
                        signature,
                        h.out_len(),
                    )
                })
            }
            (SignatureAlgorithm::Ed25519, PublicKey::Ed25519(pk)) => {
                match (<&[u8; 32]>::try_from(*pk), <&[u8; 64]>::try_from(signature)) {
                    (Ok(pk), Ok(sig)) => optcrypt::ed25519::verify(pk, message, sig),
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

#[cfg(test)]
#[path = "verifier_tests.rs"]
mod tests;
