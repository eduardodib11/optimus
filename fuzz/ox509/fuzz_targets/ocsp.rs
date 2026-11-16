#![no_main]

//! Resposta OCSP arbitrária (T-655): a validação não pode entrar em pânico,
//! com a assinatura aceita (para exercitar tudo depois dela) e recusada. A
//! semente é `seeds/ocsp/`, cópia das respostas de `lib/ox509/testdata`.

use libfuzzer_sys::fuzz_target;
use ox509::ocsp::validate;
use ox509::verify::SignatureVerifier;
use ox509::{Certificate, PublicKey, SignatureAlgorithm};

const CA: &[u8] = include_bytes!("../../../lib/ox509/testdata/ocsp-ca.der");
const LEAF: &[u8] = include_bytes!("../../../lib/ox509/testdata/ocsp-folha-bom.der");

struct Always(bool);

impl SignatureVerifier for Always {
    fn verify(&self, _: SignatureAlgorithm, _: &PublicKey<'_>, _: &[u8], _: &[u8]) -> bool {
        self.0
    }
}

fuzz_target!(|data: &[u8]| {
    let leaf = Certificate::parse(LEAF).unwrap();
    let issuer = Certificate::parse(CA).unwrap();
    // Dentro e fora da validade das respostas semeadas.
    for now in [1_794_900_000, 2_100_000_000] {
        for sig in [true, false] {
            let _ = validate(data, &leaf, &issuer, now, &Always(sig));
        }
    }
});
