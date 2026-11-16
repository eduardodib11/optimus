#![no_main]

//! Certificado arbitrário: o parser não pode entrar em pânico, e tudo o que
//! ele aceita tem de ser percorrível (nomes, restrições, cadeia). A semente
//! é `seeds/cert/`, cópia de `lib/ox509/testdata`; o noturno a copia para
//! `corpus/cert/` antes de rodar.

use libfuzzer_sys::fuzz_target;
use ox509::{Certificate, Chain};

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = Certificate::parse(data) {
        assert!(c.tbs.len() < c.raw.len() && c.spki.len() < c.tbs.len());
        assert!(c.not_before >= -62_167_219_200 && c.not_after <= 253_402_300_799);
        if let Some(san) = c.extensions.subject_alt_name {
            assert!(san.iter().count() > 0);
        }
        if let Some(nc) = c.extensions.name_constraints {
            let p = nc.permitted().map_or(0, Iterator::count);
            let x = nc.excluded().map_or(0, Iterator::count);
            assert!(p + x > 0);
        }
    }
    // A mesma entrada partida ao meio, como cadeia de dois.
    let (a, b) = data.split_at(data.len() / 2);
    let _ = Chain::parse([a, b]);
});
