#![no_main]

//! Registro arbitrário aberto com chaves fixas, nas duas suítes: nem pânico
//! nem texto claro sem autenticação. O que é selado tem de abrir igual.

use libfuzzer_sys::fuzz_target;
use otls::Suite;
use otls::record::{HEADER_LEN, MAX_RECORD, RecordKeys, content, parse_header};

fn keys(suite: Suite) -> Option<RecordKeys> {
    RecordKeys::new(suite, &mut [0x11; 32], [0x22; 12])
}

fuzz_target!(|data: &[u8]| {
    if let Some(h) = data.first_chunk::<HEADER_LEN>() {
        let _ = parse_header(h);
    }
    for suite in [Suite::Chacha20Poly1305Sha256, Suite::Aes256GcmSha384] {
        let Some(mut k) = keys(suite) else { continue };
        let mut rec = data.to_vec();
        // Um registro aleatório não pode autenticar.
        assert!(k.open(&mut rec).is_err());
        // Ida e volta com o conteúdo do fuzz como texto claro.
        let (Some(mut s), Some(mut o)) = (keys(suite), keys(suite)) else {
            continue;
        };
        let kind = data
            .first()
            .map_or(content::APPLICATION_DATA, |b| 21 + b % 3);
        let pt = data.get(1..).unwrap_or_default();
        let mut buf = vec![0u8; MAX_RECORD];
        let n = pt.len().min(1 << 14);
        buf[HEADER_LEN..HEADER_LEN + n].copy_from_slice(&pt[..n]);
        let total = s.seal(kind, &mut buf, n).unwrap();
        let (k2, back) = o.open(&mut buf[..total]).unwrap();
        assert_eq!((k2, back), (kind, &pt[..n]));
    }
});
