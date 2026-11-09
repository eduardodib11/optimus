#![no_main]

use acpid::{Limits, scan, table_body};
use libfuzzer_sys::fuzz_target;

// O AML vem do firmware: qualquer entrada deve terminar em `Ok` ou em um
// `Error`, nunca em pânico. Também exercita o `_CRS` de cada dispositivo.
fuzz_target!(|data: &[u8]| {
    let aml = table_body(data).map_or(data, |(_, body)| body);
    let _ = scan(aml, Limits::default(), |d| {
        let _ = d.resources().count();
    });
});
