#![no_main]

use acpid::{Limits, scan, table_body};
use libfuzzer_sys::fuzz_target;

// O AML vem do firmware: qualquer entrada deve terminar em `Ok` ou em um
// `Error`, nunca em pânico. Também exercita o `_CRS` de cada dispositivo e
// executa os métodos `_STA` e `_CRS`, com poucas operações por execução.
fuzz_target!(|data: &[u8]| {
    let aml = table_body(data).map_or(data, |(_, body)| body);
    let limits = Limits {
        max_ops: 4_000,
        ..Limits::default()
    };
    let _ = scan(aml, Limits::default(), |d| {
        let _ = d.resources().count();
        let _ = d.status(aml, data.len() % 2 == 0, limits);
        let _ = d
            .current_resources(aml, false, limits)
            .map(Iterator::count);
    });
});
