//! Linha de comando do `oidlc`. Hoje só checa a sintaxe dos arquivos.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("uso: oidlc <arquivo.oidl>...");
        return ExitCode::from(2);
    }
    let mut ok = true;
    for path in &paths {
        let src = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{path}: {e}");
                ok = false;
                continue;
            }
        };
        match oidlc::parse(&src) {
            Ok(_) => println!("{path}: ok"),
            Err(e) => {
                eprintln!("{path}:{e}");
                ok = false;
            }
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
