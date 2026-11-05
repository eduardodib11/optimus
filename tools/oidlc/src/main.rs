//! Linha de comando do `oidlc`.
//!
//! - `oidlc <arquivo.oidl>...`: checa sintaxe e semântica.
//! - `oidlc check-compat <velho.oidl> <novo.oidl>`: checa a compatibilidade
//!   entre duas versões (ADR 0033, seção 8).

#![forbid(unsafe_code)]

use std::process::ExitCode;

use oidlc::ast::File;
use oidlc::lexer::Error;

fn carrega(path: &str) -> Result<File, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    oidlc::parse(&src).map_err(|e| format!("{path}:{e}"))
}

fn checa(path: &str) -> bool {
    let file = match carrega(path) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{msg}");
            return false;
        }
    };
    let mut erros = oidlc::analyze(&file);
    if erros.is_empty() {
        // Layout só faz sentido sobre um arquivo semanticamente correto.
        erros = oidlc::layout::Layouts::new(&file)
            .confere_tamanhos()
            .into_iter()
            .map(|e| oidlc::lexer::Error {
                pos: e.pos,
                msg: e.msg,
            })
            .collect();
    }
    if erros.is_empty() {
        println!("{path}: ok");
        return true;
    }
    for e in &erros {
        eprintln!("{path}:{e}");
    }
    false
}

fn compat(velho: &str, novo: &str) -> bool {
    let (a, b) = match (carrega(velho), carrega(novo)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(m), _) | (_, Err(m)) => {
            eprintln!("{m}");
            return false;
        }
    };
    let erros: Vec<Error> = oidlc::check_compat(&a, &b);
    if erros.is_empty() {
        println!("{velho} -> {novo}: compatível");
        return true;
    }
    for e in &erros {
        eprintln!("{novo}:{e}");
    }
    false
}

/// Roda o fuzzer por `secs` segundos com a semente `seed` (T-347).
fn fuzz(secs: &str, seed: &str) -> bool {
    let (Ok(secs), Ok(seed)) = (
        secs.parse::<u64>(),
        u64::from_str_radix(seed.trim_start_matches("0x"), 16),
    ) else {
        eprintln!("uso: oidlc fuzz <segundos> <semente hex>");
        return false;
    };
    match oidlc::fuzz::roda(secs, seed) {
        Ok(n) => {
            println!("oidlc fuzz: {n} execuções sem falha");
            true
        }
        Err(msg) => {
            eprintln!("{msg}");
            false
        }
    }
}

/// Imprime os esquemas JSON das ferramentas (`@tool`) de `arq` (T-346).
fn esquemas(arq: &str) -> bool {
    let file = match carrega(arq) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{msg}");
            return false;
        }
    };
    let erros = oidlc::analyze(&file);
    if !erros.is_empty() {
        for e in &erros {
            eprintln!("{arq}:{e}");
        }
        return false;
    }
    match oidlc::esquemas::gera_esquemas(&file) {
        Ok(json) => {
            print!("{json}");
            true
        }
        Err(erros) => {
            for e in &erros {
                eprintln!("{arq}:{e}");
            }
            false
        }
    }
}

/// Imprime o módulo de cliente gerado para `arq` (T-345).
fn gera_cliente(arq: &str) -> bool {
    let file = match carrega(arq) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{msg}");
            return false;
        }
    };
    let erros = oidlc::analyze(&file);
    if !erros.is_empty() {
        for e in &erros {
            eprintln!("{arq}:{e}");
        }
        return false;
    }
    match oidlc::servidor::gera_cliente(&file) {
        Ok(src) => {
            print!("{}", oidlc::servidor::formata(&src));
            true
        }
        Err(erros) => {
            for e in &erros {
                eprintln!("{arq}:{e}");
            }
            false
        }
    }
}

/// Imprime o módulo de servidor gerado para `arq` (T-344).
fn gera(arq: &str) -> bool {
    let file = match carrega(arq) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("{msg}");
            return false;
        }
    };
    let erros = oidlc::analyze(&file);
    if !erros.is_empty() {
        for e in &erros {
            eprintln!("{arq}:{e}");
        }
        return false;
    }
    match oidlc::servidor::gera_servidor(&file) {
        Ok(src) => {
            print!("{}", oidlc::servidor::formata(&src));
            true
        }
        Err(erros) => {
            for e in &erros {
                eprintln!("{arq}:{e}");
            }
            false
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ok = match args.as_slice() {
        [] => {
            eprintln!(
                "uso: oidlc <arquivo.oidl>... | oidlc check-compat <velho> <novo> | oidlc gera-servidor <arq> | oidlc esquemas <arq>"
            );
            return ExitCode::from(2);
        }
        [cmd, velho, novo] if cmd == "check-compat" => compat(velho, novo),
        [cmd, arq] if cmd == "gera-servidor" => gera(arq),
        [cmd, arq] if cmd == "esquemas" => esquemas(arq),
        [cmd, secs, seed] if cmd == "fuzz" => fuzz(secs, seed),
        [cmd, arq] if cmd == "gera-cliente" => gera_cliente(arq),
        paths => {
            // Sem curto-circuito: todo arquivo é checado e reportado.
            let mut ok = true;
            for p in paths {
                ok &= checa(p);
            }
            ok
        }
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
