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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ok = match args.as_slice() {
        [] => {
            eprintln!("uso: oidlc <arquivo.oidl>... | oidlc check-compat <velho> <novo>");
            return ExitCode::from(2);
        }
        [cmd, velho, novo] if cmd == "check-compat" => compat(velho, novo),
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
