//! Fuzzer do `oidlc` (T-347): muta os `.oidl` de referência e verifica que
//! analisador, semântica e geradores nunca entram em pânico.
//!
//! Cada entrada gerada passa por `parse`, `analyze` e, quando o arquivo é
//! válido, pelos dois geradores. Qualquer pânico grava a entrada em disco
//! e encerra com erro: a entrada então vira teste de regressão.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use crate::{analyze, esquemas, parser, servidor};

/// Sementes: os arquivos de referência do repositório, embutidos.
const SEMENTES: &[&str] = &[
    include_str!("../tests/golden/valid/fs.oidl"),
    include_str!("../tests/golden/valid/tudo.oidl"),
];

/// Pedaços que o mutador insere: tokens da gramática e lixo.
const PEDACOS: &[&str] = &[
    "{",
    "}",
    "(",
    ")",
    "<",
    ">",
    ",",
    ";",
    ":",
    "=",
    "->",
    "@",
    "\"",
    "\\",
    "0",
    "255",
    "99999999999999999999999",
    "struct ",
    "enum ",
    "flags ",
    "interface ",
    "handle<",
    "vec<",
    "string<",
    "result<",
    "()",
    "oneway ",
    "@tool(risk = R9)",
    "\n",
    "é",
    "\u{0}",
];

/// Gerador pseudoaleatório (xorshift64*), determinístico pela semente.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

/// Aplica de uma a oito mutações a `base`.
fn muta(base: &str, rng: &mut Rng) -> String {
    let mut s = base.to_string();
    for _ in 0..=rng.below(8) {
        let n = s.len();
        let pos = {
            let mut p = rng.below(n + 1);
            while p < s.len() && !s.is_char_boundary(p) {
                p += 1;
            }
            p
        };
        match rng.below(4) {
            0 => {
                let fim = (pos + rng.below(12)).min(s.len());
                let fim = (fim..=s.len())
                    .find(|&i| s.is_char_boundary(i))
                    .unwrap_or(s.len());
                s.replace_range(pos..fim, "");
            }
            1 | 2 => {
                let p = PEDACOS[rng.below(PEDACOS.len())];
                s.insert_str(pos, p);
            }
            _ => {
                let ini = rng.below(s.len() + 1);
                let ini = (ini..=s.len())
                    .find(|&i| s.is_char_boundary(i))
                    .unwrap_or(s.len());
                let fim = (ini + rng.below(40)).min(s.len());
                let fim = (fim..=s.len())
                    .find(|&i| s.is_char_boundary(i))
                    .unwrap_or(s.len());
                let trecho = s[ini..fim].to_string();
                s.insert_str(pos, &trecho);
            }
        }
    }
    s
}

/// Roda uma entrada pelo pipeline inteiro. Não retorna erro: só pânico.
fn passa(src: &str) {
    if let Ok(file) = parser::parse(src) {
        let erros = analyze(&file);
        if erros.is_empty() {
            let _ = servidor::gera_servidor(&file);
            let _ = esquemas::gera_esquemas(&file);
        }
    }
}

/// Roda o fuzzer por `secs` segundos com a semente `seed`.
///
/// # Errors
///
/// Primeira entrada que faz o `oidlc` entrar em pânico; ela fica gravada
/// em `falha.oidl` no diretório atual.
pub fn roda(secs: u64, seed: u64) -> Result<u64, String> {
    let mut rng = Rng(seed | 1);
    let inicio = Instant::now();
    let limite = Duration::from_secs(secs);
    let mut execs = 0u64;
    while inicio.elapsed() < limite {
        let base = SEMENTES[rng.below(SEMENTES.len())];
        let entrada = muta(base, &mut rng);
        let ok = catch_unwind(AssertUnwindSafe(|| passa(&entrada)));
        execs += 1;
        if ok.is_err() {
            let _ = std::fs::write("falha.oidl", &entrada);
            return Err(format!(
                "pânico na execução {execs} (semente 0x{seed:x}); entrada em falha.oidl"
            ));
        }
    }
    Ok(execs)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn mutacao_e_deterministica() {
        let a = muta(SEMENTES[0], &mut Rng(7));
        let b = muta(SEMENTES[0], &mut Rng(7));
        assert_eq!(a, b);
    }

    #[test]
    fn curta_rodada_nao_entra_em_panico() {
        let n = roda(1, 0x5EED).expect("sem pânico");
        assert!(n > 0);
    }
}
