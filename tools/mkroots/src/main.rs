//! `mkroots`: gera o conjunto de âncoras do `tlsd` (ADR 0071, item 5; T-651).
//!
//! ```text
//! mkroots <certdata.txt> <roots.der>
//! ```
//!
//! Lê o `certdata.txt` do NSS (projeto Mozilla, MPL-2.0) e grava, em ordem,
//! o DER de cada certificado com `CKA_TRUST_SERVER_AUTH` igual a
//! `CKT_NSS_TRUSTED_DELEGATOR`. Raízes com `CKA_NSS_SERVER_DISTRUST_AFTER`
//! (desconfiança a partir de uma data) ficam de fora: o `ox509` não guarda
//! a data e falha fechado. Cada certificado tem de ser lido pelo `ox509`.
//! Não baixa nada: o arquivo vem de quem chama (local por padrão).

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::{env, fs};

/// Um objeto do `certdata.txt`: atributos na ordem do arquivo.
#[derive(Debug, Default)]
struct Object {
    attrs: Vec<(String, Value)>,
}

#[derive(Debug, PartialEq, Eq)]
enum Value {
    /// `CK_* VALOR` ou `UTF8 "texto"`.
    Token(String),
    /// `MULTILINE_OCTAL`.
    Bytes(Vec<u8>),
}

impl Object {
    fn get(&self, name: &str) -> Option<&Value> {
        self.attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    fn bytes(&self, name: &str) -> Option<&[u8]> {
        match self.get(name)? {
            Value::Bytes(b) => Some(b),
            Value::Token(_) => None,
        }
    }

    fn token(&self, name: &str) -> Option<&str> {
        match self.get(name)? {
            Value::Token(t) => Some(t),
            Value::Bytes(_) => None,
        }
    }
}

/// Separa o arquivo em objetos (cada um começa em `CKA_CLASS`).
fn parse(text: &str) -> Result<Vec<Object>, String> {
    let mut out: Vec<Object> = Vec::new();
    let mut lines = text.lines().enumerate();
    while let Some((n, line)) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("BEGINDATA") {
            continue;
        }
        let mut f = line.splitn(3, ' ');
        let (Some(name), Some(kind)) = (f.next(), f.next()) else {
            return Err(format!("linha {}: atributo sem tipo", n + 1));
        };
        let value = if kind == "MULTILINE_OCTAL" {
            let mut bytes = Vec::new();
            loop {
                let Some((m, l)) = lines.next() else {
                    return Err(format!("linha {}: MULTILINE_OCTAL sem END", n + 1));
                };
                let l = l.trim();
                if l == "END" {
                    break;
                }
                bytes.extend(octal(l).ok_or(format!("linha {}: octal inválido", m + 1))?);
            }
            Value::Bytes(bytes)
        } else {
            Value::Token(f.next().unwrap_or("").to_string())
        };
        if name == "CKA_CLASS" {
            out.push(Object::default());
        }
        let Some(obj) = out.last_mut() else {
            return Err(format!("linha {}: atributo antes de CKA_CLASS", n + 1));
        };
        obj.attrs.push((name.to_string(), value));
    }
    Ok(out)
}

/// `\ooo\ooo...` em bytes.
fn octal(l: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for part in l.split('\\').skip(1) {
        if part.len() != 3 {
            return None;
        }
        out.push(u8::from_str_radix(part, 8).ok()?);
    }
    Some(out)
}

/// As raízes de servidor, em DER, na ordem do arquivo, com o rótulo.
fn server_roots(objects: &[Object]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let trusted = |cert: &Object| {
        objects.iter().any(|t| {
            t.token("CKA_CLASS") == Some("CKO_NSS_TRUST")
                && t.bytes("CKA_ISSUER") == cert.bytes("CKA_ISSUER")
                && t.bytes("CKA_SERIAL_NUMBER") == cert.bytes("CKA_SERIAL_NUMBER")
                && t.token("CKA_TRUST_SERVER_AUTH") == Some("CKT_NSS_TRUSTED_DELEGATOR")
        })
    };
    let mut out = Vec::new();
    for c in objects
        .iter()
        .filter(|o| o.token("CKA_CLASS") == Some("CKO_CERTIFICATE"))
    {
        let label = c
            .token("CKA_LABEL")
            .unwrap_or("?")
            .trim_matches('"')
            .to_string();
        let der = c
            .bytes("CKA_VALUE")
            .ok_or(format!("{label}: sem CKA_VALUE"))?;
        if !trusted(c) || c.bytes("CKA_NSS_SERVER_DISTRUST_AFTER").is_some() {
            continue;
        }
        ox509::Certificate::parse(der).map_err(|e| format!("{label}: {e:?}"))?;
        out.push((label, der.to_vec()));
    }
    Ok(out)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let [input, output] = args.as_slice() else {
        eprintln!("uso: mkroots <certdata.txt> <roots.der>");
        return ExitCode::FAILURE;
    };
    let result = fs::read_to_string(input)
        .map_err(|e| format!("{input}: {e}"))
        .and_then(|t| parse(&t))
        .and_then(|o| server_roots(&o));
    let roots = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mkroots: {e}");
            return ExitCode::FAILURE;
        }
    };
    let all: Vec<u8> = roots.iter().flat_map(|(_, d)| d.iter().copied()).collect();
    if let Err(e) = ox509::verify::Anchors::parse(&all) {
        eprintln!("mkroots: conjunto recusado pelo ox509: {e:?}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::write(output, &all) {
        eprintln!("mkroots: {output}: {e}");
        return ExitCode::FAILURE;
    }
    for (label, _) in &roots {
        println!("{label}");
    }
    eprintln!(
        "mkroots: {} raízes, {} bytes em {output}",
        roots.len(),
        all.len()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# comentário
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_BUILTIN_ROOT_LIST
CKA_LABEL UTF8 "Lista"
CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE
CKA_LABEL UTF8 "Raiz A"
CKA_ISSUER MULTILINE_OCTAL
\001\002
END
CKA_SERIAL_NUMBER MULTILINE_OCTAL
\007
END
CKA_VALUE MULTILINE_OCTAL
\060\000
END
CKA_NSS_SERVER_DISTRUST_AFTER CK_BBOOL CK_FALSE
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_ISSUER MULTILINE_OCTAL
\001\002
END
CKA_SERIAL_NUMBER MULTILINE_OCTAL
\007
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR
"#;

    #[test]
    fn objetos_e_octal() {
        let o = parse(SAMPLE).unwrap();
        assert_eq!(o.len(), 3);
        assert_eq!(o[1].token("CKA_LABEL"), Some("\"Raiz A\""));
        assert_eq!(o[1].bytes("CKA_VALUE"), Some(&[0x30, 0x00][..]));
        // `CK_FALSE` não é data: a raiz não tem desconfiança marcada.
        assert!(o[1].bytes("CKA_NSS_SERVER_DISTRUST_AFTER").is_none());
        assert_eq!(octal("\\101\\377"), Some(vec![0x41, 0xFF]));
        assert_eq!(octal("\\1"), None);
        assert!(parse("CKA_VALUE MULTILINE_OCTAL\n\\001\n").is_err());
    }

    #[test]
    fn certificado_ilegivel_e_recusado() {
        // `30 00` não é certificado: a ferramenta para em vez de gravar.
        let o = parse(SAMPLE).unwrap();
        assert!(server_roots(&o).unwrap_err().starts_with("Raiz A"));
        let sem_confianca =
            SAMPLE.replace("CKT_NSS_TRUSTED_DELEGATOR", "CKT_NSS_MUST_VERIFY_TRUST");
        assert!(
            server_roots(&parse(&sem_confianca).unwrap())
                .unwrap()
                .is_empty()
        );
    }
}
