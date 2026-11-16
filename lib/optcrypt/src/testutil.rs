//! Auxiliares dos testes.

use core::fmt::Write;

/// Bytes em hexadecimal minúsculo.
pub fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        write!(s, "{x:02x}").unwrap();
        s
    })
}

/// Hexadecimal para bytes; `-` é vazio.
pub fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert!(s.len().is_multiple_of(2), "hex ímpar: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Número hexadecimal (campos inteiros do Wycheproof).
pub fn unhex_usize(s: &str) -> usize {
    usize::from_str_radix(s, 16).unwrap()
}

/// Um teste do Wycheproof convertido por `vetores/wycheproof.py`.
pub struct Caso<'a> {
    /// Campos do grupo, na ordem pedida ao conversor.
    pub grupo: Vec<&'a str>,
    /// `tcId` do teste.
    pub id: u32,
    /// `v`, `i` ou `a` (valid, invalid, acceptable).
    pub res: char,
    /// Campos do teste, na ordem pedida ao conversor.
    pub campos: Vec<&'a str>,
}

/// Lê os testes do formato compacto. Confere que houve pelo menos um.
pub fn wycheproof(texto: &str) -> Vec<Caso<'_>> {
    let mut grupo = Vec::new();
    let mut casos = Vec::new();
    for linha in texto.lines() {
        let mut it = linha.split(' ');
        match it.next() {
            Some("G") => grupo = it.collect(),
            Some("T") => {
                let id = it.next().unwrap().parse().unwrap();
                let res = it.next().unwrap().chars().next().unwrap();
                casos.push(Caso {
                    grupo: grupo.clone(),
                    id,
                    res,
                    campos: it.collect(),
                });
            }
            _ => {}
        }
    }
    assert!(!casos.is_empty());
    casos
}

/// Pares (`Msg`, `MD`) de um arquivo `ShortMsg`/`LongMsg` do CAVP.
pub fn cavp_msg(texto: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut len = 0;
    let mut msg = Vec::new();
    let mut out = Vec::new();
    for linha in texto.lines() {
        if let Some(v) = linha.strip_prefix("Len = ") {
            len = v.parse::<usize>().unwrap() / 8;
        } else if let Some(v) = linha.strip_prefix("Msg = ") {
            msg = unhex(v);
            msg.truncate(len);
        } else if let Some(v) = linha.strip_prefix("MD = ") {
            out.push((core::mem::take(&mut msg), unhex(v)));
        }
    }
    assert!(!out.is_empty());
    out
}

/// Semente e os `MD` de um arquivo `Monte` do CAVP.
pub fn cavp_monte(texto: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut seed = Vec::new();
    let mut mds = Vec::new();
    for linha in texto.lines() {
        if let Some(v) = linha.strip_prefix("Seed = ") {
            seed = unhex(v);
        } else if let Some(v) = linha.strip_prefix("MD = ") {
            mds.push(unhex(v));
        }
    }
    assert!(!mds.is_empty());
    (seed, mds)
}
