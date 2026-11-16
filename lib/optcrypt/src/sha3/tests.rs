//! Vetores NIST CAVP (byte a byte) do SHA3-256, SHA3-512, SHAKE128 e
//! SHAKE256 (`ShortMsg` e uma amostra do `VariableOut`).

use super::*;
use crate::testutil::{cavp_msg, hex, unhex};

#[test]
fn cavp_sha3() {
    for (msg, md) in cavp_msg(include_str!("../../vetores/SHA3_256ShortMsg.rsp")) {
        assert_eq!(
            sha3_256(&msg)[..],
            md[..],
            "SHA3-256 de {} bytes",
            msg.len()
        );
    }
    for (msg, md) in cavp_msg(include_str!("../../vetores/SHA3_512ShortMsg.rsp")) {
        assert_eq!(
            sha3_512(&msg)[..],
            md[..],
            "SHA3-512 de {} bytes",
            msg.len()
        );
    }
}

/// Casos (`Msg`, `Output`) de um arquivo SHAKE do CAVP: no `ShortMsg` o
/// `Len` corta a mensagem; no `VariableOut` o `Outputlen` muda a saída, e
/// o tamanho vem do próprio `Output`.
fn cavp_shake(texto: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut len = None;
    let mut msg = Vec::new();
    let mut out = Vec::new();
    for linha in texto.lines() {
        if let Some(v) = linha.strip_prefix("Len = ") {
            len = Some(v.parse::<usize>().unwrap() / 8);
        } else if let Some(v) = linha.strip_prefix("Msg = ") {
            msg = unhex(v);
            if let Some(n) = len {
                msg.truncate(n);
            }
        } else if let Some(v) = linha.strip_prefix("Output = ") {
            out.push((msg.clone(), unhex(v)));
        }
    }
    assert!(!out.is_empty());
    out
}

fn confere_shake<X: Default>(texto: &str, f: fn(&mut X, &[u8]), sq: fn(&mut X, &mut [u8])) {
    for (msg, esperado) in cavp_shake(texto) {
        let mut x = X::default();
        f(&mut x, &msg);
        let mut out = vec![0u8; esperado.len()];
        sq(&mut x, &mut out);
        assert_eq!(out, esperado, "{} bytes -> {}", msg.len(), esperado.len());
    }
}

#[test]
fn cavp_shake128() {
    for texto in [
        include_str!("../../vetores/SHAKE128ShortMsg.rsp"),
        include_str!("../../vetores/SHAKE128VariableOut.rsp"),
    ] {
        confere_shake(texto, Shake128::update, Shake128::squeeze);
    }
}

#[test]
fn cavp_shake256() {
    for texto in [
        include_str!("../../vetores/SHAKE256ShortMsg.rsp"),
        include_str!("../../vetores/SHAKE256VariableOut.rsp"),
    ] {
        confere_shake(texto, Shake256::update, Shake256::squeeze);
    }
}

/// Espremer aos pedaços (atravessando a taxa) e absorver aos pedaços dão
/// a mesma saída que de uma vez.
#[test]
fn incremental_igual_de_uma_vez() {
    let dados: Vec<u8> = (0..500u32).map(|i| (i * 13 % 251) as u8).collect();
    let mut inteiro = [0u8; 600];
    let mut x = Shake128::new();
    x.update(&dados);
    x.squeeze(&mut inteiro);
    for corte in [1, 135, 136, 167, 168, 169, 337] {
        let mut x = Shake128::new();
        x.update(&dados[..corte.min(dados.len())]);
        x.update(&dados[corte.min(dados.len())..]);
        let mut a = vec![0u8; corte];
        let mut b = vec![0u8; 600 - corte];
        x.squeeze(&mut a);
        x.squeeze(&mut b);
        assert_eq!([a, b].concat(), inteiro, "corte {corte}");
    }
    let mut j = [0u8; 64];
    shake256(&[b"ab", b"c"], &mut j);
    let mut x = Shake256::new();
    x.update(b"abc");
    let mut k = [0u8; 64];
    x.squeeze(&mut k);
    assert_eq!(j, k);
}

#[test]
fn vazio() {
    assert_eq!(
        hex(&sha3_256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}
