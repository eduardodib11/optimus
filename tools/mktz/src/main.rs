//! `mktz`: `TZif` (tzdata) para `OTZ1` (T-359; ADR 0037, item 5).
//!
//! ```text
//! mktz <nome> <arquivo.tzif> <saida.otz>
//! ```
//!
//! Lê só o bloco de 64 bits e o rodapé POSIX de um `TZif` versão 2 ou
//! posterior (`zic -b slim` ou `fat`); descarta segundos intercalares e os
//! indicadores de padrão/UT. O layout do `OTZ1` está em `timed::zone`.

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::{env, fs};

fn be32(b: &[u8], i: usize) -> Result<usize, String> {
    let w = b.get(i..i + 4).ok_or("TZif truncado")?;
    Ok(u32::from_be_bytes([w[0], w[1], w[2], w[3]]) as usize)
}

/// Converte um `TZif` v2+ em um blob `OTZ1` chamado `name`.
///
/// # Errors
/// Texto com o motivo se o `TZif` for inválido, de versão 1 ou grande demais.
pub fn convert(tzif: &[u8], name: &str) -> Result<Vec<u8>, String> {
    if name.len() > 63 || tzif.get(..4) != Some(b"TZif") || tzif.get(4) == Some(&0) {
        return Err("nome longo demais ou arquivo não é TZif v2+".into());
    }
    // Bloco v1: pula.
    let c = |h: usize, i: usize| be32(tzif, h + 20 + 4 * i);
    let v1 = 44 + c(0, 3)? * 5 + c(0, 4)? * 6 + c(0, 5)? + c(0, 2)? * 8 + c(0, 1)? + c(0, 0)?;
    let h = v1;
    if tzif.get(h..h + 4) != Some(b"TZif") {
        return Err("falta o cabeçalho v2".into());
    }
    let (isut, isstd, leap, nt, ny, nc) =
        (c(h, 0)?, c(h, 1)?, c(h, 2)?, c(h, 3)?, c(h, 4)?, c(h, 5)?);
    let mut p = h + 44;
    let times = tzif.get(p..p + nt * 8).ok_or("TZif truncado")?;
    p += nt * 8;
    let idx = tzif.get(p..p + nt).ok_or("TZif truncado")?;
    p += nt;
    let types = tzif.get(p..p + ny * 6).ok_or("TZif truncado")?;
    p += ny * 6;
    let chars = tzif.get(p..p + nc).ok_or("TZif truncado")?;
    p += nc + leap * 12 + isstd + isut;
    let footer = tzif.get(p..).ok_or("TZif truncado")?;
    let footer = footer
        .strip_prefix(b"\n")
        .and_then(|f| f.split(|c| *c == b'\n').next())
        .unwrap_or(&[]);
    if ny == 0 || ny > 255 || nc > 255 || footer.len() > 255 {
        return Err("tamanhos fora do que o OTZ1 aceita".into());
    }
    let mut out = b"OTZ1".to_vec();
    for n in [1, nt, ny, nc] {
        out.extend_from_slice(&u32::try_from(n).map_err(|e| e.to_string())?.to_le_bytes());
    }
    let mut nm = [0u8; 64];
    nm[..name.len()].copy_from_slice(name.as_bytes());
    out.extend_from_slice(&nm);
    for t in types.chunks(6) {
        let off = i32::from_be_bytes([t[0], t[1], t[2], t[3]]);
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&[t[4], t[5]]);
    }
    out.extend_from_slice(chars);
    for (t, i) in times.chunks(8).zip(idx) {
        let at = i64::from_be_bytes([t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]]);
        out.extend_from_slice(&at.to_le_bytes());
        out.push(*i);
    }
    out.push(u8::try_from(footer.len()).map_err(|e| e.to_string())?);
    out.extend_from_slice(footer);
    // O resultado precisa ser aceito pelo leitor do `timed`.
    timed::zone::Zone::parse(&out).map_err(|e| format!("OTZ1 gerado inválido: {e:?}"))?;
    Ok(out)
}

fn run() -> Result<(), String> {
    let a: Vec<String> = env::args().skip(1).collect();
    let [name, input, output] = a.as_slice() else {
        return Err("uso: mktz <nome> <arquivo.tzif> <saida.otz>".into());
    };
    let tzif = fs::read(input).map_err(|e| format!("lendo {input}: {e}"))?;
    let blob = convert(&tzif, name).map_err(|e| format!("{input}: {e}"))?;
    fs::write(output, &blob).map_err(|e| format!("gravando {output}: {e}"))?;
    println!("mktz: {output}: {name}, {} bytes", blob.len());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mktz: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
