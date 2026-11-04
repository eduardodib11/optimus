//! Linha de comando do `mkmanifest`.
//!
//! ```text
//! mkmanifest --elf <dir> --out <dir> <manifesto.toml>...
//! ```
//!
//! Lê cada manifesto, confere o grafo entre todos, e grava
//! `<out>/manifest/<nome>.oman` com o BLAKE3 do binário `<elf>/<binary>`.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::{env, fs};

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let (mut elf_dir, mut out_dir) = (None, None);
    let mut inputs = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--elf" => elf_dir = args.next().map(PathBuf::from),
            "--out" => out_dir = args.next().map(PathBuf::from),
            _ => inputs.push(PathBuf::from(a)),
        }
    }
    let (Some(elf_dir), Some(out_dir)) = (elf_dir, out_dir) else {
        return Err("uso: mkmanifest --elf <dir> --out <dir> <manifesto.toml>...".into());
    };
    let mut manifests = Vec::new();
    for path in &inputs {
        let src = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let m = mkmanifest::parse(&src).map_err(|e| format!("{}: {e}", path.display()))?;
        manifests.push(m);
    }
    mkmanifest::check_graph(&manifests).map_err(|e| e.to_string())?;
    let dest = out_dir.join("manifest");
    fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    for m in &manifests {
        let elf = fs::read(elf_dir.join(&m.binary)).map_err(|e| format!("{}: {e}", m.binary))?;
        let bytes = mkmanifest::encode(m, &elf).map_err(|e| e.to_string())?;
        let file = dest.join(format!("{}.oman", m.name));
        fs::write(&file, bytes).map_err(|e| format!("{}: {e}", file.display()))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkmanifest: {e}");
            ExitCode::FAILURE
        }
    }
}
