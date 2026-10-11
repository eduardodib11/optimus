//! `mkobfs`: monta e lista imagens OBFS do bootfs (SDD v1.0, seções 5.3 e
//! 16.1).
//!
//! ```text
//! mkobfs -o <saída> <nome>=<arquivo> [<nome>=<arquivo>...]
//! mkobfs --list <imagem>
//! ```
//!
//! Só `std` e a crate `obfs`; o `cargo xtask image` a chama para gravar
//! `\EFI\optimus\bootfs.obfs` na ESP.

#![forbid(unsafe_code)]

use std::fmt::Write;
use std::process::ExitCode;
use std::{env, fs};

/// O que a linha de comando pede.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// Monta `output` com os pares (nome, arquivo).
    Build {
        output: String,
        files: Vec<(String, String)>,
    },
    /// Lista e confere a imagem.
    List(String),
}

const USAGE: &str = "uso: mkobfs -o <saída> <nome>=<arquivo>... | mkobfs --list <imagem>";

fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [flag, image] if flag == "--list" => Ok(Command::List(image.clone())),
        [flag, output, rest @ ..] if flag == "-o" && !rest.is_empty() => {
            let files = rest
                .iter()
                .map(|pair| {
                    pair.split_once('=')
                        .filter(|(name, path)| !name.is_empty() && !path.is_empty())
                        .map(|(name, path)| (name.to_owned(), path.to_owned()))
                        .ok_or_else(|| format!("esperado <nome>=<arquivo>, veio \"{pair}\""))
                })
                .collect::<Result<_, _>>()?;
            Ok(Command::Build {
                output: output.clone(),
                files,
            })
        }
        _ => Err(USAGE.into()),
    }
}

fn build(output: &str, files: &[(String, String)]) -> Result<(), String> {
    let contents = files
        .iter()
        .map(|(_, path)| fs::read(path).map_err(|e| format!("lendo {path}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let entries: Vec<(&str, &[u8])> = files
        .iter()
        .zip(&contents)
        .map(|((name, _), data)| (name.as_str(), data.as_slice()))
        .collect();
    let image = obfs::build(&entries).map_err(|e| format!("imagem recusada: {e:?}"))?;
    fs::write(output, &image).map_err(|e| format!("gravando {output}: {e}"))?;
    println!(
        "mkobfs: {output}: {} entradas, {} KiB",
        entries.len(),
        image.len() / 1024
    );
    Ok(())
}

fn list(path: &str) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|e| format!("lendo {path}: {e}"))?;
    let image = obfs::Image::parse(&bytes).map_err(|e| format!("{path}: {e:?}"))?;
    for e in image.entries() {
        let hash = e.hash[..8].iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let ok = if e.verify() { "ok" } else { "HASH ERRADO" };
        println!(
            "{:#010x} {:>9} {hash}… {ok} {}",
            e.offset,
            e.data.len(),
            e.name
        );
    }
    image
        .verify()
        .map_err(|(e, name)| format!("{path}: {name}: {e:?}"))
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = parse(&args).and_then(|cmd| match cmd {
        Command::Build { output, files } => build(&output, &files),
        Command::List(image) => list(&image),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkobfs: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn linha_de_comando() {
        assert_eq!(
            parse(&args(&["-o", "b.obfs", "root=r.elf", "svc/x=y"])),
            Ok(Command::Build {
                output: "b.obfs".into(),
                files: vec![
                    ("root".into(), "r.elf".into()),
                    ("svc/x".into(), "y".into())
                ],
            })
        );
        assert_eq!(
            parse(&args(&["--list", "b.obfs"])),
            Ok(Command::List("b.obfs".into()))
        );
        for bad in [
            &["-o", "b.obfs"][..],
            &["-o", "b", "semigual"],
            &["-o", "b", "=x"],
            &[],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn monta_e_lista() {
        let dir = env::temp_dir().join(format!("mkobfs-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("a.bin");
        fs::write(&input, b"conteudo").unwrap();
        let out = dir.join("b.obfs");
        let (out, input) = (out.to_str().unwrap(), input.to_str().unwrap());
        build(out, &[("a".into(), input.into())]).unwrap();
        list(out).unwrap();
        let bytes = fs::read(out).unwrap();
        let image = obfs::Image::parse(&bytes).unwrap();
        assert_eq!(image.find("a").unwrap().data, b"conteudo");
        assert!(
            build(
                out,
                &[("a".into(), dir.join("nada").to_str().unwrap().into())]
            )
            .is_err()
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
