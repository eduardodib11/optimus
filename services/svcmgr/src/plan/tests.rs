//! Testes do plano de partida.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::*;

fn oman(name: &str, needs: &[&str], provides: &[&str]) -> Vec<u8> {
    let quote = |v: &[&str]| {
        v.iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<String>>()
            .join(",")
    };
    let mut all: Vec<&str> = needs.to_vec();
    all.push("mem:quota:4MiB");
    let src = format!(
        "[service]\nname = \"{name}\"\nbinary = \"{name}\"\npriority = 130\nrestart = \"never\"\n\
         [capabilities]\nneeds = [{}]\nprovides = [{}]\n[limits]\nmax_threads = 2\n",
        quote(&all),
        quote(provides)
    );
    let m = mkmanifest::parse(&src).expect("manifesto de teste");
    mkmanifest::encode(&m, b"elf").expect("codifica")
}

fn fs(items: &[(&'static str, Vec<u8>)]) -> Vec<(&'static str, Vec<u8>)> {
    items.to_vec()
}

fn run(files: &[(&'static str, Vec<u8>)]) -> Result<Plan, PlanError> {
    let v: Vec<(&str, &[u8])> = files.iter().map(|(n, d)| (*n, d.as_slice())).collect();
    build(&v)
}

#[test]
fn ordem_por_dependencias() {
    let files = fs(&[
        ("hello", b"elf".to_vec()),
        ("logd", b"elf".to_vec()),
        ("timed", b"elf".to_vec()),
        (
            "manifest/hello.oman",
            oman("hello", &["svc:optimus.log.Log@1"], &[]),
        ),
        (
            "manifest/logd.oman",
            oman(
                "logd",
                &["svc:optimus.time.Clock@1"],
                &["optimus.log.Log@1.0"],
            ),
        ),
        (
            "manifest/timed.oman",
            oman("timed", &[], &["optimus.time.Clock@1.0"]),
        ),
        ("leiame", b"x".to_vec()),
    ]);
    let p = run(&files).expect("plano");
    // Ids na ordem dos nomes: hello 0, logd 1, timed 2.
    assert_eq!(p.levels, [vec![2], vec![1], vec![0]]);
    assert_eq!(p.broker.manifest(1).map(|m| m.name.as_str()), Some("logd"));
}

#[test]
fn recusas() {
    let sem_binario = fs(&[("manifest/a.oman", oman("a", &[], &[]))]);
    assert_eq!(
        run(&sem_binario).err(),
        Some(PlanError::MissingBinary("a".into()))
    );
    let ruim = fs(&[("manifest/a.oman", b"lixo".to_vec())]);
    assert_eq!(
        run(&ruim).err(),
        Some(PlanError::BadManifest("manifest/a.oman".into()))
    );
    let sem_provedor = fs(&[
        ("a", b"elf".to_vec()),
        ("manifest/a.oman", oman("a", &["svc:x.Y@1"], &[])),
    ]);
    assert!(matches!(
        run(&sem_provedor).err(),
        Some(PlanError::Graph(_))
    ));
    let vazio = build(&[]).expect("sem manifestos");
    assert!(vazio.levels.is_empty());
}

#[test]
fn drivers_ficam_fora_dos_niveis() {
    let files = fs(&[
        ("devmgr", b"elf".to_vec()),
        ("drv", b"elf".to_vec()),
        (
            "manifest/devmgr.oman",
            oman("devmgr", &[], &["optimus.dev.DeviceBus@1.0"]),
        ),
        (
            "manifest/drv.oman",
            oman("drv", &["dev:pci:1234:11e8"], &[]),
        ),
    ]);
    let p = run(&files).expect("plano");
    assert_eq!(p.levels, [vec![0]]);
    assert_eq!(p.drivers, [1]);
    assert!(p.broker.is_device_manager(0));
    assert!(!p.broker.is_device_manager(1));
    assert!(!p.broker.is_device_manager(9));
}
