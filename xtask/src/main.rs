//! `cargo xtask`: orquestrador de build, imagem, QEMU e verificações (SDD v1.0, seção 16.3).
//!
//! Sem dependências externas: só `std` e as ferramentas do host (`cargo`, QEMU, OVMF).

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

/// Alvo do kernel no lugar de `x86_64-optimus-kernel`: alvos próprios em JSON
/// exigem `-Zbuild-std`, que não existe no Rust estável (ADR 0025).
const KERNEL_TARGET: &str = "x86_64-unknown-none";
/// Alvo de usuário no lugar de `x86_64-optimus` (ADR 0025).
const USER_TARGET: &str = "x86_64-unknown-none";
const UEFI_TARGET: &str = "x86_64-unknown-uefi";

/// Crates do sistema e o alvo de cada uma.
const CRATES: &[(&str, &str, &str)] = &[
    ("optboot", "boot/optboot/src/main.rs", UEFI_TARGET),
    ("kabi", "kernel/kabi/src/lib.rs", KERNEL_TARGET),
    ("okernel", "kernel/okernel/src/main.rs", KERNEL_TARGET),
    ("oelf", "lib/oelf/src/lib.rs", KERNEL_TARGET),
    ("ostd", "lib/ostd/src/lib.rs", USER_TARGET),
];

const PROFILES: &[&str] = &["lite", "basic", "jarvis", "premium", "server"];

/// Textos que o smoke test exige na serial.
const BOOT_MARKERS: &[&str] = &[
    "optboot",
    "optboot: kernel carregado",
    "optboot: mapa de memória",
    "optboot: KASLR",
    "saindo dos serviços de boot",
];
/// Status do QEMU quando o kernel escreve 0x10 no `isa-debug-exit`: `(0x10 << 1) | 1`.
const KERNEL_EXIT_OK: i32 = 33;
/// Prefixo das linhas em que o `optboot` descreve cada segmento carregado.
const SEGMENT_PREFIX: &str = "optboot: seg ";
const SMOKE_TIMEOUT: Duration = Duration::from_mins(1);

type Result<T = ()> = std::result::Result<T, String>;

/// Opções de linha de comando comuns aos subcomandos.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    arch: String,
    profile: String,
    release: bool,
    gdb: bool,
    smp: u32,
    mem: String,
    suite: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            arch: "x86_64".into(),
            profile: "lite".into(),
            release: false,
            gdb: false,
            smp: 1,
            mem: "512M".into(),
            suite: "all".into(),
        }
    }
}

fn parse(args: &[String]) -> Result<Options> {
    let mut opts = Options::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or(format!("{name} precisa de um valor"))
        };
        match arg.as_str() {
            "--arch" => opts.arch = value("--arch")?,
            "--profile" => opts.profile = value("--profile")?,
            "--release" => opts.release = true,
            "--gdb" => opts.gdb = true,
            "--smp" => {
                opts.smp = value("--smp")?
                    .parse()
                    .map_err(|_| "--smp espera um número")?;
            }
            "--mem" => opts.mem = value("--mem")?,
            "unit" | "boot" | "all" => opts.suite.clone_from(arg),
            other => return Err(format!("opção desconhecida: {other}")),
        }
    }
    if opts.arch != "x86_64" {
        return Err(format!(
            "arquitetura ainda não suportada: {} (só x86_64 no M0)",
            opts.arch
        ));
    }
    if !PROFILES.contains(&opts.profile.as_str()) {
        return Err(format!(
            "perfil inválido: {} (use {})",
            opts.profile,
            PROFILES.join("|")
        ));
    }
    Ok(opts)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        eprintln!("uso: cargo xtask <build|image|run|test|check> [opções]");
        return ExitCode::FAILURE;
    };
    let result = parse(rest).and_then(|opts| match cmd.as_str() {
        "build" => build(&opts),
        "image" => build(&opts).and_then(|()| image(&opts).map(drop)),
        "run" => run(&opts),
        "test" => test(&opts),
        "check" => check(),
        other => Err(format!("subcomando desconhecido: {other}")),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn cargo() -> Command {
    let mut cmd = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(root());
    cmd
}

fn status(cmd: &mut Command) -> Result {
    let st = cmd
        .status()
        .map_err(|e| format!("falha ao executar {cmd:?}: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} terminou com {st}"))
    }
}

fn mode(opts: &Options) -> &'static str {
    if opts.release { "release" } else { "debug" }
}

fn build(opts: &Options) -> Result {
    println!(
        "xtask: build {} perfil {} ({})",
        opts.arch,
        opts.profile,
        mode(opts)
    );
    for (package, _, target) in CRATES {
        let mut cmd = cargo();
        cmd.args(["build", "--package", package, "--target", target]);
        if opts.release {
            cmd.arg("--release");
        }
        // Vale para a crate e suas dependências (lib e bin do kernel, `kabi`), e cada
        // pacote é compilado numa invocação própria, então não vaza para o `ostd`.
        let flags = rustc_flags(package);
        if !flags.is_empty() {
            cmd.env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f"));
        }
        status(&mut cmd)?;
    }
    Ok(())
}

/// Flags de `rustc` só para a crate final, no lugar do que o alvo próprio
/// definiria (ADR 0025): o kernel vive nos 2 GiB do topo e é PIE, para o
/// `optboot` aplicar o deslocamento de KASLR pelas relocações relativas.
fn rustc_flags(package: &str) -> &'static [&'static str] {
    match package {
        "okernel" => &["-C", "code-model=kernel", "-C", "relocation-model=pie"],
        _ => &[],
    }
}

/// Monta a ESP em `target/esp`, que o QEMU expõe como disco FAT virtual.
fn image(opts: &Options) -> Result<PathBuf> {
    let esp = root().join("target/esp");
    let boot = esp.join("EFI/BOOT");
    fs::create_dir_all(&boot).map_err(|e| format!("criando {}: {e}", boot.display()))?;
    let efi = root().join(format!("target/{UEFI_TARGET}/{}/optboot.efi", mode(opts)));
    fs::copy(&efi, boot.join("BOOTX64.EFI"))
        .map_err(|e| format!("copiando {}: {e}", efi.display()))?;
    // TODO(boot A/B): slots em \EFI\optimus\slot-{a,b}\ e assinaturas híbridas
    // do kernel (SDD 5.1, passos 2 e 3), em tarefa posterior ao backlog M0-M2.
    let optimus = esp.join("EFI/optimus");
    fs::create_dir_all(&optimus).map_err(|e| format!("criando {}: {e}", optimus.display()))?;
    let kernel = root().join(format!("target/{KERNEL_TARGET}/{}/okernel", mode(opts)));
    fs::copy(&kernel, optimus.join("okernel.elf"))
        .map_err(|e| format!("copiando {}: {e}", kernel.display()))?;
    println!("xtask: ESP pronta em {}", esp.display());
    Ok(esp)
}

/// Procura o firmware OVMF: variáveis `OVMF_CODE`/`OVMF_VARS` ou caminhos comuns.
fn ovmf() -> Result<(PathBuf, PathBuf)> {
    if let (Ok(code), Ok(vars)) = (env::var("OVMF_CODE"), env::var("OVMF_VARS")) {
        return Ok((code.into(), vars.into()));
    }
    let candidates = [
        (
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/OVMF/OVMF_VARS_4M.fd",
        ),
        (
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/OVMF/OVMF_VARS.fd",
        ),
        (
            "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
            "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
        ),
        (
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ),
    ];
    candidates
        .iter()
        .find(|(code, vars)| Path::new(code).exists() && Path::new(vars).exists())
        .map(|(code, vars)| (code.into(), vars.into()))
        .ok_or_else(|| {
            "OVMF não encontrado; instale o pacote ovmf ou defina OVMF_CODE e OVMF_VARS".into()
        })
}

fn qemu(opts: &Options, esp: &Path) -> Result<Command> {
    let (code, vars) = ovmf()?;
    let vars_copy = root().join("target/OVMF_VARS.fd");
    fs::copy(&vars, &vars_copy).map_err(|e| format!("copiando {}: {e}", vars.display()))?;
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-machine",
        "q35",
        "-m",
        &opts.mem,
        "-smp",
        &opts.smp.to_string(),
    ])
    .args(["-display", "none", "-serial", "stdio", "-no-reboot"])
    // Fonte do EFI_RNG_PROTOCOL do OVMF; a semente do optboot vem dele.
    .args(["-device", "virtio-rng-pci"])
    // Porta 0xf4: o kernel desliga o QEMU com um código de saída.
    .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
    .arg("-drive")
    .arg(format!(
        "if=pflash,format=raw,readonly=on,file={}",
        code.display()
    ))
    .arg("-drive")
    .arg(format!("if=pflash,format=raw,file={}", vars_copy.display()))
    .arg("-drive")
    .arg(format!("format=raw,file=fat:rw:{}", esp.display()));
    if kvm_usable() {
        cmd.args(["-enable-kvm", "-cpu", "host"]);
    }
    if opts.gdb {
        cmd.args(["-s", "-S"]);
    }
    Ok(cmd)
}

/// KVM só acelera se `/dev/kvm` existir e o usuário puder abri-lo (nos runners
/// do GitHub ele existe, mas sem permissão).
fn kvm_usable() -> bool {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

fn run(opts: &Options) -> Result {
    build(opts)?;
    let esp = image(opts)?;
    let mut cmd = qemu(opts, &esp)?;
    let st = cmd
        .status()
        .map_err(|e| format!("falha ao executar o QEMU: {e}"))?;
    match st.code() {
        Some(0 | KERNEL_EXIT_OK) => Ok(()),
        _ => Err(format!("QEMU terminou com {st}")),
    }
}

/// Dá boot no QEMU sem interação e confere a serial com [`check_serial`].
fn smoke(opts: &Options) -> Result {
    build(opts)?;
    let esp = image(opts)?;
    let mut child = qemu(opts, &esp)?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("falha ao iniciar o QEMU: {e}"))?;
    let mut stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        String::from_utf8_lossy(&out).into_owned()
    });
    let start = Instant::now();
    let exit = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st.code();
        }
        if start.elapsed() > SMOKE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(100));
    };
    let serial = reader.join().unwrap_or_default();
    let result = check_serial(&serial).and_then(|()| match exit {
        Some(KERNEL_EXIT_OK) => Ok(()),
        Some(code) => Err(format!("QEMU saiu com {code}, esperado {KERNEL_EXIT_OK}")),
        None => Err("o kernel não desligou o QEMU a tempo".into()),
    });
    match result {
        Ok(()) => {
            println!("xtask: smoke test de boot ok");
            Ok(())
        }
        Err(e) => Err(format!("smoke test de boot falhou: {e}; serial:\n{serial}")),
    }
}

/// Exige os `BOOT_MARKERS`, ao menos um segmento e nenhum segmento W+X.
fn check_serial(serial: &str) -> Result {
    if let Some(missing) = BOOT_MARKERS.iter().find(|m| !serial.contains(*m)) {
        return Err(format!("faltou \"{missing}\""));
    }
    let mut segments = 0;
    for line in serial.lines().filter(|l| l.contains(SEGMENT_PREFIX)) {
        let perms = line.split_whitespace().last().unwrap_or_default();
        if perms.contains('W') && perms.contains('X') {
            return Err(format!("segmento W+X: {}", line.trim()));
        }
        segments += 1;
    }
    if segments == 0 {
        return Err("nenhum segmento do kernel carregado".into());
    }
    Ok(())
}

fn test(opts: &Options) -> Result {
    if matches!(opts.suite.as_str(), "unit" | "all") {
        status(cargo().args([
            "test",
            "--workspace",
            "--exclude",
            "okernel",
            "--exclude",
            "optboot",
            "--exclude",
            "ostd",
        ]))?;
        // A lógica portável do kernel (biblioteca `okernel`) roda no host.
        status(cargo().args(["test", "--package", "okernel", "--lib"]))?;
    }
    if matches!(opts.suite.as_str(), "boot" | "all") {
        smoke(opts)?;
    }
    Ok(())
}

/// Formatação, clippy em cada alvo e a regra de `unsafe` da seção 17.1.
fn check() -> Result {
    status(cargo().args(["fmt", "--all", "--check"]))?;
    status(cargo().args(["clippy", "--package", "xtask", "--", "-D", "warnings"]))?;
    // Bibliotecas testadas no host também passam pelo clippy com os testes.
    status(cargo().args([
        "clippy",
        "--package",
        "oelf",
        "--tests",
        "--",
        "-D",
        "warnings",
    ]))?;
    status(cargo().args([
        "clippy",
        "--package",
        "okernel",
        "--lib",
        "--tests",
        "--",
        "-D",
        "warnings",
    ]))?;
    for (package, _, target) in CRATES {
        status(cargo().args([
            "clippy",
            "--package",
            package,
            "--target",
            target,
            "--",
            "-D",
            "warnings",
        ]))?;
    }
    check_unsafe()
}

fn check_unsafe() -> Result {
    let allowlist =
        fs::read_to_string(root().join("unsafe-allowlist.toml")).map_err(|e| e.to_string())?;
    let crates = CRATES
        .iter()
        .map(|(_, file, _)| *file)
        .chain(["xtask/src/main.rs"]);
    for file in crates {
        let dir = file.split("/src/").next().unwrap_or(file);
        let allowed = allowlist.contains(&format!("\"{dir}\""));
        let source = fs::read_to_string(root().join(file)).map_err(|e| e.to_string())?;
        if !allowed && !source.contains("#![forbid(unsafe_code)]") {
            return Err(format!(
                "{file}: falta #![forbid(unsafe_code)] (ou inclua {dir} em unsafe-allowlist.toml)"
            ));
        }
    }
    println!("xtask: allowlist de unsafe ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn padrao_e_lite_x86_64() {
        assert_eq!(parse(&[]), Ok(Options::default()));
    }

    #[test]
    fn le_opcoes_do_run() {
        let opts = parse(&args(&[
            "--smp",
            "4",
            "--mem",
            "1G",
            "--gdb",
            "--profile",
            "jarvis",
        ]))
        .unwrap();
        assert_eq!(
            (opts.smp, opts.mem.as_str(), opts.gdb, opts.profile.as_str()),
            (4, "1G", true, "jarvis")
        );
    }

    #[test]
    fn rejeita_perfil_e_arquitetura_invalidos() {
        assert!(parse(&args(&["--profile", "turbo"])).is_err());
        assert!(parse(&args(&["--arch", "aarch64"])).is_err());
        assert!(parse(&args(&["--smp"])).is_err());
    }

    #[test]
    fn serial_exige_kernel_carregado_e_w_xor_x() {
        let ok = "Optimus OS \u{2014} optboot\r\n\
                  optboot: seg 0xffffffff80000000 -> 0x1000 0xcc R-X\r\n\
                  optboot: seg 0xffffffff80002000 -> 0x2000 0x8 RW-\r\n\
                  optboot: kernel carregado, entrada 0xffffffff80000000\r\n\
                  optboot: mapa de memória: 24 regiões, 517896 KiB usáveis\r\n\
                  optboot: KASLR: deslocamento 0x200000\r\n\
                  optboot: tabelas de página prontas; saindo dos serviços de boot\r\n";
        assert_eq!(check_serial(ok), Ok(()));
        assert!(check_serial("Optimus OS \u{2014} optboot\r\n").is_err());
        assert!(check_serial(&ok.replace("R-X", "RWX")).is_err());
        assert!(check_serial(&ok.replace("optboot: seg", "x")).is_err());
    }

    #[test]
    fn crates_do_sistema_respeitam_a_regra_de_unsafe() {
        check_unsafe().unwrap();
    }
}
