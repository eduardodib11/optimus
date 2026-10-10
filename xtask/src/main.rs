//! `cargo xtask`: orquestrador de build, imagem, QEMU e verificações (SDD v1.0, seção 16.3).
//!
//! Sem dependências externas: só `std` e as ferramentas do host (`cargo`, QEMU, OVMF).

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs, sync::mpsc, thread};

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
    "okernel: hello",
    "okernel: GDT, TSS e IDT carregadas",
    "okernel: kaslr_slide",
    "okernel: mapa de memória",
    "okernel: identidade removida",
    "okernel: heap: slab   16 B",
];
/// Status do QEMU quando o kernel escreve 0x10 no `isa-debug-exit`: `(0x10 << 1) | 1`.
const KERNEL_EXIT_OK: i32 = 33;
/// Textos que o cenário `test=fault` exige: o dump legível do #UD.
const FAULT_MARKERS: &[&str] = &[
    "okernel: hello",
    "okernel: GDT, TSS e IDT carregadas",
    "okernel: FALTA #UD (opcode inválido), vetor 6",
    "  rip 0x",
    "  rax 0x",
    "  cr3 0x",
    "okernel: CPU congelada",
];
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
    /// Linha de comando do kernel, gravada em `\EFI\optimus\cmdline.txt`.
    cmdline: String,
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
            cmdline: String::new(),
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
            "--cmdline" => opts.cmdline = value("--cmdline")?,
            "unit" | "boot" | "kernel" | "all" => opts.suite.clone_from(arg),
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
        "image" => build(&opts).and_then(|()| image(&opts, &opts.cmdline).map(drop)),
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

/// Monta a ESP em `target/esp`, que o QEMU expõe como disco FAT virtual, com
/// `cmdline` como linha de comando do kernel (vazia: sem arquivo).
fn image(opts: &Options, cmdline: &str) -> Result<PathBuf> {
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
    let cmdline_file = optimus.join("cmdline.txt");
    if cmdline.is_empty() {
        let _ = fs::remove_file(&cmdline_file);
    } else {
        fs::write(&cmdline_file, cmdline)
            .map_err(|e| format!("gravando {}: {e}", cmdline_file.display()))?;
    }
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
    } else {
        // Sem KVM, o TCG emula tudo o que sabe (SMEP, SMAP, UMIP, x2APIC),
        // para os testes de kernel exercitarem esses caminhos.
        cmd.args(["-cpu", "max"]);
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
    let esp = image(opts, &opts.cmdline)?;
    let mut cmd = qemu(opts, &esp)?;
    let st = cmd
        .status()
        .map_err(|e| format!("falha ao executar o QEMU: {e}"))?;
    match st.code() {
        Some(0 | KERNEL_EXIT_OK) => Ok(()),
        _ => Err(format!("QEMU terminou com {st}")),
    }
}

/// Um boot de teste: linha de comando, o que a serial precisa (e não pode)
/// mostrar e como o QEMU deve terminar.
struct Scenario {
    name: &'static str,
    cmdline: &'static str,
    markers: &'static [&'static str],
    forbidden: &'static [&'static str],
    /// `Some(código)`: o kernel desliga o QEMU com esse código. `None`: a CPU
    /// congela, e o xtask encerra o QEMU assim que todos os marcadores saem.
    exit: Option<i32>,
    /// Confere e mostra o relatório do harness de testes de kernel (T-111).
    ktest: bool,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "boot normal",
        cmdline: "",
        markers: BOOT_MARKERS,
        forbidden: &["okernel: FALTA", "PÂNICO"],
        exit: Some(KERNEL_EXIT_OK),
        ktest: false,
    },
    Scenario {
        name: "falta proposital",
        cmdline: "test=fault",
        markers: FAULT_MARKERS,
        forbidden: &["okernel: desligando"],
        exit: None,
        ktest: false,
    },
];

/// Testes de kernel (T-111): o kernel roda os testes registrados e sai com 33
/// se todos passarem.
const KERNEL_SCENARIO: Scenario = Scenario {
    name: "testes de kernel",
    cmdline: "test=kernel",
    markers: &[KTEST_START, KTEST_END],
    forbidden: &["ktest: FALHOU", "okernel: FALTA", "PÂNICO"],
    exit: Some(KERNEL_EXIT_OK),
    ktest: true,
};
/// Primeira linha do harness: `ktest: início, N testes`.
const KTEST_START: &str = "ktest: início, ";
/// Última linha do harness: `ktest: fim: N ok, M falharam`.
const KTEST_END: &str = "ktest: fim: ";

/// Dá boot em cada cenário e confere a serial com [`check_serial`].
fn smoke(opts: &Options, scenarios: &[Scenario]) -> Result {
    build(opts)?;
    for scenario in scenarios {
        boot_scenario(opts, scenario)?;
    }
    Ok(())
}

fn boot_scenario(opts: &Options, sc: &Scenario) -> Result {
    let esp = image(opts, sc.cmdline)?;
    let mut child = qemu(opts, &esp)?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("falha ao iniciar o QEMU: {e}"))?;
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n @ 1..) = stdout.read(&mut chunk) {
            if tx.send(chunk[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut raw = Vec::new();
    let start = Instant::now();
    let seen_all = |raw: &[u8]| {
        let text = String::from_utf8_lossy(raw);
        sc.markers.iter().all(|m| text.contains(m))
    };
    // `Ok(código)`: o QEMU terminou sozinho; `Err(congelou)`: o xtask o matou,
    // depois de ver todos os marcadores (`true`) ou por tempo (`false`).
    let end: std::result::Result<Option<i32>, bool> = loop {
        raw.extend(rx.try_iter().flatten());
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break Ok(st.code());
        }
        let frozen = sc.exit.is_none() && seen_all(&raw);
        if frozen || start.elapsed() > SMOKE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            break Err(frozen);
        }
        thread::sleep(Duration::from_millis(100));
    };
    let _ = reader.join();
    raw.extend(rx.try_iter().flatten());
    let serial = String::from_utf8_lossy(&raw);
    let result = check_serial(&serial, sc.markers, sc.forbidden)
        .and_then(|()| {
            if sc.ktest {
                check_ktest(&serial)
            } else {
                Ok(())
            }
        })
        .and_then(|()| match end {
            Ok(code) if code.is_some() && code == sc.exit => Ok(()),
            Ok(code) => Err(format!(
                "QEMU terminou com {code:?}, esperado {:?}",
                sc.exit
            )),
            Err(true) => Ok(()),
            Err(false) => Err("tempo esgotado".into()),
        });
    match result {
        Ok(()) => {
            if sc.ktest {
                for line in serial.lines().filter_map(|l| l.split_once("ktest: ")) {
                    println!("  {}", line.1.trim_end());
                }
            }
            println!("xtask: smoke test de boot ok ({})", sc.name);
            Ok(())
        }
        Err(e) => Err(format!(
            "smoke test de boot falhou ({}): {e}; serial:\n{serial}",
            sc.name
        )),
    }
}

/// Confere o relatório do harness: ao menos um teste, todos anunciados
/// rodaram e passaram.
fn check_ktest(serial: &str) -> Result {
    let after = |prefix: &str| {
        serial
            .lines()
            .find_map(|l| l.split_once(prefix).map(|(_, rest)| rest.trim_end()))
    };
    let number =
        |text: Option<&str>| -> Option<usize> { text?.split_whitespace().next()?.parse().ok() };
    let announced = number(after(KTEST_START)).ok_or("sem a linha de início do ktest")?;
    let end = after(KTEST_END).ok_or("sem a linha de fim do ktest")?;
    let passed = number(Some(end)).ok_or("linha de fim do ktest ilegível")?;
    let ok_lines = serial.lines().filter(|l| l.contains("ktest: ok ")).count();
    if announced == 0 {
        return Err("nenhum teste de kernel registrado".into());
    }
    if !end.ends_with(", 0 falharam") {
        return Err(format!("testes de kernel falharam: {end}"));
    }
    if passed != announced || ok_lines != announced {
        return Err(format!(
            "{announced} testes anunciados, {passed} contados e {ok_lines} linhas ok"
        ));
    }
    Ok(())
}

/// Exige `markers`, recusa `forbidden` e exige ao menos um segmento do
/// kernel e nenhum segmento W+X.
fn check_serial(serial: &str, markers: &[&str], forbidden: &[&str]) -> Result {
    if let Some(missing) = markers.iter().find(|m| !serial.contains(*m)) {
        return Err(format!("faltou \"{missing}\""));
    }
    if let Some(bad) = forbidden.iter().find(|m| serial.contains(*m)) {
        return Err(format!("não devia aparecer \"{bad}\""));
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
        smoke(opts, SCENARIOS)?;
    }
    if matches!(opts.suite.as_str(), "kernel" | "all") {
        smoke(opts, &[KERNEL_SCENARIO])?;
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
            "--cmdline",
            "log=debug",
        ]))
        .unwrap();
        assert_eq!(
            (opts.smp, opts.mem.as_str(), opts.gdb, opts.profile.as_str()),
            (4, "1G", true, "jarvis")
        );
        assert_eq!(opts.cmdline, "log=debug");
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
                  optboot: tabelas de página prontas; saindo dos serviços de boot\r\n\
                  info  okernel: hello\r\n\
                  info  okernel: GDT, TSS e IDT carregadas\r\n\
                  info  okernel: kaslr_slide 0x200000\r\n\
                  info  okernel: mapa de memória com 24 faixas\r\n\
                  info  okernel: identidade removida; 40 páginas\r\n\
                  info  okernel: heap: slab   16 B: 0 slabs\r\n";
        let check = |serial: &str| check_serial(serial, BOOT_MARKERS, SCENARIOS[0].forbidden);
        assert_eq!(check(ok), Ok(()));
        assert!(check("Optimus OS \u{2014} optboot\r\n").is_err());
        assert!(check(&ok.replace("okernel: hello", "okernel")).is_err());
        assert!(check(&ok.replace("R-X", "RWX")).is_err());
        assert!(check(&ok.replace("optboot: seg", "x")).is_err());
        assert!(check(&format!("{ok}okernel: FALTA #GP\r\n")).is_err());
    }

    #[test]
    fn relatorio_do_ktest() {
        let ok = "info  ktest: início, 2 testes\r\n\
                  info  ktest: ok a.b\r\n\
                  info  ktest: ok a.c\r\n\
                  info  ktest: fim: 2 ok, 0 falharam\r\n";
        assert_eq!(check_ktest(ok), Ok(()));
        assert!(check_ktest(&ok.replace("2 testes", "3 testes")).is_err());
        assert!(check_ktest(&ok.replace("0 falharam", "1 falharam")).is_err());
        assert!(check_ktest(&ok.replace("ktest: fim", "x")).is_err());
        assert!(
            check_ktest("info  ktest: início, 0 testes\r\nktest: fim: 0 ok, 0 falharam").is_err()
        );
        assert_eq!(parse(&args(&["kernel"])).unwrap().suite, "kernel");
    }

    #[test]
    fn crates_do_sistema_respeitam_a_regra_de_unsafe() {
        check_unsafe().unwrap();
    }
}
