//! `cargo xtask`: orquestrador de build, imagem, QEMU e verificações (SDD v1.0, seção 16.3).
//!
//! Sem dependências externas: só `std` e as ferramentas do host (`cargo`, QEMU, OVMF).

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs, sync::mpsc, thread};

mod bench;
mod perfil;

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
    ("optcrypt", "lib/optcrypt/src/lib.rs", KERNEL_TARGET),
    ("obfs", "lib/obfs/src/lib.rs", KERNEL_TARGET),
    ("ostd", "lib/ostd/src/lib.rs", USER_TARGET),
    ("root", "services/root/src/main.rs", USER_TARGET),
    ("hello", "services/hello/src/main.rs", USER_TARGET),
    ("utest", "services/utest/src/main.rs", USER_TARGET),
    ("okfuzz", "fuzz/okfuzz/src/main.rs", USER_TARGET),
];

/// Bibliotecas portáveis cujos testes rodam no host.
const HOST_TESTED: &[&str] = &["obfs", "oelf", "optcrypt"];

const PROFILES: &[&str] = &["lite", "basic", "jarvis", "premium", "server"];

/// Textos que o smoke test exige na serial.
const BOOT_MARKERS: &[&str] = &[
    "optboot",
    "optboot: kernel carregado",
    "optboot: mapa de memória",
    "optboot: KASLR",
    "entradas verificadas (BLAKE3)",
    "saindo dos serviços de boot",
    "okernel: hello",
    "okernel: GDT, TSS e IDT carregadas",
    "okernel: kaslr_slide",
    DIRECT_MAP_LINE,
    "okernel: mapa de memória",
    "okernel: identidade removida",
    "okernel: heap: slab   16 B",
    "okernel: cota raiz de ",
    "okernel: relógio: TSC de",
    "okernel: root carregado do bootfs",
    "root: iniciado",
    "root: IPC sem par: TimedOut e WouldBlock",
    "hello: iniciado pelo root",
    "root: o hello disse:",
    "olá, root! aqui é o hello, pelo buffer de IPC",
    " ns por ida e volta com o hello",
    "okernel: root terminou",
];
/// Linha em que o kernel diz onde ficou o mapa direto (ADR 0026).
const DIRECT_MAP_LINE: &str = "okernel: mapa direto em ";
/// Status do QEMU quando o kernel escreve 0x10 no `isa-debug-exit`: `(0x10 << 1) | 1`.
const KERNEL_EXIT_OK: i32 = 33;
/// Status do QEMU quando o kernel sai com falha (0x11), como no pânico em teste.
const KERNEL_EXIT_FAILURE: i32 = 35;
/// Linha em que o pânico de `test=panic` espera o xtask capturar a tela.
const PANIC_WAIT: &str = "okernel: pânico registrado; aguardando confirmação na serial";
/// Textos que o cenário `test=panic` exige na serial (T-110).
const PANIC_MARKERS: &[&str] = &[
    "okernel: hello",
    "okernel: PÂNICO em kernel/okernel/src/main.rs:",
    ": pânico de teste proposital (test=panic)",
    "okernel: tela de pânico desenhada",
    PANIC_WAIT,
    "okernel: confirmação recebida",
];
/// Cor de fundo da tela de pânico (`okernel::console::PANIC_BACKGROUND`).
const PANIC_RGB: [u8; 3] = [0x80, 0x00, 0x00];
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
/// Limite dos testes de kernel: o ping-pong de IPC (10⁴ idas e voltas) leva
/// dezenas de segundos no build de depuração sob TCG.
const KTEST_TIMEOUT: Duration = Duration::from_mins(5);
/// Limite do `test hello`: 10⁶ idas e voltas levam por volta de um minuto
/// no build de release sob TCG.
const HELLO_TIMEOUT: Duration = Duration::from_mins(20);
/// Idas e voltas entre o `hello` e o `root` no boot normal do `test all`
/// (build de depuração) e no `test hello` (aceite do T-212, em release).
const BOOT_ROUNDS: u64 = 10_000;
const HELLO_ROUNDS: u64 = 1_000_000;
/// Idas e voltas no boot dos testes de kernel (o teste do `root` as faz).
const KTEST_ROUNDS: u64 = 100;

type Result<T = ()> = std::result::Result<T, String>;

/// Opções de linha de comando comuns aos subcomandos.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Idas e voltas do `hello` com o `root` (entrada `hello.rounds` do
    /// bootfs); `None` deixa o padrão do `root`.
    rounds: Option<u64>,
    /// Duração da rodada de `fuzz`, em segundos.
    seconds: u64,
    /// Semente de `fuzz` (`None`: sorteada do relógio).
    seed: Option<u64>,
    /// Duração do `stress`, em minutos.
    minutes: u64,
    /// `test user --falha-proposital`: compila o `utest` com o teste que
    /// falha de propósito (T-332).
    fail_on_purpose: bool,
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
            rounds: None,
            seconds: 60,
            seed: None,
            minutes: STRESS_MINUTES,
            fail_on_purpose: false,
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
            "--seconds" => {
                opts.seconds = value("--seconds")?
                    .parse()
                    .map_err(|_| "--seconds espera um número")?;
            }
            "--minutes" => {
                opts.minutes = value("--minutes")?
                    .parse()
                    .map_err(|_| "--minutes espera um número")?;
            }
            "--seed" => {
                let v = value("--seed")?;
                let seed = v
                    .strip_prefix("0x")
                    .map_or_else(|| v.parse(), |hex| u64::from_str_radix(hex, 16))
                    .map_err(|_| "--seed espera um número (decimal ou 0x…)")?;
                opts.seed = Some(seed);
            }
            "--falha-proposital" => opts.fail_on_purpose = true,
            "--rounds" => {
                opts.rounds = Some(
                    value("--rounds")?
                        .parse()
                        .map_err(|_| "--rounds espera um número")?,
                );
            }
            "unit" | "boot" | "kernel" | "smp" | "stress" | "hello" | "user" | "fuzz" | "all" => {
                opts.suite.clone_from(arg);
            }
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
        eprintln!("uso: cargo xtask <build|image|run|test|fuzz|check|kani|bench|perfil> [opções]");
        return ExitCode::FAILURE;
    };
    let result = parse(rest).and_then(|opts| match cmd.as_str() {
        "build" => build(&opts),
        "image" => build(&opts).and_then(|()| image(&opts, &opts.cmdline, opts.rounds).map(drop)),
        "run" => run(&opts),
        "test" => test(&opts),
        "fuzz" => fuzz(&opts),
        "check" => check(),
        "kani" => kani(),
        "bench" => bench::bench(&opts),
        "perfil" => perfil::perfil(&opts),
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
    build_with(opts, &[])
}

/// [`build`] com variáveis de ambiente a mais para o `cargo`.
fn build_with(opts: &Options, env: &[(&str, &str)]) -> Result {
    println!(
        "xtask: build {} perfil {} ({})",
        opts.arch,
        opts.profile,
        mode(opts)
    );
    for (package, _, target) in CRATES {
        let mut cmd = cargo();
        cmd.args(["build", "--package", package, "--target", target]);
        cmd.envs(env.iter().copied());
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
        // Binários de usuário: ET_EXEC no endereço de `lib/ostd/user.ld`
        // (o kernel ainda não reloca processos; ASLR de usuário depois).
        "root" | "hello" | "utest" | "okfuzz" => &["-C", "relocation-model=static"],
        _ => &[],
    }
}

/// Monta a ESP em `target/esp`, que o QEMU expõe como disco FAT virtual, com
/// `cmdline` como linha de comando do kernel (vazia: sem arquivo) e
/// `rounds` idas e voltas do `hello`.
fn image(opts: &Options, cmdline: &str, rounds: Option<u64>) -> Result<PathBuf> {
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
    bootfs(opts, &optimus.join("bootfs.obfs"), rounds)?;
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

/// Serviços do bootfs: (nome na imagem, binário de usuário).
const BOOTFS: &[(&str, &str)] = &[
    ("root", "root"),
    ("hello", "hello"),
    ("utest", "utest"),
    ("okfuzz", "okfuzz"),
];

/// Monta o bootfs com `tools/mkobfs` a partir dos binários de usuário e,
/// com `rounds`, a entrada `hello.rounds` que o `root` lê.
fn bootfs(opts: &Options, output: &Path, rounds: Option<u64>) -> Result {
    let bin = root().join(format!("target/{USER_TARGET}/{}", mode(opts)));
    let mut cmd = cargo();
    cmd.args(["run", "--quiet", "--package", "mkobfs", "--", "-o"])
        .arg(output);
    for (name, file) in BOOTFS {
        cmd.arg(format!("{name}={}", bin.join(file).display()));
    }
    if let Some(n) = rounds {
        let file = root().join("target/hello.rounds");
        fs::write(&file, format!("{n}\n"))
            .map_err(|e| format!("gravando {}: {e}", file.display()))?;
        cmd.arg(format!("hello.rounds={}", file.display()));
    }
    status(&mut cmd)
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
        // Sem KVM, o TCG emula tudo o que sabe (SMEP, SMAP, UMIP; x2APIC só
        // a partir do QEMU 9.0), para os testes de kernel exercitarem esses
        // caminhos.
        cmd.args(["-cpu", "max"]);
    }
    if opts.gdb {
        cmd.args(["-s", "-S"]);
    }
    // Opções a mais para depurar (`-s`, `-d cpu_reset`...), separadas por
    // espaço.
    if let Ok(extra) = env::var("OPTIMUS_QEMU_ARGS") {
        cmd.args(extra.split_whitespace());
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
    let esp = image(opts, &opts.cmdline, opts.rounds)?;
    let mut cmd = qemu(opts, &esp)?;
    let st = cmd
        .status()
        .map_err(|e| format!("falha ao executar o QEMU: {e}"))?;
    match st.code() {
        Some(0 | KERNEL_EXIT_OK) => Ok(()),
        _ => Err(format!("QEMU terminou com {st}")),
    }
}

/// Harness de testes que escreve um relatório na serial.
#[derive(Clone, Copy)]
enum Harness {
    /// `ktest`, dentro do kernel.
    Kernel,
    /// `utest`, serviço de usuário.
    User,
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
    /// Harness cujo relatório se confere e se mostra: `ktest` (kernel,
    /// T-111) ou `utest` (usuário, T-332).
    harness: Option<Harness>,
    /// Captura a tela pelo monitor do QEMU quando o pânico pedir e confere
    /// a tela de pânico (T-110).
    screen: bool,
    /// Idas e voltas do `hello` (entrada `hello.rounds` do bootfs).
    rounds: Option<u64>,
    /// Exige na serial que o `root` confirme as idas e voltas sem erro.
    hello: bool,
    /// Quanto esperar o QEMU.
    timeout: Duration,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "boot normal",
        cmdline: "",
        markers: BOOT_MARKERS,
        forbidden: &["okernel: FALTA", "PÂNICO"],
        exit: Some(KERNEL_EXIT_OK),
        harness: None,
        screen: false,
        rounds: Some(BOOT_ROUNDS),
        hello: true,
        timeout: SMOKE_TIMEOUT,
    },
    Scenario {
        name: "falta proposital",
        cmdline: "test=fault",
        markers: FAULT_MARKERS,
        forbidden: &["okernel: desligando"],
        exit: None,
        harness: None,
        screen: false,
        rounds: None,
        hello: false,
        timeout: SMOKE_TIMEOUT,
    },
    PANIC_SCENARIO,
];

/// Pânico proposital (T-110); com `smp.panic_cpu`, vindo de um AP (T-322).
const PANIC_SCENARIO: Scenario = Scenario {
    name: "pânico proposital",
    cmdline: "test=panic",
    markers: PANIC_MARKERS,
    forbidden: &["okernel: desligando", "okernel: FALTA"],
    exit: Some(KERNEL_EXIT_FAILURE),
    harness: None,
    screen: true,
    rounds: None,
    hello: false,
    timeout: SMOKE_TIMEOUT,
};

/// Testes de kernel (T-111): o kernel roda os testes registrados e sai com 33
/// se todos passarem.
const KERNEL_SCENARIO: Scenario = Scenario {
    name: "testes de kernel",
    cmdline: "test=kernel",
    markers: &[KTEST_START, KTEST_END],
    forbidden: &["ktest: FALHOU", "okernel: FALTA", "PÂNICO"],
    exit: Some(KERNEL_EXIT_OK),
    harness: Some(Harness::Kernel),
    screen: false,
    rounds: Some(KTEST_ROUNDS),
    hello: false,
    timeout: KTEST_TIMEOUT,
};

/// Aceite do T-324 (`cargo xtask test smp`): dois processos alternam 10⁶
/// vezes cada, em CPUs distintas, só com despertares de uma CPU para a
/// outra. Em release: cerca de um minuto sob TCG com 4 e 8 CPUs; com 2, o
/// QEMU demora mais a tirar uma vCPU do `hlt` e leva uns cinco.
const ALTERNATE_SCENARIO: Scenario = Scenario {
    name: "dois processos alternando 10⁶ vezes em CPUs distintas",
    cmdline: "test=kernel ktest=smp.dois_processos smp.alternate=1000000",
    timeout: Duration::from_mins(15),
    ..KERNEL_SCENARIO
};

/// Aceite do T-327 (em `cargo xtask test smp`, release): 10⁶ idas e voltas
/// de IPC com o servidor começando noutra CPU; ele segue quem chama e o
/// resto é troca direta na CPU do cliente.
const IPC_SCENARIO: Scenario = Scenario {
    name: "10⁶ idas e voltas de IPC com o servidor seguindo quem chama",
    cmdline: "test=kernel ktest=smp.ipc_servidor smp.ipc=1000000",
    timeout: Duration::from_mins(15),
    ..KERNEL_SCENARIO
};

/// Aceite do T-326 (em `cargo xtask test smp`, release): 10⁵ trocas de
/// mapeamento lidas por outra CPU sem nenhuma leitura pela tradução velha.
/// Sob TCG, cerca de meio minuto com 4 e 8 CPUs; com 2, uns três.
const SHOOTDOWN_SCENARIO: Scenario = Scenario {
    name: "10⁵ shootdowns sem tradução velha",
    cmdline: "test=kernel ktest=smp.shootdown_sem smp.shootdown=100000",
    timeout: Duration::from_mins(15),
    ..KERNEL_SCENARIO
};

/// Minutos do `cargo xtask test stress` sem `--minutes` (aceite do T-329).
const STRESS_MINUTES: u64 = 30;

/// CPUs do `cargo xtask test stress` sem `--smp`.
const STRESS_CPUS: u32 = 4;

/// Aceite do T-212 (`cargo xtask test hello`): o boot normal com 10⁶ idas
/// e voltas entre o `hello` e o `root`. Fica fora do `test all` pelo tempo.
const HELLO_SCENARIO: Scenario = Scenario {
    name: "hello com 10⁶ idas e voltas",
    cmdline: "",
    markers: BOOT_MARKERS,
    forbidden: &["okernel: FALTA", "PÂNICO"],
    exit: Some(KERNEL_EXIT_OK),
    harness: None,
    screen: false,
    rounds: Some(HELLO_ROUNDS),
    hello: true,
    timeout: HELLO_TIMEOUT,
};
/// Testes de usuário (T-332, `cargo xtask test user`): o kernel inicia o
/// serviço `utest` do bootfs no lugar do `root`, e ele escreve o relatório
/// na serial. O kernel sai com 33 quando o `utest` termina; quem diz se os
/// testes passaram é o relatório (`utest: fim: N ok, 0 falharam`).
const USER_SCENARIO: Scenario = Scenario {
    name: "testes de usuário",
    cmdline: "test=user",
    markers: &[UTEST_START, UTEST_END],
    forbidden: &["utest: FALHOU", "ostd: pânico", "okernel: FALTA", "PÂNICO"],
    exit: Some(KERNEL_EXIT_OK),
    harness: Some(Harness::User),
    screen: false,
    rounds: None,
    hello: false,
    timeout: KTEST_TIMEOUT,
};

/// Primeira linha do harness: `ktest: início, N testes`.
const KTEST_START: &str = "ktest: início, ";
/// Última linha do harness: `ktest: fim: N ok, M falharam`.
const KTEST_END: &str = "ktest: fim: ";
/// Mesmo relatório do `utest`.
const UTEST_START: &str = "utest: início, ";
const UTEST_END: &str = "utest: fim: ";

/// Dá boot em cada cenário e confere a serial com [`check_serial`]; com
/// mais de um boot, confere também que o mapa direto mudou de lugar.
fn smoke(opts: &Options, scenarios: &[Scenario]) -> Result {
    build(opts)?;
    let mut bases = Vec::new();
    for scenario in scenarios {
        let serial = boot_scenario(opts, scenario)?;
        bases.extend(direct_map_base(&serial));
    }
    check_direct_map_bases(&bases)
}

/// Base do mapa direto anunciada pelo kernel na serial.
fn direct_map_base(serial: &str) -> Option<u64> {
    let line = serial
        .lines()
        .find_map(|l| l.split_once(DIRECT_MAP_LINE))?
        .1;
    let hex = line.trim().strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

/// Com dois ou mais boots, a base do mapa direto não pode ter sido a mesma
/// em todos (ADR 0026; a chance de coincidir por acaso é de 1 em 2^16 por
/// par de boots).
fn check_direct_map_bases(bases: &[u64]) -> Result {
    if bases.len() >= 2 && bases.iter().all(|b| *b == bases[0]) {
        return Err(format!(
            "o mapa direto ficou em {:#x} em {} boots",
            bases[0],
            bases.len()
        ));
    }
    if bases.len() >= 2 {
        let list: Vec<String> = bases.iter().map(|b| format!("{b:#x}")).collect();
        println!("xtask: mapa direto mudou entre boots: {}", list.join(", "));
    }
    Ok(())
}

/// Dá boot num cenário e devolve a serial, se ela conferir.
fn boot_scenario(opts: &Options, sc: &Scenario) -> Result<String> {
    let esp = image(opts, sc.cmdline, sc.rounds)?;
    let monitor = root().join("target/qemu-monitor.sock");
    let mut cmd = qemu(opts, &esp)?;
    // O monitor também serve para ver onde as CPUs pararam se o boot
    // travar.
    let _ = fs::remove_file(&monitor);
    cmd.arg("-monitor")
        .arg(format!("unix:{},server=on,wait=off", monitor.display()));
    let stdin = if sc.screen {
        Stdio::piped()
    } else {
        Stdio::null()
    };
    let mut child = cmd
        .stdin(stdin)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("falha ao iniciar o QEMU: {e}"))?;
    let mut screen: Option<Result> = None;
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
        if sc.screen && screen.is_none() && String::from_utf8_lossy(&raw).contains(PANIC_WAIT) {
            let shot = check_panic_screen(&monitor);
            // Qualquer byte na serial libera o kernel para sair.
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(b"\n").and_then(|()| stdin.flush());
            }
            screen = Some(shot);
        }
        let frozen = sc.exit.is_none() && seen_all(&raw);
        if frozen || start.elapsed() > sc.timeout {
            if !frozen {
                println!("xtask: tempo esgotado em {}; estado das CPUs:", sc.name);
                println!("{}", monitor_dump(&monitor));
            }
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
        .and_then(|()| check_hello(&serial, sc))
        .and_then(|()| match sc.harness {
            Some(Harness::Kernel) => check_ktest(&serial),
            Some(Harness::User) => check_utest(&serial),
            None => Ok(()),
        })
        .and_then(|()| match (sc.screen, screen) {
            (false, _) => Ok(()),
            (true, Some(shot)) => shot,
            (true, None) => Err("a tela de pânico não foi capturada".into()),
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
            show_report(&serial, sc.harness);
            println!("xtask: smoke test de boot ok ({})", sc.name);
            Ok(serial.into_owned())
        }
        Err(e) => Err(format!(
            "smoke test de boot falhou ({}): {e}; serial:\n{serial}",
            sc.name
        )),
    }
}

/// Com `sc.hello`, exige a confirmação do `root` das idas e voltas pedidas
/// e mostra o tempo de cada uma.
fn check_hello(serial: &str, sc: &Scenario) -> Result {
    let Some(rounds) = sc.rounds.filter(|_| sc.hello) else {
        return Ok(());
    };
    let ok = format!("root: hello: {rounds} idas e voltas sem erro");
    if !serial.contains(&ok) {
        return Err(format!("faltou \"{ok}\""));
    }
    if let Some(line) = serial.lines().find(|l| l.contains("ns por ida e volta")) {
        println!("xtask: {}", line.trim().trim_start_matches("info  "));
    }
    Ok(())
}

/// Pede ao monitor do QEMU uma captura da tela e confere a tela de pânico:
/// a maior parte no vermelho do fundo e algum texto branco.
fn check_panic_screen(monitor: &Path) -> Result {
    let shot = root().join("target/panic-screen.ppm");
    let _ = fs::remove_file(&shot);
    let mut sock = UnixStream::connect(monitor).map_err(|e| format!("monitor do QEMU: {e}"))?;
    writeln!(sock, "screendump {}", shot.display()).map_err(|e| e.to_string())?;
    let start = Instant::now();
    loop {
        if let Ok(bytes) = fs::read(&shot)
            && let Some((width, height, pixels)) = parse_ppm(&bytes)
        {
            let count = |rgb: [u8; 3]| pixels.chunks(3).filter(|p| *p == rgb).count();
            let (red, white) = (count(PANIC_RGB), count([0xff; 3]));
            println!(
                "xtask: tela de pânico {width}x{height}: {red} pixels de fundo, {white} de texto"
            );
            return if red * 2 > width * height && white > 500 {
                Ok(())
            } else {
                Err("a captura não mostra a tela de pânico".into())
            };
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err("o QEMU não gravou a captura da tela".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Registradores de todas as CPUs e o APIC local da primeira, pelo monitor
/// do QEMU: onde um boot travado parou.
fn monitor_dump(monitor: &Path) -> String {
    let run = || -> std::io::Result<String> {
        let mut sock = UnixStream::connect(monitor)?;
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;
        writeln!(sock, "info registers -a")?;
        writeln!(sock, "info lapic")?;
        let (mut out, mut chunk) = (Vec::new(), [0u8; 4096]);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            match sock.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
                Err(_) if !out.is_empty() => break,
                Err(_) => {}
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    };
    run().unwrap_or_else(|e| format!("monitor do QEMU: {e}"))
}

/// Imagem PPM binária (P6, 8 bits) completa: largura, altura e pixels RGB.
fn parse_ppm(bytes: &[u8]) -> Option<(usize, usize, &[u8])> {
    let mut fields = Vec::new();
    let mut at = 0;
    while fields.len() < 4 {
        while bytes.get(at)?.is_ascii_whitespace() {
            at += 1;
        }
        let start = at;
        while !bytes.get(at)?.is_ascii_whitespace() {
            at += 1;
        }
        fields.push(std::str::from_utf8(&bytes[start..at]).ok()?);
    }
    let [magic, width, height, max] = fields[..] else {
        return None;
    };
    let (width, height): (usize, usize) = (width.parse().ok()?, height.parse().ok()?);
    let pixels = bytes.get(at + 1..)?;
    (magic == "P6" && max == "255" && pixels.len() == width * height * 3)
        .then_some((width, height, pixels))
}

/// Mostra as linhas do relatório do harness.
fn show_report(serial: &str, harness: Option<Harness>) {
    let prefix = match harness {
        Some(Harness::Kernel) => "ktest: ",
        Some(Harness::User) => "utest: ",
        None => return,
    };
    for line in serial.lines().filter_map(|l| l.split_once(prefix)) {
        println!("  {}", line.1.trim_end());
    }
}

/// Confere o relatório do harness de kernel (`ktest`).
fn check_ktest(serial: &str) -> Result {
    check_report(serial, "ktest", (KTEST_START, KTEST_END))
}

/// Confere o relatório do harness de usuário (`utest`, T-332).
fn check_utest(serial: &str) -> Result {
    check_report(serial, "utest", (UTEST_START, UTEST_END))
}

/// Confere o relatório de um harness (`ktest` ou `utest`): ao menos um
/// teste, todos anunciados rodaram e passaram.
fn check_report(serial: &str, harness: &str, (start, end): (&str, &str)) -> Result {
    let after = |prefix: &str| {
        serial
            .lines()
            .find_map(|l| l.split_once(prefix).map(|(_, rest)| rest.trim_end()))
    };
    let number =
        |text: Option<&str>| -> Option<usize> { text?.split_whitespace().next()?.parse().ok() };
    let announced = number(after(start)).ok_or(format!("sem a linha de início do {harness}"))?;
    let end = after(end).ok_or(format!("sem a linha de fim do {harness}"))?;
    let passed = number(Some(end)).ok_or(format!("linha de fim do {harness} ilegível"))?;
    let ok_prefix = format!("{harness}: ok ");
    let ok_lines = serial.lines().filter(|l| l.contains(&ok_prefix)).count();
    if announced == 0 {
        return Err(format!("nenhum teste do {harness} registrado"));
    }
    if !end.ends_with(", 0 falharam") {
        return Err(format!("testes do {harness} falharam: {end}"));
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
            "--exclude",
            "root",
            "--exclude",
            "okfuzz",
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
    if opts.suite == "smp" {
        smp(opts)?;
    }
    if opts.suite == "stress" {
        stress(opts)?;
    }
    if opts.suite == "hello" {
        // 10⁶ idas e voltas no build de depuração levariam horas sob TCG.
        let release = Options {
            release: true,
            ..opts.clone()
        };
        smoke(&release, &[HELLO_SCENARIO])?;
    }
    if matches!(opts.suite.as_str(), "user" | "all") && !opts.fail_on_purpose {
        smoke(opts, &[USER_SCENARIO])?;
    }
    if opts.suite == "user" && opts.fail_on_purpose {
        // Compila o `utest` com o teste que falha de propósito: o comando
        // tem de terminar com erro (o CI confere que o código é ≠ 0).
        build_with(opts, &[("UTEST_FALHA", "1")])?;
        boot_scenario(opts, &USER_SCENARIO)?;
        return Err("o teste que falha de propósito não derrubou o comando".into());
    }
    if matches!(opts.suite.as_str(), "fuzz" | "all") {
        // Rodada curta com semente fixa: breve o bastante para o CI, mas
        // já exercita todas as syscalls (`cargo xtask fuzz` roda o longo).
        run_fuzz(opts, FUZZ_SHORT_SECONDS, FUZZ_SHORT_SEED)?;
    }
    Ok(())
}

/// CPUs de `cargo xtask test smp` sem `--smp` (T-320); o CI roda 2 e 4,
/// um por job.
const SMP_COUNTS: &[u32] = &[2, 4, 8];

/// `cargo xtask test smp [--smp N]`: a suíte de kernel inteira com N CPUs
/// (só N com `--smp` maior que 1; senão 2, 4 e 8), exigindo que todas
/// tenham ligado, o pânico numa CPU secundária e, em release, a alternância
/// de 10⁶ vezes entre duas CPUs, os 10⁵ shootdowns e as 10⁶ idas e voltas
/// de IPC com o servidor seguindo quem chama, e uma rodada curta de
/// `okfuzz` com um processo por CPU.
fn smp(opts: &Options) -> Result {
    build(opts)?;
    let release = Options {
        release: true,
        ..opts.clone()
    };
    build(&release)?;
    let counts = if opts.smp > 1 {
        vec![opts.smp]
    } else {
        SMP_COUNTS.to_vec()
    };
    let mut bases = Vec::new();
    for n in counts {
        println!("xtask: suíte de kernel com -smp {n}");
        let serial = boot_scenario(
            &Options {
                smp: n,
                ..opts.clone()
            },
            &KERNEL_SCENARIO,
        )?;
        check_cpus_online(&serial, n)?;
        println!("xtask: -smp {n}: {n} CPUs ligadas, suíte de kernel ok");
        bases.extend(direct_map_base(&serial));
        // Pânico na última CPU: as outras congelam e o dump sai legível.
        let cpu = n - 1;
        let cmdline: &'static str =
            Box::leak(format!("test=panic smp.panic_cpu={cpu}").into_boxed_str());
        let serial = boot_scenario(
            &Options {
                smp: n,
                ..opts.clone()
            },
            &Scenario {
                name: "pânico numa CPU secundária",
                cmdline,
                ..PANIC_SCENARIO
            },
        )?;
        check_smp_panic(&serial, n, cpu)?;
        println!("xtask: -smp {n}: pânico na cpu{cpu} congelou as outras {cpu} CPUs");
        bases.extend(direct_map_base(&serial));
        let serial = boot_scenario(
            &Options {
                smp: n,
                ..release.clone()
            },
            &ALTERNATE_SCENARIO,
        )?;
        println!("xtask: -smp {n}: dois processos alternaram 10⁶ vezes em CPUs distintas");
        bases.extend(direct_map_base(&serial));
        let serial = boot_scenario(
            &Options {
                smp: n,
                ..release.clone()
            },
            &SHOOTDOWN_SCENARIO,
        )?;
        println!("xtask: -smp {n}: 10⁵ shootdowns sem leitura pela tradução velha");
        bases.extend(direct_map_base(&serial));
        let serial = boot_scenario(
            &Options {
                smp: n,
                ..release.clone()
            },
            &IPC_SCENARIO,
        )?;
        println!("xtask: -smp {n}: 10⁶ idas e voltas de IPC, servidor seguindo quem chama");
        bases.extend(direct_map_base(&serial));
        // Um okfuzz por CPU no build de depuração (T-330): pegou o kernel
        // calculando por mais de 1 s com IF=0 enquanto outra CPU esperava
        // o shootdown dele.
        run_fuzz(
            &Options {
                smp: n,
                ..opts.clone()
            },
            FUZZ_SMP_SECONDS,
            FUZZ_SHORT_SEED,
        )?;
        println!("xtask: -smp {n}: okfuzz em todas as CPUs sem pânico");
    }
    check_direct_map_bases(&bases)
}

/// `cargo xtask test stress [--smp N] [--minutes M]` (aceite do T-329):
/// o estresse SMP (IPC cruzado, mutex de futex, revogação concorrente no
/// CDT, criação e destruição de processos, shootdown e destruição de longe)
/// por `M` minutos (30) em `N` CPUs (4), no build de depuração, que liga a
/// verificação de ordem de travas. Não roda no CI: a suíte de kernel de
/// `test smp` já traz uma rodada curta dele.
fn stress(opts: &Options) -> Result {
    let smp = if opts.smp > 1 { opts.smp } else { STRESS_CPUS };
    let seconds = opts.minutes * 60;
    let cmdline: &'static str = Box::leak(
        format!("test=kernel ktest=smp.estresse smp.estresse_s={seconds}").into_boxed_str(),
    );
    println!("xtask: estresse SMP: {} min em -smp {smp}", opts.minutes);
    build(opts)?;
    let serial = boot_scenario(
        &Options {
            smp,
            ..opts.clone()
        },
        &Scenario {
            name: "estresse SMP",
            cmdline,
            // Poucas épocas por minuto na depuração, com folga de um quarto.
            timeout: Duration::from_secs(seconds + seconds / 4 + 600),
            ..KERNEL_SCENARIO
        },
    )?;
    check_cpus_online(&serial, smp)?;
    if !serial.contains("ktest: · ") || !serial.lines().any(|l| l.contains("épocas em")) {
        return Err("o estresse não imprimiu o resumo das épocas".into());
    }
    println!(
        "xtask: estresse SMP: {} min em -smp {smp} sem pânico nem trava",
        opts.minutes
    );
    Ok(())
}

/// Pânico SMP (ADR 0031, item 8): a dona é `cpu` e cada uma das outras
/// `n - 1` CPUs deixou o quadro na serial.
fn check_smp_panic(serial: &str, n: u32, cpu: u32) -> Result {
    if n < 2 {
        return Ok(());
    }
    let owner = format!("(cpu{cpu}): pânico de teste proposital");
    if !serial
        .lines()
        .any(|l| l.contains("okernel: PÂNICO em") && l.contains(&owner))
    {
        return Err(format!("o pânico não veio da cpu{cpu}"));
    }
    let others = n - 1;
    let summary = format!("okernel: {others} de {others} outras CPUs congeladas");
    if !serial.contains(&summary) {
        return Err(format!("faltou \"{summary}\""));
    }
    for other in (0..n).filter(|&c| c != cpu) {
        let line = format!("okernel: cpu{other} congelada: rip 0x");
        if !serial.contains(&line) {
            return Err(format!("faltou o quadro da cpu{other}"));
        }
    }
    Ok(())
}

/// Exige que o kernel tenha ligado todas as `n` CPUs da máquina.
fn check_cpus_online(serial: &str, n: u32) -> Result {
    if n < 2 {
        return Ok(());
    }
    let want = format!("okernel: {n} de {n} CPU(s) ligadas");
    if serial.contains(&want) {
        Ok(())
    } else {
        let got = serial
            .lines()
            .find(|l| l.contains("CPU(s) ligadas"))
            .map_or("nenhuma linha de CPUs ligadas", str::trim);
        Err(format!("faltou \"{want}\" ({got})"))
    }
}

/// Marcador de sucesso do `okfuzz`: a cota raiz voltou ao fim da rodada.
const FUZZ_OK: &str = "okernel: okfuzz terminou; cota raiz devolvida";
/// Texto que denuncia um kernel quebrado numa rodada de fuzz.
const FUZZ_BAD: &[&str] = &[
    "PÂNICO",
    "okernel: FALTA",
    "okernel: okfuzz não terminou no prazo",
    "não voltou",
];
/// Duração da rodada curta de fuzz dentro do `test all` (segundos).
const FUZZ_SHORT_SECONDS: u64 = 60;
/// Duração do fuzz de cada `-smp N` dentro de `test smp` (segundos).
const FUZZ_SMP_SECONDS: u64 = 20;
/// Semente fixa da rodada curta, para o `test all` ser reprodutível.
const FUZZ_SHORT_SEED: u64 = 0x0c_f022;

/// `cargo xtask fuzz [--seconds N] [--seed S]`: sobe o QEMU com
/// `test=fuzz`, roda o `okfuzz` por `N` segundos e falha se o kernel entrar
/// em pânico, tomar uma falta ou travar. A semente é impressa para
/// reproduzir com `--seed`.
fn fuzz(opts: &Options) -> Result {
    build(opts)?;
    let seed = opts.seed.unwrap_or_else(seed_from_clock) & ((1 << 48) - 1);
    run_fuzz(opts, opts.seconds, seed)
}

/// Semente dos 48 bits baixos do relógio do host.
fn seed_from_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |d| {
            u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(1)
        })
}

/// Sobe o QEMU com `test=fuzz`, semente `seed` e duração `seconds`, e
/// confere a serial.
fn run_fuzz(opts: &Options, seconds: u64, seed: u64) -> Result {
    let cmdline = format!("test=fuzz fuzz.seed=0x{seed:x} fuzz.secs={seconds}");
    println!("xtask: fuzz semente 0x{seed:x}, {seconds} s (repita com --seed 0x{seed:x})");
    let esp = image(opts, &cmdline, None)?;
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
    // Folga sobre a duração pedida: o kernel se dá `seconds + 600 s` antes
    // de desistir, e o host precisa viver mais para capturar a mensagem.
    let limit = Duration::from_secs(seconds + 800);
    let mut raw = Vec::new();
    let start = Instant::now();
    // `Ok(código)`: o QEMU saiu sozinho; `Err(())`: o host o matou por
    // tempo esgotado (travou).
    let end: std::result::Result<Option<i32>, ()> = loop {
        raw.extend(rx.try_iter().flatten());
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break Ok(st.code());
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            break Err(());
        }
        thread::sleep(Duration::from_millis(200));
    };
    let _ = reader.join();
    raw.extend(rx.try_iter().flatten());
    let serial = String::from_utf8_lossy(&raw);
    check_fuzz(&serial, end, seed)
}

/// Decide a rodada de fuzz: nenhum texto de kernel quebrado, o marcador de
/// sucesso e saída do QEMU com o código de sucesso.
fn check_fuzz(serial: &str, exit: std::result::Result<Option<i32>, ()>, seed: u64) -> Result {
    let fail = |why: String| {
        Err(format!(
            "fuzz falhou (semente 0x{seed:x}): {why};\n{serial}"
        ))
    };
    if let Some(bad) = FUZZ_BAD.iter().find(|m| serial.contains(*m)) {
        return fail(format!("a serial mostrou \"{bad}\""));
    }
    match exit {
        Err(()) => return fail("o QEMU travou (tempo esgotado sem o kernel sair)".into()),
        Ok(Some(KERNEL_EXIT_OK)) => {}
        Ok(code) => return fail(format!("o QEMU terminou com {code:?}")),
    }
    if !serial.contains(FUZZ_OK) {
        return fail("sem o marcador de sucesso do okfuzz".into());
    }
    for line in serial.lines().filter(|l| l.contains("okfuzz:")) {
        if let Some((_, rest)) = line.split_once("okfuzz:") {
            println!("  okfuzz:{}", rest.trim_end());
        }
    }
    println!("xtask: fuzz ok (semente 0x{seed:x})");
    Ok(())
}

/// Formatação, clippy em cada alvo e a regra de `unsafe` da seção 17.1.
fn check() -> Result {
    status(cargo().args(["fmt", "--all", "--check"]))?;
    for tool in ["xtask", "mkobfs"] {
        status(cargo().args([
            "clippy",
            "--package",
            tool,
            "--tests",
            "--",
            "-D",
            "warnings",
        ]))?;
    }
    // Bibliotecas testadas no host também passam pelo clippy com os testes.
    for package in HOST_TESTED {
        status(cargo().args([
            "clippy",
            "--package",
            package,
            "--tests",
            "--",
            "-D",
            "warnings",
        ]))?;
    }
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

/// Provas Kani da lógica portável do kernel (T-204); `KANI_ALL=1` roda
/// todas. O Kani é ferramenta de host, fora do toolchain fixado: `cargo
/// install --locked kani-verifier && cargo kani setup`.
fn kani() -> Result {
    let installed = Command::new("cargo-kani")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|st| st.success());
    if !installed {
        return Err(
            "Kani não instalado; rode `cargo install --locked kani-verifier && cargo kani setup`"
                .into(),
        );
    }
    let mut cmd = cargo();
    cmd.args(["kani", "--package", "okernel", "--lib"]);
    // As demais provas esgotam a memória do CBMC (ver `cap/space/proofs.rs`).
    if env::var_os("KANI_ALL").is_none() {
        for harness in KANI_HARNESSES {
            cmd.args(["--harness", harness]);
        }
    }
    status(&mut cmd)
}

/// Provas Kani que cabem na memória de uma máquina comum.
const KANI_HARNESSES: &[&str] = &[
    "cap::space::proofs::derive_nunca_aumenta",
    "cap::space::proofs::mint_nunca_aumenta",
];

fn check_unsafe() -> Result {
    let allowlist =
        fs::read_to_string(root().join("unsafe-allowlist.toml")).map_err(|e| e.to_string())?;
    let crates = CRATES
        .iter()
        .map(|(_, file, _)| *file)
        .chain(["xtask/src/main.rs", "tools/mkobfs/src/main.rs"]);
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
        let opts = parse(&args(&["hello", "--rounds", "7"])).unwrap();
        assert_eq!((opts.suite.as_str(), opts.rounds), ("hello", Some(7)));
        assert!(parse(&args(&["--rounds", "x"])).is_err());
    }

    #[test]
    fn utest_confere_o_relatorio() {
        let ok = "info  utest: início, 2 testes\r\n\
                  info  utest: ok a\r\n\
                  info  utest: ok b\r\n\
                  info  utest: fim: 2 ok, 0 falharam\r\n";
        assert_eq!(check_utest(ok), Ok(()));
        // Teste que falha: o relatório diz, e o `xtask` recusa.
        let bad = "info  utest: início, 2 testes\r\n\
                   info  utest: ok a\r\n\
                   info  utest: FALHOU b: motivo\r\n\
                   info  utest: fim: 1 ok, 1 falharam\r\n";
        assert!(check_utest(bad).unwrap_err().contains("falharam"));
        // Sem relatório (o `utest` morreu no meio): também recusa.
        assert!(check_utest("info  utest: início, 1 testes\r\n").is_err());
        assert!(check_utest("").is_err());
        // Linha ok a menos do que o anunciado.
        let short = "utest: início, 2 testes\nutest: ok a\nutest: fim: 2 ok, 0 falharam\n";
        assert!(check_utest(short).is_err());
        // O cenário também recusa a linha de falha, mesmo com o resto ok.
        assert!(check_serial(bad, &[UTEST_START], USER_SCENARIO.forbidden).is_err());
    }

    #[test]
    fn le_a_suite_user_com_falha_proposital() {
        let opts = parse(&args(&["user", "--falha-proposital"])).unwrap();
        assert_eq!((opts.suite.as_str(), opts.fail_on_purpose), ("user", true));
        assert!(!parse(&args(&["user"])).unwrap().fail_on_purpose);
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
                  optboot: bootfs com 1 entradas verificadas (BLAKE3) em 0x1000\r\n\
                  optboot: tabelas de página prontas; saindo dos serviços de boot\r\n\
                  info  okernel: hello\r\n\
                  info  okernel: GDT, TSS e IDT carregadas\r\n\
                  info  okernel: kaslr_slide 0x200000\r\n\
                  info  okernel: mapa direto em 0xffff823c00000000\r\n\
                  info  okernel: mapa de memória com 24 faixas\r\n\
                  info  okernel: identidade removida; 40 páginas\r\n\
                  info  okernel: heap: slab   16 B: 0 slabs\r\n\
                  info  okernel: cota raiz de 28000 KiB\r\n\
                  info  okernel: relógio: TSC de 2100000 kHz\r\n\
                  info  okernel: root carregado do bootfs (856 KiB), iniciando no anel 3\r\n\
                  info  root: iniciado\r\n\
                  info  root: IPC sem par: TimedOut e WouldBlock\r\n\
                  info  hello: iniciado pelo root\r\n\
                  info  root: o hello disse:\r\n\
                  info  olá, root! aqui é o hello, pelo buffer de IPC\r\n\
                  info  root: 812 ns por ida e volta com o hello\r\n\
                  info  root: hello: 10000 idas e voltas sem erro\r\n\
                  info  okernel: root terminou\r\n";
        let check = |serial: &str| check_serial(serial, BOOT_MARKERS, SCENARIOS[0].forbidden);
        assert_eq!(check(ok), Ok(()));
        assert!(check("Optimus OS \u{2014} optboot\r\n").is_err());
        assert!(check(&ok.replace("okernel: hello", "okernel")).is_err());
        assert!(check(&ok.replace("R-X", "RWX")).is_err());
        assert!(check(&ok.replace("optboot: seg", "x")).is_err());
        assert!(check(&format!("{ok}okernel: FALTA #GP\r\n")).is_err());
        assert_eq!(check_hello(ok, &SCENARIOS[0]), Ok(()));
        assert!(check_hello(ok, &HELLO_SCENARIO).is_err());
        assert_eq!(check_hello("", &KERNEL_SCENARIO), Ok(()));
    }

    #[test]
    fn mapa_direto_precisa_mudar_entre_boots() {
        let serial = "info  okernel: mapa direto em 0xffff823c00000000\r\n";
        assert_eq!(direct_map_base(serial), Some(0xffff_823c_0000_0000));
        assert_eq!(direct_map_base("okernel: hello"), None);
        assert!(check_direct_map_bases(&[1, 1, 1]).is_err());
        assert!(check_direct_map_bases(&[1, 2, 1]).is_ok());
        assert!(check_direct_map_bases(&[1]).is_ok());
    }

    #[test]
    fn le_ppm_completo() {
        let mut ppm = b"P6\n2 1\n255\n".to_vec();
        ppm.extend_from_slice(&[0x80, 0, 0, 0xff, 0xff, 0xff]);
        let (w, h, px) = parse_ppm(&ppm).unwrap();
        assert_eq!((w, h, px.len()), (2, 1, 6));
        assert!(parse_ppm(&ppm[..ppm.len() - 1]).is_none());
        assert!(parse_ppm(b"P3\n1 1\n255\nabc").is_none());
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
    fn suite_smp_exige_todas_as_cpus() {
        let opts = parse(&args(&["stress", "--smp", "4", "--minutes", "2"])).unwrap();
        assert_eq!(
            (opts.suite.as_str(), opts.smp, opts.minutes),
            ("stress", 4, 2)
        );
        assert_eq!(parse(&args(&["stress"])).unwrap().minutes, STRESS_MINUTES);
        assert!(parse(&args(&["--minutes", "x"])).is_err());
        let opts = parse(&args(&["smp", "--smp", "4"])).unwrap();
        assert_eq!((opts.suite.as_str(), opts.smp), ("smp", 4));
        let serial = "info  okernel: cpu3 online (APIC 3)\r\n\
                      info  okernel: 4 de 4 CPU(s) ligadas\r\n";
        assert_eq!(check_cpus_online(serial, 4), Ok(()));
        assert!(check_cpus_online(serial, 8).is_err());
        assert!(check_cpus_online(&serial.replace("4 de 4", "3 de 4"), 4).is_err());
        assert_eq!(check_cpus_online("", 1), Ok(()));
    }

    #[test]
    fn panico_smp_exige_dona_e_quadros() {
        let serial = "okernel: PÂNICO em kernel/okernel/src/main.rs:1:2 (cpu1): pânico de teste proposital (test=panic)\n\
                      okernel: 1 de 1 outras CPUs congeladas\n\
                      okernel: cpu0 congelada: rip 0xffff rsp 0x1\n";
        assert_eq!(check_smp_panic(serial, 2, 1), Ok(()));
        assert!(check_smp_panic(serial, 2, 0).is_err());
        assert!(
            check_smp_panic(
                &serial.replace("cpu0 congelada", "cpu0 não respondeu"),
                2,
                1
            )
            .is_err()
        );
        assert!(check_smp_panic(&serial.replace("1 de 1", "0 de 1"), 2, 1).is_err());
        assert_eq!(check_smp_panic("", 1, 0), Ok(()));
    }

    #[test]
    fn crates_do_sistema_respeitam_a_regra_de_unsafe() {
        check_unsafe().unwrap();
    }
}
