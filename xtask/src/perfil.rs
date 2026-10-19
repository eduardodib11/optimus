//! `cargo xtask perfil`: perfil instrução a instrução de uma ida e volta de
//! IPC e de uma troca de contexto (T-331).
//!
//! Dá boot no kernel de release, com tabela de linhas, com `test=perfil`
//! (os benchmarks de `kernel/okernel/src/kbench.rs` em laço), liga o gdb
//! ao gdbstub do QEMU e, com `tools/perfil/perfil.py`, segue uma volta
//! inteira com `stepi`. O relatório conta as instruções por função, por
//! arquivo e por linha, e as caras (atômicos, troca de CR3, FPU, MSRs). Vai
//! para `docs/bench/<data>-<commit>-perfil.md`, que também imprime.
//!
//! Ao contrário do tempo, a contagem não depende do acelerador: é a mesma
//! no TCG e em KVM, o que a torna a medida do caminho onde não há KVM.

use std::fmt::Write as _;
use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, sync::mpsc, thread};

use super::{KERNEL_TARGET, Options, Result, build_with, image, mode, qemu, root};
use crate::bench::{fields, line, meta};

/// Tabela de linhas no kernel de release: muda só a informação de
/// depuração, não o código.
const DEBUG_ENV: (&str, &str) = ("CARGO_PROFILE_RELEASE_DEBUG", "line-tables-only");
/// Linha da serial quando o laço dos benchmarks começa.
const READY: &str = "perfil: pronto";
/// Prefixo do deslocamento de KASLR na serial.
const SLIDE: &str = "kaslr_slide ";
const BOOT_TIMEOUT: Duration = Duration::from_mins(5);
/// Cada volta leva segundos; o tempo vai em parar nas syscalls até ela.
const GDB_TIMEOUT: Duration = Duration::from_mins(15);
/// Entradas da syscall ignoradas antes da volta seguida (aquecimento).
const SKIP: u32 = 100;
/// As voltas seguidas: a syscall que as abre e o título.
const ROUNDS: &[(u32, &str)] = &[
    (20, "IPC `ipc_call` → `ipc_reply_recv`, ida e volta"),
    (
        28,
        "Troca de contexto entre processos (`yield`, ida e volta)",
    ),
];

/// Faz o perfil e grava o relatório.
pub fn perfil(opts: &Options) -> Result {
    let opts = Options {
        release: true,
        ..opts.clone()
    };
    build_with(&opts, &[DEBUG_ENV])?;
    let esp = image(&opts, "test=perfil", None)?;
    let port = free_port()?;
    let mut cmd = qemu(&opts, &esp)?;
    cmd.args(["-gdb", &format!("tcp:127.0.0.1:{port}")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let mut qemu = cmd
        .spawn()
        .map_err(|e| format!("falha ao iniciar o QEMU: {e}"))?;
    let result = profile(&opts, &mut qemu, port);
    let _ = qemu.kill();
    let _ = qemu.wait();
    let report = result?;
    let meta = meta();
    let dir = root().join("docs/bench");
    fs::create_dir_all(&dir).map_err(|e| format!("criando {}: {e}", dir.display()))?;
    let file = dir.join(format!("{}-{}-perfil.md", meta.date, meta.commit));
    let report = format!(
        "# Perfil do caminho de IPC e da troca de contexto ({})\n\n\
         - Commit: `{}`\n\
         - Comando: `cargo xtask perfil` (kernel e serviços em release, com \
         tabela de linhas; `-smp {}`)\n\
         - CPU do host: {}\n\
         - QEMU: {}\n\
         {report}",
        meta.date, meta.commit, opts.smp, meta.host_cpu, meta.qemu
    );
    fs::write(&file, &report).map_err(|e| format!("gravando {}: {e}", file.display()))?;
    println!("{report}");
    println!("xtask: relatório em {}", file.display());
    Ok(())
}

/// Espera o laço dos benchmarks e segue cada volta de [`ROUNDS`]; devolve
/// o corpo do relatório.
fn profile(opts: &Options, qemu: &mut Child, port: u16) -> Result<String> {
    let mut stdout = qemu.stdout.take().ok_or("QEMU sem saída")?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n @ 1..) = stdout.read(&mut chunk) {
            if tx.send(chunk[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut raw = Vec::new();
    let start = Instant::now();
    let serial = loop {
        raw.extend(rx.try_iter().flatten());
        let text = String::from_utf8_lossy(&raw).into_owned();
        if text.contains(READY) {
            break text;
        }
        if qemu.try_wait().map_err(|e| e.to_string())?.is_some() || start.elapsed() > BOOT_TIMEOUT {
            return Err(format!("o kernel não chegou a `{READY}`; serial:\n{text}"));
        }
        thread::sleep(Duration::from_millis(100));
    };
    let slide = serial
        .lines()
        .find_map(|l| l.split_once(SLIDE))
        .and_then(|(_, rest)| rest.split([',', ' ', '\r']).next())
        .ok_or("sem o deslocamento de KASLR na serial")?
        .to_string();
    let env = line(&serial, "ambiente").map(fields).unwrap_or_default();
    let get = |k: &str| {
        env.iter()
            .find(|(key, _)| *key == k)
            .map_or("?", |(_, v)| *v)
    };
    let mut md = format!(
        "- Acelerador: {}\n- CPU do convidado: {}\n\n\
         Cada seção segue uma volta inteira, da entrada da syscall que a abre \
         até a volta ao anel 3 de quem a fez, com `stepi` pelo gdbstub do \
         QEMU (sem interrupções no passo a passo), depois de {SKIP} voltas \
         de aquecimento. A estimativa de ciclos só ordena as causas: conta \
         um ciclo por instrução comum e um custo típico para as caras, sem \
         faltas de cache e de TLB; o tempo de verdade é o do `cargo xtask \
         bench` em KVM.\n\n",
        get("acelerador"),
        get("cpu"),
    );
    let kernel = root().join(format!("target/{KERNEL_TARGET}/{}/okernel", mode(opts)));
    let section = root().join("target/perfil-secao.md");
    for &(nr, title) in ROUNDS {
        let _ = fs::remove_file(&section);
        println!("xtask: perfil de {title}");
        let mut gdb = Command::new("gdb")
            .args(["-nx", "-batch", "-x"])
            .arg(root().join("tools/perfil/perfil.py"))
            .env("PERFIL_KERNEL", &kernel)
            .env("PERFIL_SLIDE", &slide)
            .env("PERFIL_PORT", port.to_string())
            .env("PERFIL_NR", nr.to_string())
            .env("PERFIL_SKIP", SKIP.to_string())
            .env("PERFIL_TITLE", title)
            .env("PERFIL_OUT", &section)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("falha ao iniciar o gdb: {e}"))?;
        let ok = wait(&mut gdb, GDB_TIMEOUT)?;
        let mut err = String::new();
        if let Some(mut e) = gdb.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        let text = fs::read_to_string(&section).unwrap_or_default();
        if !ok || text.is_empty() {
            return Err(format!("o gdb não terminou o perfil de {title}:\n{err}"));
        }
        writeln!(md, "{text}").map_err(|e| e.to_string())?;
    }
    raw.extend(rx.try_iter().flatten());
    let serial = String::from_utf8_lossy(&raw);
    if serial.contains("FALHOU") || serial.contains("PÂNICO") {
        return Err(format!(
            "o kernel falhou durante o perfil; serial:\n{serial}"
        ));
    }
    Ok(md)
}

/// Uma porta TCP livre no host para o gdbstub.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    Ok(port)
}

/// Espera `child` terminar em até `limit`; `false` se não terminou bem (e
/// o mata, se passou do prazo).
fn wait(child: &mut Child, limit: Duration) -> Result<bool> {
    let start = Instant::now();
    loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(st.success());
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(200));
    }
}
