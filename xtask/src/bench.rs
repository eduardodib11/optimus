//! `cargo xtask bench`: benchmarks de IPC e de troca de contexto (T-213).
//!
//! Dá boot no kernel de release com `test=bench`, lê as linhas `bench:`
//! da serial (ver `kernel/okernel/src/kbench.rs`) e grava o relatório em
//! `docs/bench/<data>-<commit>.md`, que também imprime. Com `/dev/kvm`
//! acessível o QEMU roda com KVM; sem ele, com TCG, e o relatório avisa
//! que os números não valem para as metas do SDD.

use std::fmt::Write as _;
use std::fs;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{KERNEL_EXIT_OK, Options, Result, Scenario, boot_scenario, build, root};

/// O boot dos benchmarks.
const BENCH_SCENARIO: Scenario = Scenario {
    name: "benchmarks",
    cmdline: "test=bench",
    markers: &["bench: ambiente", "bench: fim"],
    forbidden: &["FALHOU", "okernel: FALTA", "PÂNICO"],
    exit: Some(KERNEL_EXIT_OK),
    harness: None,
    screen: false,
    rounds: None,
    hello: false,
    timeout: Duration::from_mins(10),
};

/// Benchmarks na ordem do relatório: nome na serial, descrição e meta do
/// SDD (seção 20.3, T-213; em KVM).
const ROWS: &[(&str, &str, &str)] = &[
    (
        "ipc_call_reply_recv",
        "IPC `ipc_call` → `ipc_reply_recv`, ida e volta",
        "≤ 1 µs",
    ),
    (
        "troca_de_contexto_entre_processos",
        "Troca de contexto entre processos (por troca)",
        "≤ 2 µs",
    ),
    (
        "troca_de_contexto_mesmo_processo",
        "Troca de contexto no mesmo processo (por troca)",
        "—",
    ),
];

/// O que o relatório diz do ambiente além da serial.
pub struct Meta {
    /// Data UTC (`AAAA-MM-DD`).
    pub date: String,
    /// Commit curto, com `-sujo` se a árvore tiver mudanças.
    pub commit: String,
    /// CPU do host.
    pub host_cpu: String,
    /// Kernel do host.
    pub host_kernel: String,
    /// Versão do QEMU.
    pub qemu: String,
}

/// Roda os benchmarks e grava o relatório.
pub fn bench(opts: &Options) -> Result {
    let opts = Options {
        release: true,
        ..opts.clone()
    };
    build(&opts)?;
    let serial = boot_scenario(&opts, &BENCH_SCENARIO)?;
    let meta = meta();
    let report = report(&serial, &meta, opts.smp)?;
    let dir = root().join("docs/bench");
    fs::create_dir_all(&dir).map_err(|e| format!("criando {}: {e}", dir.display()))?;
    // Com mais de uma CPU, o relatório não sobrescreve o de uma.
    let smp = if opts.smp > 1 {
        format!("-smp{}", opts.smp)
    } else {
        String::new()
    };
    let file = dir.join(format!("{}-{}{smp}.md", meta.date, meta.commit));
    fs::write(&file, &report).map_err(|e| format!("gravando {}: {e}", file.display()))?;
    println!("{report}");
    println!("xtask: relatório em {}", file.display());
    Ok(())
}

fn output(cmd: &mut Command) -> Option<String> {
    let out = cmd.current_dir(root()).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn meta() -> Meta {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let commit = output(Command::new("git").args(["rev-parse", "--short", "HEAD"]))
        .unwrap_or_else(|| "desconhecido".into());
    // Relatórios ainda não commitados em docs/bench não sujam a árvore.
    let status = ["status", "--porcelain", "--", ".", ":!docs/bench"];
    let dirty = output(Command::new("git").args(status)).is_some_and(|s| !s.is_empty());
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    Meta {
        date: civil_date(secs),
        commit: if dirty {
            format!("{commit}-sujo")
        } else {
            commit
        },
        host_cpu: cpuinfo
            .lines()
            .find_map(|l| l.strip_prefix("model name"))
            .map_or("?", |l| l.trim_start_matches([' ', '\t', ':']))
            .to_string(),
        host_kernel: fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_or_else(|_| "?".into(), |s| s.trim().to_string()),
        qemu: output(Command::new("qemu-system-x86_64").arg("--version"))
            .and_then(|s| s.lines().next().map(str::to_string))
            .unwrap_or_else(|| "?".into()),
    }
}

/// `AAAA-MM-DD` (UTC) de `secs` desde 1970 (algoritmo `civil_from_days`
/// de Howard Hinnant).
fn civil_date(secs: u64) -> String {
    let z = i64::try_from(secs / 86_400).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

/// `ns` legível: µs com duas casas a partir de 1 µs.
fn human(ns: u64) -> String {
    if ns < 1000 {
        format!("{ns} ns")
    } else {
        format!("{},{:02} µs", ns / 1000, (ns % 1000) / 10)
    }
}

/// Campos `chave=valor` de uma linha `bench:` (valores com aspas inteiros).
pub fn fields(line: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some((key, tail)) = rest.trim_start().split_once('=') {
        let key = key.rsplit(' ').next().unwrap_or(key);
        let (value, tail) = if let Some(quoted) = tail.strip_prefix('"') {
            quoted.split_once('"').unwrap_or((quoted, ""))
        } else {
            tail.split_once(' ').unwrap_or((tail, ""))
        };
        out.push((key, value));
        rest = tail;
    }
    out
}

/// A linha `bench: <nome> ...` da serial, sem o prefixo.
pub fn line<'a>(serial: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("bench: {name} ");
    serial.lines().find_map(|l| {
        l.split_once(prefix.as_str())
            .map(|(_, rest)| rest.trim_end())
    })
}

/// O relatório em markdown, de uma rodada com `smp` CPUs.
pub fn report(serial: &str, meta: &Meta, smp: u32) -> Result<String> {
    let env = line(serial, "ambiente").ok_or("sem a linha bench: ambiente")?;
    let env = fields(env);
    let get = |k: &str| {
        env.iter()
            .find(|(key, _)| *key == k)
            .map_or("?", |(_, v)| *v)
    };
    let accel = get("acelerador");
    let mut md = format!(
        "# Benchmarks de IPC e troca de contexto ({})\n\n\
         - Commit: `{}`\n\
         - Comando: `cargo xtask bench{}` (kernel e serviços em release; \
         `-smp {smp}`, o par de cada benchmark preso a uma CPU)\n\
         - Acelerador: {accel}\n\
         - CPU do convidado: {}\n\
         - TSC: {} kHz; APIC {}; timer {}\n\
         - CPU do host: {}\n\
         - Kernel do host: {}\n\
         - QEMU: {}\n\n",
        meta.date,
        meta.commit,
        if smp > 1 {
            format!(" --smp {smp}")
        } else {
            String::new()
        },
        get("cpu"),
        get("tsc_khz"),
        get("apic"),
        get("timer"),
        meta.host_cpu,
        meta.host_kernel,
        meta.qemu,
    );
    if accel != "KVM" {
        md.push_str(
            "> **Sem KVM:** estes números vêm do TCG, que emula cada instrução, \
             e servem só para comparar versões do kernel na mesma máquina. Eles \
             não valem para as metas do SDD (≤ 1 µs e ≤ 2 µs em KVM). Rode \
             `cargo xtask bench` num host com `/dev/kvm` acessível para medir \
             as metas.\n\n",
        );
    }
    md.push_str(
        "| Benchmark | Amostras | Mediana | p99 | Mín. | Máx. | Média | Meta (KVM) |\n\
         |---|---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for (name, label, goal) in ROWS {
        let row = line(serial, name).ok_or_else(|| format!("sem a linha bench: {name}"))?;
        let f = fields(row);
        let num = |k: &str| -> Result<u64> {
            f.iter()
                .find(|(key, _)| *key == k)
                .and_then(|(_, v)| v.parse().ok())
                .ok_or_else(|| format!("bench: {name} sem {k}"))
        };
        writeln!(
            md,
            "| {label} | {} | {} | {} | {} | {} | {} | {goal} |",
            num("n")?,
            human(num("mediana_ns")?),
            human(num("p99_ns")?),
            human(num("min_ns")?),
            human(num("max_ns")?),
            human(num("media_ns")?),
        )
        .map_err(|e| e.to_string())?;
    }
    md.push_str(
        "\n## Método\n\n\
         O kernel roda com `test=bench` (`kernel/okernel/src/kbench.rs`): \
         threads de usuário com o código de `arch/x86_64/user.S`, prioridade \
         100 e orçamento sem limite, medem no anel 3 cada syscall com \
         `LFENCE; RDTSC` antes e depois; as 1000 primeiras voltas são \
         descartadas e as 10 000 seguintes entram nas estatísticas, \
         convertidas em ns pela frequência do TSC calibrada contra o HPET.\n\n\
         - IPC: um cliente chama (`ipc_call`, só o rótulo, 0 palavras) e um \
         servidor em outro processo responde com `ipc_reply_recv`; os dois \
         sentidos usam a troca direta do caminho rápido. A amostra é a ida e \
         volta inteira, vista pelo cliente.\n\
         - Troca de contexto: duas threads de mesma prioridade alternam com \
         `yield`; a amostra (duas trocas, a ida e a volta) é dividida por \
         dois. Entre processos há troca de CR3; no mesmo processo, não.\n\n\
         Os máximos incluem disparos do timer e, no TCG, preempções do \
         QEMU pelo host; mediana e p99 são as medidas de referência.\n",
    );
    Ok(md)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERIAL: &str = "info  bench: ambiente cpu=\"QEMU TCG CPU version 2.5+\" acelerador=TCG tsc_khz=2100078 apic=XApic timer=one-shot\r\n\
        info  bench: ipc_call_reply_recv n=10000 mediana_ns=61963 p99_ns=130410 min_ns=33501 max_ns=4114760 media_ns=58536\r\n\
        info  bench: troca_de_contexto_entre_processos n=10000 mediana_ns=24888 p99_ns=57504 min_ns=13203 max_ns=2914261 media_ns=26529\r\n\
        info  bench: troca_de_contexto_mesmo_processo n=10000 mediana_ns=707 p99_ns=41613 min_ns=5874 max_ns=1917219 media_ns=13884\r\n\
        info  bench: fim\r\n";

    fn meta() -> Meta {
        Meta {
            date: "2026-10-11".into(),
            commit: "abc1234".into(),
            host_cpu: "Xeon".into(),
            host_kernel: "6.1".into(),
            qemu: "QEMU 8.2.2".into(),
        }
    }

    #[test]
    fn relatorio_com_mediana_p99_e_aviso_do_tcg() {
        let md = report(SERIAL, &meta(), 1).unwrap();
        assert!(md.contains("Commit: `abc1234`"));
        assert!(md.contains("CPU do convidado: QEMU TCG CPU version 2.5+"));
        assert!(md.contains(
            "| IPC `ipc_call` → `ipc_reply_recv`, ida e volta | 10000 | 61,96 µs | 130,41 µs |"
        ));
        assert!(md.contains("| 707 ns |"));
        assert!(md.contains("**Sem KVM:**"));
        let kvm = SERIAL.replace("acelerador=TCG", "acelerador=KVM");
        assert!(!report(&kvm, &meta(), 1).unwrap().contains("Sem KVM"));
        let missing = SERIAL.replace("bench: troca_de_contexto_mesmo_processo", "x");
        assert!(report(&missing, &meta(), 1).is_err());
    }

    #[test]
    fn datas_civis() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(951_782_400), "2000-02-29");
        assert_eq!(civil_date(1_791_676_800), "2026-10-11");
    }
}
