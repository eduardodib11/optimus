//! `test=fuzz`: inicia o `okfuzz` (T-214), o fuzzer de syscalls, no lugar
//! do `root` (convenção em [`kabi::fuzz`]).
//!
//! `fuzz.seed=S` (decimal ou `0x` hexadecimal) e `fuzz.secs=N` na linha de
//! comando escolhem a semente e a duração. O kernel monta os processos, cada
//! um com duas threads, e espera as principais terminarem. Depois de soltar
//! os processos, confere que a cota raiz voltou ao que era antes deles: todo
//! objeto que o fuzzer criou, direta ou indiretamente, morreu e devolveu a
//! memória.
//!
//! Com várias CPUs (T-330) são `fuzz.procs=P` processos independentes (por
//! padrão, um por CPU ligada; com uma CPU, um só, como antes), cada um com
//! a semente derivada da base e as duas threads em CPUs vizinhas: o
//! processo `i` põe a principal na CPU `i % n` e a auxiliar na seguinte.
//! Assim todas as CPUs fazem syscalls ao mesmo tempo, sobre a cota raiz, o
//! heap, as tabelas de frames e as travas globais, e cada principal e sua
//! auxiliar ainda disputam o mesmo `CapSpace` de CPUs diferentes.
//!
//! Um pânico ou uma falta do kernel aparecem na serial como sempre; o
//! `cargo xtask fuzz` os procura, e também a falta de progresso.

use alloc::sync::Arc;

use kabi::fuzz::{BUFFER_MAIN, BUFFER_WORKER, Config};
use kabi::vm::{PAGE_SIZE, WRITE};
use okernel::log::option;
use okernel::thread::Thread;

use crate::kcap;
use crate::kroot::{self, STACK_BYTES, STACK_TOP};
use crate::kthread::{self, UserEntry};

/// Nome do fuzzer no bootfs.
pub const NAME: &str = "okfuzz";
/// Prioridade das duas threads (abaixo da do `root`, acima de nada).
const PRIORITY: u64 = 100;
/// Topo da pilha da thread auxiliar, com uma página de guarda até a da
/// principal.
const WORKER_STACK_TOP: u64 = STACK_TOP - STACK_BYTES - PAGE_SIZE;
/// Folga sobre a duração pedida antes de o kernel desistir de esperar.
const SLACK_NS: u64 = 600_000_000_000;
/// Processos no máximo (uma página de buffers de IPC por thread cabe, e o
/// teste não precisa de mais que um punhado por CPU).
const MAX_PROCS: usize = 16;
/// Passo da semente de um processo para o seguinte (o inverso áureo, para
/// as sementes não ficarem parecidas).
const SEED_STEP: u64 = 0x9e37_79b9_7f4a;

/// Número decimal ou hexadecimal com `0x`.
fn parse_u64(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Os bytes do `okfuzz` no bootfs, com o hash conferido. Confere uma vez
/// só, antes de qualquer processo rodar: o BLAKE3 de uma imagem inteira
/// leva mais de 1 s no TCG com o kernel de depuração, e o kernel roda com
/// IF=0, sem atender os shootdowns das outras CPUs enquanto calcula.
fn verified_image(image: &[u8]) -> Result<&[u8], &'static str> {
    let fs = obfs::Image::parse(image).map_err(|_| "bootfs inválido")?;
    let entry = fs.find(NAME).ok_or("bootfs sem okfuzz")?;
    if !entry.verify() {
        return Err("hash do okfuzz não confere");
    }
    Ok(entry.data)
}

/// Monta o processo `index` a partir do ELF já conferido e inicia as duas
/// threads, a principal na CPU `index % online` e a auxiliar na seguinte.
fn spawn(
    data: &[u8],
    config: Config,
    index: usize,
    online: usize,
) -> Result<[Arc<Thread>; 2], &'static str> {
    let elf = oelf::Elf::parse_user(data).map_err(|_| "ELF do okfuzz inválido")?;
    let p = kroot::image(&elf)?;
    kroot::map_stack(&p, WORKER_STACK_TOP)?;
    // O kernel mapeia os dois buffers de IPC (uma página cada): o `okfuzz`
    // não precisa conhecê-los.
    kroot::map_zeros(&p, BUFFER_MAIN, PAGE_SIZE, WRITE)?;
    kroot::map_zeros(&p, BUFFER_WORKER, PAGE_SIZE, WRITE)?;
    let mut threads = [None, None];
    for (slot, buffer) in threads.iter_mut().zip([BUFFER_MAIN, BUFFER_WORKER]) {
        let (h, t) = kroot::new_thread(&p, PRIORITY)?;
        t.set_ipc_buffer(buffer).map_err(|_| "buffer de IPC")?;
        // O fuzzer não recebe a própria thread: sem a capability, nenhum
        // ciclo thread ↔ CapSpace sobra quando ele termina.
        drop(p.cspace.lock().delete(h));
        *slot = Some(t);
    }
    let [Some(main), Some(worker)] = threads else {
        return Err("threads");
    };
    let raw = config.to_raw();
    let cpu = |i: usize| u32::try_from(i % online).map_err(|_| "cpu");
    let entries = [
        (
            &main,
            STACK_TOP,
            [p.quota, p.aspace].map(|h| u64::from(h.raw())),
            cpu(index)?,
        ),
        (&worker, WORKER_STACK_TOP, [0, 0], cpu(index + 1)?),
    ];
    for (t, rsp, [rdi, rsi], cpu) in entries {
        let e = UserEntry {
            rip: elf.entry(),
            rsp,
            args: [rdi, rsi, raw],
        };
        kthread::start_on(t, &e, cpu).map_err(|_| "thread_start")?;
    }
    Ok([main, worker])
}

/// Roda o `okfuzz` com a semente, a duração e o número de processos da
/// linha de comando.
pub fn run(cmdline: &str) {
    let online = crate::ksmp::start::online_count().max(1);
    let procs = option(cmdline, "fuzz.procs")
        .and_then(parse_u64)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(online)
        .clamp(1, MAX_PROCS);
    let base = Config {
        seed: option(cmdline, "fuzz.seed")
            .and_then(parse_u64)
            .unwrap_or(1),
        seconds: option(cmdline, "fuzz.secs")
            .and_then(parse_u64)
            .map_or(60, |s| u16::try_from(s).unwrap_or(u16::MAX)),
    };
    let base = Config::from_raw(base.to_raw());
    let Some(image) = kroot::bootfs() else {
        error!("okernel: sem bootfs; okfuzz não iniciado");
        return;
    };
    let Some(quota) = kcap::root_quota() else {
        error!("okernel: sem cota raiz; okfuzz não iniciado");
        return;
    };
    let data = match verified_image(image) {
        Ok(d) => d,
        Err(e) => {
            error!("okernel: okfuzz não iniciado: {e}");
            return;
        }
    };
    let used0 = quota.used();
    let mut running = alloc::vec::Vec::new();
    for index in 0..procs {
        let config = Config {
            seed: base.seed.wrapping_add(index as u64 * SEED_STEP),
            ..base
        };
        match spawn(data, config, index, online) {
            Ok(t) => {
                info!(
                    "okernel: okfuzz iniciado, semente {:#x}, {} s (processo {index} de {procs}, \
                     {online} CPU(s))",
                    Config::from_raw(config.to_raw()).seed,
                    config.seconds
                );
                running.push(t);
            }
            Err(e) => {
                error!("okernel: okfuzz não iniciado: {e}");
                return;
            }
        }
    }
    let limit = u64::from(base.seconds) * 1_000_000_000 + SLACK_NS;
    for [main, _] in &running {
        if !kroot::run_until_exit(main, limit) {
            error!("okernel: okfuzz não terminou no prazo");
            return;
        }
    }
    for [_, worker] in &running {
        if !kroot::run_until_exit(worker, 5_000_000_000) {
            error!("okernel: okfuzz: a thread auxiliar não terminou");
            return;
        }
    }
    drop(running);
    let used = quota.used();
    if used == used0 {
        info!("okernel: okfuzz terminou; cota raiz devolvida");
    } else {
        error!(
            "okernel: okfuzz terminou, mas a cota raiz não voltou: {} bytes a mais",
            used.wrapping_sub(used0).cast_signed()
        );
    }
}
