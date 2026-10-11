//! `test=fuzz`: inicia o `okfuzz` (T-214), o fuzzer de syscalls, no lugar
//! do `root` (convenção em [`kabi::fuzz`]).
//!
//! `fuzz.seed=S` (decimal ou `0x` hexadecimal) e `fuzz.secs=N` na linha de
//! comando escolhem a semente e a duração. O kernel monta o processo com
//! duas threads e espera a principal terminar. Depois de soltar o processo,
//! confere que a cota raiz voltou ao que era antes dele: todo objeto que o
//! fuzzer criou, direta ou indiretamente, morreu e devolveu a memória.
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

/// Número decimal ou hexadecimal com `0x`.
fn parse_u64(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Monta o processo e inicia as duas threads.
fn spawn(image: &[u8], config: Config) -> Result<[Arc<Thread>; 2], &'static str> {
    let fs = obfs::Image::parse(image).map_err(|_| "bootfs inválido")?;
    let entry = fs.find(NAME).ok_or("bootfs sem okfuzz")?;
    if !entry.verify() {
        return Err("hash do okfuzz não confere");
    }
    let elf = oelf::Elf::parse_user(entry.data).map_err(|_| "ELF do okfuzz inválido")?;
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
    let entries = [
        (
            &main,
            STACK_TOP,
            [p.quota, p.aspace].map(|h| u64::from(h.raw())),
        ),
        (&worker, WORKER_STACK_TOP, [0, 0]),
    ];
    for (t, rsp, [rdi, rsi]) in entries {
        let e = UserEntry {
            rip: elf.entry(),
            rsp,
            args: [rdi, rsi, raw],
        };
        kthread::start(t, &e).map_err(|_| "thread_start")?;
    }
    Ok([main, worker])
}

/// Roda o `okfuzz` com a semente e a duração da linha de comando.
pub fn run(cmdline: &str) {
    let config = Config {
        seed: option(cmdline, "fuzz.seed")
            .and_then(parse_u64)
            .unwrap_or(1),
        seconds: option(cmdline, "fuzz.secs")
            .and_then(parse_u64)
            .map_or(60, |s| u16::try_from(s).unwrap_or(u16::MAX)),
    };
    let config = Config::from_raw(config.to_raw());
    let Some(image) = kroot::bootfs() else {
        error!("okernel: sem bootfs; okfuzz não iniciado");
        return;
    };
    let Some(quota) = kcap::root_quota() else {
        error!("okernel: sem cota raiz; okfuzz não iniciado");
        return;
    };
    let used0 = quota.used();
    let threads = match spawn(image, config) {
        Ok(t) => t,
        Err(e) => {
            error!("okernel: okfuzz não iniciado: {e}");
            return;
        }
    };
    info!(
        "okernel: okfuzz iniciado, semente {:#x}, {} s",
        config.seed, config.seconds
    );
    let limit = u64::from(config.seconds) * 1_000_000_000 + SLACK_NS;
    let [main, worker] = &threads;
    if !kroot::run_until_exit(main, limit) {
        error!("okernel: okfuzz não terminou no prazo");
        return;
    }
    if !kroot::run_until_exit(worker, 5_000_000_000) {
        error!("okernel: okfuzz: a thread auxiliar não terminou");
        return;
    }
    drop(threads);
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
