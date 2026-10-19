//! Benchmarks de IPC e de troca de contexto (T-213; SDD v1.0, seção 6.7).
//!
//! Com `test=bench` na linha de comando, o kernel roda, entre threads de
//! usuário com o código de `user.S`, cada benchmark de [`BENCHES`],
//! escreve uma linha `bench:` por resultado e desliga o QEMU. Cada amostra
//! é medida no anel 3 com `LFENCE; RDTSC` em volta de uma syscall; as
//! [`WARMUP`] primeiras são descartadas. O `cargo xtask bench` (sempre em
//! release) lê essas linhas e grava o relatório em `docs/bench/`.
//!
//! - `ipc_call_reply_recv`: ida e volta `ipc_call` → `ipc_reply_recv` sem
//!   palavras, entre dois processos (troca de CR3), pelo caminho rápido.
//! - `troca_de_contexto_*`: duas threads de mesma prioridade alternando
//!   com `yield`; uma amostra cobre duas trocas (ida e volta), e o valor
//!   publicado é metade dela. `entre_processos` troca o CR3; `mesmo_processo`
//!   não.
//!
//! As medidas incluem a entrada e a saída da syscall e o próprio `RDTSC`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use kabi::ipc::recv_target;
use kabi::vm::PAGE_SIZE;
use kabi::{Handle, ObjectType, Rights};
use okernel::thread::Thread;

use crate::arch::x86_64::{QemuExit, apic, cpu, qemu_exit};
use crate::kipc::tests::{create, give};
use crate::kthread::tests::{
    DATA_VA, Process, RUN_LIMIT_NS, delete, process, run_until_exit_within, thread, user_symbol,
};
use crate::kthread::{UserEntry, fast_switches, start};
use crate::{kmem, ktime};

/// Amostras guardadas de cada benchmark.
pub const SAMPLES: usize = 10_000;
/// Voltas descartadas no início (caches, TLB, primeiras faltas).
pub const WARMUP: usize = 1_000;
const ROUNDS: usize = SAMPLES + WARMUP;
/// Página da pilha; as amostras começam na seguinte.
const STACK_PAGE: u64 = 1;
const SAMPLES_VA: u64 = DATA_VA + (STACK_PAGE + 2) * PAGE_SIZE;
/// Páginas de dados: buffer, duas pilhas e as amostras.
const DATA_PAGES: u64 = 3 + (ROUNDS as u64 * 8).div_ceil(PAGE_SIZE);

unsafe extern "C" {
    static user_bench_ipc_client: u8;
    static user_bench_ipc_server: u8;
    static user_bench_yield: u8;
}

/// Com `test=perfil`, as threads não têm limite de tempo: o gdb para a
/// máquina a cada entrada de syscall enquanto espera a volta escolhida.
static NO_LIMIT: AtomicBool = AtomicBool::new(false);

/// Roda as threads até terminarem (no limite dos testes, ou sem limite no
/// perfil).
fn run_until_exit(threads: &[Arc<Thread>]) -> Result<(), &'static str> {
    let limit = if NO_LIMIT.load(Ordering::Relaxed) {
        u64::MAX
    } else {
        RUN_LIMIT_NS
    };
    run_until_exit_within(threads, limit)
}

/// Um benchmark: nome e função que devolve as amostras em ciclos do TSC
/// (já divididas pelo número de eventos de cada uma).
struct Bench {
    name: &'static str,
    run: fn() -> Result<Vec<u64>, &'static str>,
}

const BENCHES: &[Bench] = &[
    Bench {
        name: "ipc_call_reply_recv",
        run: ipc,
    },
    Bench {
        name: "troca_de_contexto_entre_processos",
        run: || switches(false),
    },
    Bench {
        name: "troca_de_contexto_mesmo_processo",
        run: || switches(true),
    },
];

/// Inicia em `p` uma thread em `sym` com `args` e a pilha na página
/// `stack_page`.
fn spawn(
    p: &Process,
    sym: *const u8,
    args: [u64; 3],
    stack_page: u64,
) -> Result<(Handle, Arc<Thread>), &'static str> {
    let (h, t) = thread(p)?;
    let e = UserEntry {
        rip: user_symbol(sym),
        rsp: DATA_VA + (stack_page + 1) * PAGE_SIZE,
        args,
    };
    start(&t, &e).map_err(|_| "thread_start")?;
    Ok((h, t))
}

/// As amostras gravadas em `SAMPLES_VA` no espaço de `p`, sem o
/// aquecimento e divididas por `per`.
fn samples(p: &Process, per: u64) -> Result<Vec<u64>, &'static str> {
    let aspace = p.aspace.object.as_address_space().map_err(|_| "tipo")?;
    let mut out = Vec::new();
    out.try_reserve_exact(ROUNDS).map_err(|_| "memória")?;
    let per_page = (PAGE_SIZE / 8) as usize;
    for i in 0..ROUNDS {
        let va = SAMPLES_VA + (i / per_page) as u64 * PAGE_SIZE;
        let (phys, _) = aspace.lock().query(va).ok_or("página de amostras")?;
        let at = usize::try_from(kmem::direct(phys)).map_err(|_| "endereço")? + (i % per_page) * 8;
        // SAFETY: a página é RAM de um `MemoryObject` vivo (mapeado em
        // `p`), lida pelo mapa direto, alinhada a 8; as threads que a
        // gravavam já terminaram.
        let v = unsafe { core::ptr::with_exposed_provenance::<u64>(at).read() };
        ensure!(v != u64::MAX);
        out.push(v / per);
    }
    Ok(out.split_off(WARMUP))
}

/// `ipc_call` → `ipc_reply_recv` entre dois processos.
fn ipc() -> Result<Vec<u64>, &'static str> {
    let (client, server) = (process(DATA_PAGES)?, process(DATA_PAGES)?);
    let (ep_h, ep) = create(&server, ObjectType::Endpoint)?;
    let (reply, _) = create(&server, ObjectType::Reply)?;
    let c_ep = give(&client, &ep, Rights::SEND, 1)?;
    let fast0 = fast_switches();
    let rounds = ROUNDS as u64;
    let target = recv_target(ep_h, reply);
    let server_sym = &raw const user_bench_ipc_server;
    let (hs, ts) = spawn(&server, server_sym, [target, rounds, 0], STACK_PAGE)?;
    let client_sym = &raw const user_bench_ipc_client;
    let args = [u64::from(c_ep.raw()), rounds, SAMPLES_VA];
    let (hc, tc) = spawn(&client, client_sym, args, STACK_PAGE)?;
    run_until_exit(&[Arc::clone(&ts), Arc::clone(&tc)])?;
    let fast = fast_switches() - fast0;
    // Só a primeira chamada e a última resposta podem não ser diretas.
    ensure!(fast + 2 >= 2 * rounds);
    let out = samples(&client, 1)?;
    drop((ts, tc));
    delete(&client, &[hc])?;
    delete(&server, &[hs])?;
    Ok(out)
}

/// Duas threads alternando com `yield`, no mesmo processo ou em dois.
fn switches(same: bool) -> Result<Vec<u64>, &'static str> {
    let a = process(DATA_PAGES)?;
    let b = if same {
        None
    } else {
        Some(process(DATA_PAGES)?)
    };
    let other = b.as_ref().unwrap_or(&a);
    let sym = &raw const user_bench_yield;
    let rounds = ROUNDS as u64;
    let (ha, ta) = spawn(&a, sym, [rounds, SAMPLES_VA, 0], STACK_PAGE)?;
    let (hb, tb) = spawn(other, sym, [rounds, 0, 0], STACK_PAGE + 1)?;
    run_until_exit(&[Arc::clone(&ta), Arc::clone(&tb)])?;
    let out = samples(&a, 2)?;
    drop((ta, tb));
    delete(&a, &[ha])?;
    delete(other, &[hb])?;
    Ok(out)
}

/// Com `test=perfil` (T-331): o benchmark de IPC e o de troca entre
/// processos em laço até o QEMU ser desligado, para o `cargo xtask perfil`
/// conectar o gdb a qualquer momento e seguir uma volta instrução a
/// instrução.
pub fn profile() -> ! {
    NO_LIMIT.store(true, Ordering::Relaxed);
    environment();
    info!("perfil: pronto");
    loop {
        if let Err(why) = ipc().and_then(|_| switches(false)) {
            error!("perfil: FALHOU: {why}");
            qemu_exit(QemuExit::Failure);
        }
    }
}

/// Ciclos do TSC em ns.
fn ns(cycles: u64) -> u64 {
    let hz = u128::from(ktime::tsc_hz().max(1));
    u64::try_from(u128::from(cycles) * 1_000_000_000 / hz).unwrap_or(u64::MAX)
}

/// Nome da CPU (CPUID `0x8000_0002`–`0x8000_0004`).
fn cpu_brand() -> ([u8; 48], usize) {
    let mut brand = [0u8; 48];
    if cpu::max_leaf(true) >= 0x8000_0004 {
        for (i, leaf) in (0x8000_0002..=0x8000_0004).enumerate() {
            let r = cpu::cpuid(leaf, 0);
            for (j, word) in [r.eax, r.ebx, r.ecx, r.edx].into_iter().enumerate() {
                let at = i * 16 + j * 4;
                brand[at..at + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
    }
    let len = brand.iter().position(|&b| b == 0).unwrap_or(48);
    (brand, len)
}

/// A linha `bench: ambiente` (CPU, acelerador, TSC, APIC e timer).
fn environment() {
    let (brand, len) = cpu_brand();
    let accel = match cpu::hypervisor() {
        Some(sig) if &sig == b"TCGTCGTCGTCG" => "TCG",
        Some(sig) if sig.starts_with(b"KVMKVMKVM") => "KVM",
        Some(_) => "outro",
        None => "nenhum",
    };
    info!(
        "bench: ambiente cpu=\"{}\" acelerador={accel} tsc_khz={} apic={:?} timer={}",
        core::str::from_utf8(&brand[..len]).unwrap_or("?").trim(),
        ktime::tsc_hz() / 1000,
        apic::mode(),
        if apic::tsc_deadline() {
            "tsc-deadline"
        } else {
            "one-shot"
        }
    );
}

/// Roda os benchmarks e desliga o QEMU.
pub fn run() -> ! {
    environment();
    let mut ok = true;
    for b in BENCHES {
        match (b.run)() {
            Ok(mut s) => {
                s.sort_unstable();
                let n = s.len();
                let pick = |q: usize| ns(s[(n * q).div_ceil(100).saturating_sub(1)]);
                let mean = ns(s.iter().sum::<u64>() / n as u64);
                info!(
                    "bench: {} n={n} mediana_ns={} p99_ns={} min_ns={} max_ns={} media_ns={mean}",
                    b.name,
                    pick(50),
                    pick(99),
                    ns(s[0]),
                    ns(s[n - 1]),
                );
            }
            Err(why) => {
                ok = false;
                error!("bench: {} FALHOU: {why}", b.name);
            }
        }
    }
    info!("bench: fim");
    qemu_exit(if ok {
        QemuExit::Success
    } else {
        QemuExit::Failure
    })
}
