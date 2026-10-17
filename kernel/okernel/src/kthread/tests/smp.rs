//! Testes de kernel de threads em várias CPUs (T-324): os APs rodam
//! threads da própria fila e o despertar vindo de outra CPU põe a thread na
//! fila certa e avisa com o IPI de reescalonar.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use kabi::vm::{PAGE_SIZE, WRITE};
use kabi::{ObjectType, STATUS_OK};
use okernel::futex::FUTEXES;
use okernel::sched::Params;
use okernel::thread::{RunState, Thread};
use okernel::vm::vm_map;

use super::super::{UserEntry, start_on, wake, yield_now};
use super::sync::read_user;
use super::{
    DATA_VA, Page, Process, cap, delete, process, settled, thread, thread_with, user_symbol,
};
use crate::arch::x86_64::cpu;
use crate::kcap::root_quota;
use crate::ksmp;
use crate::ktest::Outcome;
use crate::ktime;

unsafe extern "C" {
    static user_pingpong: u8;
    static user_wait_cpu: u8;
    static user_spin_flag: u8;
}

/// Onde os dois processos do pingue-pongue mapeiam a página comum.
const SHARED_VA: u64 = 0x60_0000;
/// Jogadas de cada processo no pingue-pongue sem `smp.alternate`. O aceite
/// do T-324 pede 10⁶, que `cargo xtask test smp` roda num boot de release
/// à parte (de um a cinco minutos sob TCG; na depuração, dez vezes mais).
const DEFAULT_ROUNDS: u64 = 10_000;
pub(super) const MS: u64 = 1_000_000;
/// Prazo das esperas por outra CPU: folgado, porque sob TCG uma vCPU pode
/// ficar centenas de milissegundos sem andar.
pub(super) const LIMIT: u64 = 10_000 * MS;
/// Onde a thread que gira mapeia a página com o pedido de parar.
const SPIN_VA: u64 = 0x70_0000;

/// Valor de uma opção `nome=N` da linha de comando, ou `default`.
pub(super) fn option(name: &str, default: u64) -> u64 {
    crate::bootinfo::get()
        .and_then(|i| i.cmdline())
        .and_then(|c| okernel::log::option(c, name))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Espera até `done()` ou `limit_ns`, rodando as prontas desta CPU e
/// dormindo (`hlt`, com o timer armado para 1 ms) entre uma olhada e outra:
/// o BSP girando tiraria do host a CPU de que os APs do QEMU precisam.
pub(super) fn wait_for(limit_ns: u64, done: impl Fn() -> bool) -> bool {
    wait_with(limit_ns, true, done)
}

/// Como [`wait_for`]; sem `sleep`, gira cedendo a vez (quando o próprio
/// BSP joga, o `hlt` atrasaria cada despertar dele).
pub(super) fn wait_with(limit_ns: u64, sleep: bool, done: impl Fn() -> bool) -> bool {
    let give_up = ktime::now_ns() + limit_ns;
    while !done() {
        let now = ktime::now_ns();
        if now > give_up {
            return false;
        }
        yield_now();
        if sleep {
            ktime::arm_by(now + MS);
            cpu::wait_for_interrupt();
        } else {
            ksmp::ipi::poll();
        }
    }
    true
}

/// Bloqueada e fora da CPU (a troca que a tirou terminou).
pub(super) fn parked(t: &Thread) -> bool {
    t.state() == RunState::Blocked && !t.on_cpu()
}

/// Aceite do T-324: dois processos, cada um começando numa CPU, alternam a
/// vez por futex numa página comum `smp.alternate` vezes cada. Cada passagem de vez acorda a outra thread na CPU dela, a
/// partir da outra CPU; toda jogada tem de acontecer na CPU de partida.
pub fn alternam_em_cpus_distintas() -> Outcome {
    let n = ksmp::start::online_count();
    if n < 2 {
        info!("ktest: · só uma CPU; nada a alternar");
        return Ok(());
    }
    let rounds = option("smp.alternate", DEFAULT_ROUNDS);
    // Com APs livres, longe do BSP (que roda o teste); com duas CPUs, o
    // BSP joga quando o teste cede a vez.
    let (a, b) = if n >= 3 { (1u32, 2u32) } else { (0, 1) };
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    let before = FUTEXES.stats();
    {
        let (pa, pb) = (process(1)?, process(1)?);
        let shared = pa
            .cspace
            .lock()
            .obj_create(pa.quota, ObjectType::MemoryObject, PAGE_SIZE)
            .map_err(|_| "obj_create(MemoryObject)")?;
        let page = cap(&pa.cspace, shared)?;
        for p in [&pa, &pb] {
            ensure!(vm_map(&p.aspace, &page, SHARED_VA, 0, PAGE_SIZE, WRITE).is_ok());
        }
        drop(page);
        let entry = user_symbol(&raw const user_pingpong);
        let (ha, ta) = thread(&pa)?;
        let (hb, tb) = thread(&pb)?;
        let t0 = ktime::now_ns();
        for (id, (t, cpu)) in [(&ta, a), (&tb, b)].into_iter().enumerate() {
            let e = UserEntry {
                rip: entry,
                rsp: DATA_VA + PAGE_SIZE,
                args: [id as u64 | u64::from(cpu) << 8, rounds, SHARED_VA],
            };
            ensure!(start_on(t, &e, cpu).is_ok());
        }
        // 10⁶ jogadas levam de um a cinco minutos em release sob TCG; a
        // depuração é umas dez vezes mais lenta.
        let limit = 60_000 * MS + rounds * 700_000;
        let done = wait_with(limit, a != 0, || gone(&ta) && gone(&tb));
        let ns = ktime::now_ns() - t0;
        let [turn, plays_a, plays_b, away_a, away_b] = read_user::<5>(&pa, SHARED_VA)?;
        let after = FUTEXES.stats();
        info!(
            "ktest: · cpu{a} e cpu{b}: {plays_a} + {plays_b} jogadas em {} ms ({} ns cada), \
             {away_a} + {away_b} fora da CPU, {} esperas no futex",
            ns / MS,
            ns / (plays_a + plays_b).max(1),
            after.blocked - before.blocked
        );
        ensure!(done);
        ensure!(plays_a == rounds && plays_b == rounds && turn == 0);
        ensure!(away_a == 0 && away_b == 0);
        ensure!(ta.cpu() == a && tb.cpu() == b);
        drop((ta, tb));
        delete(&pa, &[ha, shared])?;
        delete(&pb, &[hb])?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Cria uma notificação em `p` e devolve o handle e o objeto.
pub(super) fn notification(
    p: &Process,
) -> Result<(kabi::Handle, Arc<okernel::notify::Notification>), &'static str> {
    let h = p
        .cspace
        .lock()
        .obj_create(p.quota, ObjectType::Notification, 0)
        .map_err(|_| "obj_create(Notification)")?;
    let n = Arc::clone(
        cap(&p.cspace, h)?
            .object
            .as_notification()
            .map_err(|_| "tipo")?,
    );
    Ok((h, n))
}

/// Põe uma thread de `p` esperando na notificação `ntfy` na CPU `cpu` e
/// espera ela bloquear e sair da CPU.
pub(super) fn park_on(
    p: &Process,
    ntfy: kabi::Handle,
    cpu: u32,
) -> Result<(kabi::Handle, Arc<Thread>), &'static str> {
    let (h, t) = thread(p)?;
    let e = UserEntry {
        rip: user_symbol(&raw const user_wait_cpu),
        rsp: DATA_VA + PAGE_SIZE,
        args: [u64::from(ntfy.raw()), DATA_VA, 0],
    };
    ensure!(start_on(&t, &e, cpu).is_ok());
    ensure!(wait_for(LIMIT, || parked(&t)));
    ensure!(t.cpu() == cpu);
    Ok((h, t))
}

/// Sinaliza `ntfy` daqui (o BSP) e acorda quem espera, como `ntfy_signal`.
fn signal(ntfy: &okernel::notify::Notification, bits: u64) -> Outcome {
    let (t, word) = ntfy.signal(bits).ok_or("ninguém esperando")?;
    wake(t, word);
    Ok(())
}

/// Aceite do T-324: a thread bloqueada numa CPU e acordada do BSP volta a
/// rodar na CPU certa pela escolha do despertar (ADR 0032, item 5): na
/// dela, ociosa (cache quente); com a dela ocupada por uma mais
/// prioritária, na primeira ociosa a partir dela (o BSP, que roda o teste e
/// conta como ocioso).
pub fn acorda_na_cpu_certa() -> Outcome {
    let online = ksmp::start::online_count();
    if online < 2 {
        info!("ktest: · só uma CPU; nada a escolher");
        return Ok(());
    }
    let last = u32::try_from(online - 1).map_err(|_| "id")?;
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    acorda_na_ociosa(last)?;
    acorda_longe_da_ocupada(last)?;
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Bloqueada na CPU `home`, ociosa: acorda lá.
fn acorda_na_ociosa(home: u32) -> Outcome {
    let p = process(1)?;
    let (ntfy_h, ntfy) = notification(&p)?;
    let (handle, waiter) = park_on(&p, ntfy_h, home)?;
    signal(&ntfy, 0b10)?;
    ensure!(wait_for(LIMIT, || gone(&waiter)));
    let [status, bits, cpu] = read_user::<3>(&p, DATA_VA)?;
    info!("ktest: · cpu{home} ociosa: acordou na cpu{cpu}");
    ensure!(status == STATUS_OK && bits == 0b10);
    ensure!(cpu == u64::from(home) && waiter.cpu() == home);
    drop(waiter);
    delete(&p, &[handle, ntfy_h])
}

/// Bloqueada na CPU `home`, ocupada por uma de prioridade 200: a de 100
/// acorda na primeira ociosa depois dela, que é o BSP (o teste roda no
/// ocioso dele). A de 200 gira até o teste mandar parar, não por um prazo
/// de relógio: sob TCG uma vCPU pode ficar centenas de milissegundos sem
/// andar (o MMIO do APIC espera a trava global do QEMU), e o prazo venceria
/// antes do despertar.
fn acorda_longe_da_ocupada(home: u32) -> Outcome {
    let p = process(1)?;
    let (ntfy_h, ntfy) = notification(&p)?;
    let (handle, waiter) = park_on(&p, ntfy_h, home)?;
    let busy = Params::new(MS, MS, 200).map_err(|_| "params")?;
    let (spin_h, spinner) = thread_with(&p, busy)?;
    let stop = Page::new(&p)?;
    ensure!(vm_map(&p.aspace, &stop.cap, SPIN_VA, 0, PAGE_SIZE, WRITE).is_ok());
    let e = UserEntry {
        rip: user_symbol(&raw const user_spin_flag),
        rsp: DATA_VA + PAGE_SIZE,
        args: [SPIN_VA, 0, 0],
    };
    ensure!(start_on(&spinner, &e, home).is_ok());
    // Já no anel 3: a troca terminou e a CPU publicou a prioridade 200.
    let running = wait_for(LIMIT, || stop.word(1).load(Ordering::Acquire) == 1);
    let woke = running && signal(&ntfy, 0b100).is_ok() && wait_for(LIMIT, || gone(&waiter));
    stop.word(0).store(1, Ordering::Release);
    ensure!(running && woke);
    let [status, bits, cpu] = read_user::<3>(&p, DATA_VA)?;
    info!("ktest: · cpu{home} ocupada por prioridade 200: a de 100 acordou na cpu{cpu}");
    ensure!(status == STATUS_OK && bits == 0b100);
    ensure!(cpu == 0 && waiter.cpu() == 0);
    ensure!(wait_for(LIMIT, || gone(&spinner)));
    ensure!(spinner.cpu() == home);
    drop((waiter, spinner));
    delete(&p, &[handle, spin_h, ntfy_h, stop.handle])
}

/// Terminou e saiu da CPU.
pub(super) fn gone(t: &Thread) -> bool {
    t.state() == RunState::Exited && !t.on_cpu()
}
