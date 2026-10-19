//! Estresse SMP (T-329): todas as partes do kernel que o M3 tornou
//! concorrentes trabalhando ao mesmo tempo, com a verificação de ordem de
//! travas do build de depuração ligada (ADR 0031).
//!
//! O teste roda "épocas" até `smp.estresse_s` segundos (o aceite pede 30
//! minutos em `-smp 4`, que `cargo xtask test stress` roda). Em cada época,
//! com as CPUs sorteadas de novo:
//!
//! - IPC cruzado: um servidor e um cliente, em processos e CPUs sorteados;
//! - mutex de usuário (futex): 4 threads de um processo;
//! - revogação concorrente no CDT: dois processos com `MANAGE` no
//!   `CapSpace` um do outro, duas threads em cada, copiando, revogando e
//!   apagando capabilities entre os dois (ADR 0028), inclusive revogando a
//!   raiz de que as outras threads copiam;
//! - enquanto isso, o BSP cria e destrói processos de uma thread sorteada
//!   (criação e destruição), troca mapeamentos lidos por outra CPU
//!   (shootdown) e apaga endpoints sob quem espera neles (destruição de
//!   longe).
//!
//! No fim de cada época: contas exatas, nenhuma thread presa, cota e
//! despertares de futex fechando. A migração aparece nas threads que
//! terminam fora da CPU em que começaram.

use alloc::sync::Arc;
use alloc::vec::Vec;

use kabi::ipc::recv_target;
use kabi::vm::PAGE_SIZE;
use kabi::{Handle, ObjectType, Rights, STATUS_OK};
use okernel::cap::Object;
use okernel::cap::space::Revoke;
use okernel::cap::xcdt;
use okernel::futex::FUTEXES;
use okernel::thread::Thread;

use super::super::{UserEntry, start_on};
use super::smp::{LIMIT, MS, gone, option, wait_for};
use super::smp_ipc::{em_corrida, spawn_on};
use super::{DATA_VA, Process, delete, process, settled, thread, tlb, user_symbol};
use crate::kcap::root_quota;
use crate::kipc::tests::{BADGE, create, give, user_words};
use crate::ksmp;
use crate::ktest::Outcome;
use crate::ktime;

unsafe extern "C" {
    static user_ipc_server: u8;
    static user_ipc_client: u8;
    static user_mutex: u8;
    static user_cap_churn: u8;
    static user_spin: u8;
}

/// Duração sem `smp.estresse_s`: poucas épocas, para a suíte de kernel.
const DEFAULT_SECONDS: u64 = 6;
/// Idas e voltas de IPC por época.
const IPC_ROUNDS: u64 = 200;
/// Voltas de cada thread do mutex por época.
const MUTEX_ROUNDS: u64 = 150;
/// Voltas de cada thread do CDT por época.
const CHURN_ROUNDS: u64 = 80;
/// Prazo de uma época: folgado, o TCG com a depuração é lento.
const EPOCH_LIMIT: u64 = 60_000 * MS;
/// Uma linha de progresso a cada tantas épocas.
const REPORT_EVERY: u64 = 200;

/// Gerador xorshift: o estresse é reproduzível pela semente do log.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % n as u64).unwrap_or(0)
    }

    fn cpu(&mut self, online: usize) -> u32 {
        u32::try_from(self.below(online)).unwrap_or(0)
    }
}

/// Somas de todas as épocas.
#[derive(Default)]
struct Totals {
    epochs: u64,
    ipc_calls: u64,
    mutex_sums: u64,
    churn_rounds: u64,
    churn_revokes: u64,
    churn_remote: u64,
    churn_raced: u64,
    processes: u64,
    shootdowns: u64,
    destroyed: u64,
    migrated: u64,
    threads: u64,
}

/// Aceite do T-329: o estresse inteiro por `smp.estresse_s` segundos.
pub fn estresse() -> Outcome {
    let online = ksmp::start::online_count();
    let seconds = option("smp.estresse_s", DEFAULT_SECONDS);
    let seed = option("smp.estresse_seed", ktime::now_ns() | 1);
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    let futex0 = FUTEXES.stats();
    let mut rng = Rng(seed);
    let mut totals = Totals::default();
    info!("ktest: · estresse de {seconds} s em {online} CPU(s), semente {seed:#x}");
    let t0 = ktime::now_ns();
    let deadline = t0 + seconds * 1_000_000_000;
    loop {
        epoca(&mut rng, online, &mut totals)?;
        ensure!(settled(&quota, used0));
        totals.epochs += 1;
        if totals.epochs.is_multiple_of(REPORT_EVERY) {
            info!(
                "ktest: · {} épocas em {} s, {} chamadas de IPC, {} voltas de CDT",
                totals.epochs,
                (ktime::now_ns() - t0) / 1_000_000_000,
                totals.ipc_calls,
                totals.churn_rounds
            );
        }
        if ktime::now_ns() >= deadline {
            break;
        }
    }
    let futex = FUTEXES.stats();
    let (blocked, woken) = (futex.blocked - futex0.blocked, futex.woken - futex0.woken);
    info!(
        "ktest: · {} épocas em {} s: {} chamadas de IPC, {} somas sob mutex ({blocked} esperas, \
         {woken} despertares), {} voltas de CDT ({} revogações, {} cópias remotas, {} erros de \
         corrida esperados), {} processos criados e destruídos, {} shootdowns, {} destruições de \
         longe; {} de {} threads terminaram noutra CPU",
        totals.epochs,
        (ktime::now_ns() - t0) / 1_000_000_000,
        totals.ipc_calls,
        totals.mutex_sums,
        totals.churn_rounds,
        totals.churn_revokes,
        totals.churn_remote,
        totals.churn_raced,
        totals.processes,
        totals.shootdowns,
        totals.destroyed,
        totals.migrated,
        totals.threads,
    );
    ensure!(woken == blocked);
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Threads em andamento e a CPU em que cada uma começou.
type Running = Vec<(Arc<Thread>, u32)>;

/// Servidor e cliente de IPC em processos e CPUs sorteados.
struct Ipc {
    client: Process,
    server: Process,
    handles: [Handle; 2],
}

impl Ipc {
    fn monta(rng: &mut Rng, online: usize, running: &mut Running) -> Result<Self, &'static str> {
        let (client, server) = (process(2)?, process(2)?);
        let (recv_ep, ep) = create(&server, ObjectType::Endpoint)?;
        let (reply, _) = create(&server, ObjectType::Reply)?;
        user_words(&server, DATA_VA + 16, Some([BADGE]))?;
        let send_ep = give(&client, &ep, Rights::SEND, BADGE)?;
        let target = recv_target(recv_ep, reply);
        let cpu = rng.cpu(online);
        let args = [target, IPC_ROUNDS, DATA_VA];
        let (h_server, t_server) = spawn_on(&server, &raw const user_ipc_server, args, 1, cpu)?;
        running.push((t_server, cpu));
        let cpu = rng.cpu(online);
        let args = [u64::from(send_ep.raw()), IPC_ROUNDS, DATA_VA];
        let (h_client, t_client) = spawn_on(&client, &raw const user_ipc_client, args, 1, cpu)?;
        running.push((t_client, cpu));
        Ok(Self {
            client,
            server,
            handles: [h_server, h_client],
        })
    }

    fn confere(&self, totals: &mut Totals) -> Outcome {
        let [c_status, c_count] = user_words::<2>(&self.client, DATA_VA, None)?;
        let [s_status, s_count] = user_words::<2>(&self.server, DATA_VA, None)?;
        ensure!(c_status == STATUS_OK && s_status == STATUS_OK);
        ensure!(c_count == IPC_ROUNDS && s_count == IPC_ROUNDS);
        totals.ipc_calls += c_count;
        Ok(())
    }

    fn apaga(&self) -> Outcome {
        delete(&self.server, &[self.handles[0]])?;
        delete(&self.client, &[self.handles[1]])
    }
}

/// Quatro threads de um processo somando sob um mutex de futex.
struct Mutex {
    p: Process,
    handles: Vec<Handle>,
}

impl Mutex {
    /// Página 0: mutex (u32) e contador (u64); páginas 2 a 5: pilhas.
    fn monta(rng: &mut Rng, online: usize, running: &mut Running) -> Result<Self, &'static str> {
        let p = process(5)?;
        let mut handles = Vec::new();
        for i in 0..4u64 {
            let cpu = rng.cpu(online);
            let (h, t) = thread(&p)?;
            let entry = UserEntry {
                rip: user_symbol(&raw const user_mutex),
                rsp: DATA_VA + (i + 2) * PAGE_SIZE,
                args: [DATA_VA, DATA_VA + 8, MUTEX_ROUNDS],
            };
            ensure!(start_on(&t, &entry, cpu).is_ok());
            handles.push(h);
            running.push((t, cpu));
        }
        Ok(Self { p, handles })
    }

    fn confere(&self, totals: &mut Totals) -> Outcome {
        let [mutex, counter] = user_words::<2>(&self.p, DATA_VA, None)?;
        ensure!(mutex == 0 && counter == 4 * MUTEX_ROUNDS);
        totals.mutex_sums += counter;
        Ok(())
    }

    fn apaga(&self) -> Outcome {
        delete(&self.p, &self.handles)
    }
}

/// Dois processos, cada um com `MANAGE` no `CapSpace` do outro, e duas
/// threads em cada. A página `1 + i` da thread `i` guarda a estatística
/// (no início) e a pilha (no fim).
struct Cdt {
    pair: [Process; 2],
    handles: [Vec<Handle>; 2],
    /// (raiz, capability do `CapSpace` do outro) de cada lado.
    caps: [(Handle, Handle); 2],
    /// (lado, página) de cada thread.
    pages: Vec<(usize, u64)>,
}

impl Cdt {
    fn monta(rng: &mut Rng, online: usize, running: &mut Running) -> Result<Self, &'static str> {
        let pair = [process(3)?, process(3)?];
        let mut handles: [Vec<Handle>; 2] = [Vec::new(), Vec::new()];
        let mut pages = Vec::new();
        let mut caps = [(Handle::from_raw(0), Handle::from_raw(0)); 2];
        for side in 0..2 {
            let (p, other) = (&pair[side], &pair[1 - side]);
            let (root, _) = create(p, ObjectType::Notification)?;
            let space = Object::CapSpace(Arc::clone(&other.cspace));
            let remote = give(p, &space, Rights::MANAGE, 0)?;
            caps[side] = (root, remote);
            for i in 0..2u64 {
                let page = DATA_VA + (1 + i) * PAGE_SIZE;
                user_words(p, page + 16, Some([u64::from(remote.raw())]))?;
                let cpu = rng.cpu(online);
                let args = [u64::from(root.raw()), CHURN_ROUNDS, page];
                let (h, t) = spawn_on(p, &raw const user_cap_churn, args, 1 + i, cpu)?;
                handles[side].push(h);
                pages.push((side, page));
                running.push((t, cpu));
            }
        }
        Ok(Self {
            pair,
            handles,
            caps,
            pages,
        })
    }

    fn confere(&self, totals: &mut Totals) -> Outcome {
        for &(side, page) in &self.pages {
            let [status, rounds, _, raced, remote, revokes] =
                user_words::<6>(&self.pair[side], page, None)?;
            if status != STATUS_OK {
                info!("ktest: · thread do CDT terminou com status {status:#x}");
            }
            ensure!(status == STATUS_OK && rounds == CHURN_ROUNDS);
            totals.churn_rounds += rounds;
            totals.churn_raced += raced;
            totals.churn_remote += remote;
            totals.churn_revokes += revokes;
        }
        Ok(())
    }

    /// Revoga cada raiz (leva as cópias que sobraram nos dois lados) e
    /// apaga o que cria o ciclo entre os dois `CapSpace`.
    fn apaga(&self) -> Outcome {
        for (p, &(root, remote)) in self.pair.iter().zip(&self.caps) {
            loop {
                match xcdt::revoke(&p.cspace, root, 64) {
                    Ok(Revoke::Continue) => {}
                    Ok(Revoke::Done) => break,
                    Err(e) => {
                        info!("ktest: · cap_revoke da raiz recusado: {e:?}");
                        return Err("revoke");
                    }
                }
            }
            delete(p, &[root, remote])?;
        }
        for (p, handles) in self.pair.iter().zip(&self.handles) {
            delete(p, handles)?;
        }
        Ok(())
    }
}

/// Uma época: monta os trabalhos, deixa o BSP estressar processos, TLB e
/// destruição enquanto as outras CPUs trabalham, e confere as contas.
fn epoca(rng: &mut Rng, online: usize, totals: &mut Totals) -> Outcome {
    let mut running = Running::new();
    let ipc = Ipc::monta(rng, online, &mut running)?;
    let mutex = Mutex::monta(rng, online, &mut running)?;
    let cdt = Cdt::monta(rng, online, &mut running)?;

    // O BSP trabalha enquanto os outros não terminam.
    let give_up = ktime::now_ns() + EPOCH_LIMIT;
    let mut step = 0u64;
    while !running.iter().all(|(t, _)| gone(t)) {
        if ktime::now_ns() >= give_up {
            for (i, (t, started)) in running.iter().enumerate() {
                info!(
                    "ktest: · thread {i} (começou na cpu{started}): {:?} na cpu{}, on_cpu {}",
                    t.state(),
                    t.cpu(),
                    t.on_cpu()
                );
            }
            for (name, t) in ["servidor", "cliente"].iter().zip(&running) {
                let slot = t.0.ipc().lock();
                info!(
                    "ktest: · {name}: enviando {}, recebendo {}, esperando resposta {}",
                    slot.sending(),
                    slot.receiving(),
                    slot.awaiting_reply()
                );
            }
            let [_, c_count] = user_words::<2>(&ipc.client, DATA_VA, None)?;
            let [_, s_count] = user_words::<2>(&ipc.server, DATA_VA, None)?;
            info!("ktest: · idas e voltas: cliente {c_count}, servidor {s_count} de {IPC_ROUNDS}");
            return Err("a época não terminou no prazo");
        }
        processo_efemero(rng, online)?;
        totals.processes += 1;
        if online >= 2 && step.is_multiple_of(6) {
            tlb::unmap_em(1 + rng.cpu(online - 1))?;
            totals.shootdowns += 1;
        }
        if online >= 2 && step % 10 == 5 {
            em_corrida(1 + rng.cpu(online - 1), 2)?;
            totals.destroyed += 2;
        }
        step += 1;
    }

    ipc.confere(totals)?;
    mutex.confere(totals)?;
    cdt.confere(totals)?;
    for (t, started) in &running {
        totals.threads += 1;
        totals.migrated += u64::from(t.cpu() != *started);
    }
    drop(running);
    ipc.apaga()?;
    mutex.apaga()?;
    cdt.apaga()
}

/// Cria um processo com uma thread que sai logo, numa CPU sorteada, e o
/// destrói: criação e destruição de processos em meio ao resto.
fn processo_efemero(rng: &mut Rng, online: usize) -> Outcome {
    let p = process(1)?;
    let (h, t) = thread(&p)?;
    let entry = UserEntry {
        rip: user_symbol(&raw const user_spin),
        rsp: DATA_VA + PAGE_SIZE,
        args: [0, 0, 0],
    };
    ensure!(start_on(&t, &entry, rng.cpu(online)).is_ok());
    ensure!(wait_for(LIMIT, || gone(&t)));
    drop(t);
    delete(&p, &[h])
}
