//! Testes de kernel de IPC, futex e notificações entre CPUs (T-327; ADR
//! 0032, item 6): o servidor que esperava noutra CPU segue quem chama, a
//! espera de futex não perde despertar com as threads em CPUs diferentes, e
//! o objeto destruído numa CPU acorda com `PeerClosed` quem espera noutra,
//! inclusive quem ainda está entrando na espera.

use alloc::sync::Arc;
use alloc::vec::Vec;

use kabi::ipc::recv_target;
use kabi::vm::PAGE_SIZE;
use kabi::{Error, Handle, ObjectType, Rights, STATUS_OK};
use okernel::futex::FUTEXES;
use okernel::thread::Thread;

use super::super::{UserEntry, fast_switches, follows, start_on};
use super::smp::{LIMIT, MS, gone, notification, option, park_on, parked, wait_for, wait_with};
use super::sync::read_user;
use super::{DATA_VA, Process, delete, process, settled, thread, user_symbol};
use crate::kcap::root_quota;
use crate::kipc::tests::{BADGE, create, give, user_words};
use crate::ksmp;
use crate::ktest::Outcome;
use crate::ktime;

unsafe extern "C" {
    static user_ipc_server: u8;
    static user_ipc_client: u8;
    static user_ipc_recv: u8;
    static user_mutex: u8;
}

/// Idas e voltas de cada cliente sem `smp.ipc`. O aceite do T-327 pede
/// 10⁶, que `cargo xtask test smp` roda num boot de release à parte.
const DEFAULT_ROUNDS: u64 = 10_000;
/// Voltas de cada thread do mutex sem `smp.mutex`.
const MUTEX_ROUNDS: u64 = 2_000;
/// Rodadas da destruição em corrida sem `smp.peer`.
const PEER_ROUNDS: u64 = 100;

/// Como `kipc::tests::spawn`, na fila da CPU `cpu`.
pub(super) fn spawn_on(
    p: &Process,
    sym: *const u8,
    args: [u64; 3],
    stack_page: u64,
    cpu: u32,
) -> Result<(Handle, Arc<Thread>), &'static str> {
    let (h, t) = thread(p)?;
    t.set_ipc_buffer(DATA_VA).map_err(|_| "buffer")?;
    let e = UserEntry {
        rip: user_symbol(sym),
        rsp: DATA_VA + (stack_page + 1) * PAGE_SIZE,
        args,
    };
    ensure!(start_on(&t, &e, cpu).is_ok());
    Ok((h, t))
}

/// Prazo para `rounds` idas e voltas sob TCG (de um a cinco minutos para
/// 10⁶ em release; a depuração é umas dez vezes mais lenta).
fn ipc_limit(rounds: u64) -> u64 {
    60_000 * MS + rounds * 700_000
}

/// Aceite do T-327: o servidor espera na CPU `b`, o cliente chama da CPU
/// `a` `smp.ipc` vezes. Na primeira chamada o servidor segue o cliente
/// (ADR 0032, item 6) e daí em diante a ida e volta inteira é a troca
/// direta do caminho rápido, na CPU do cliente.
pub fn servidor_segue_quem_chama() -> Outcome {
    let n = ksmp::start::online_count();
    if n < 2 {
        info!("ktest: · só uma CPU; nada a seguir");
        return Ok(());
    }
    let rounds = option("smp.ipc", DEFAULT_ROUNDS);
    let (a, b) = if n >= 3 { (1u32, 2u32) } else { (0, 1) };
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let (client, server) = (process(2)?, process(2)?);
        let (ep_h, ep) = create(&client, ObjectType::Endpoint)?;
        let c_ep = client
            .cspace
            .lock()
            .mint(ep_h, Rights::SEND, Some(BADGE))
            .map_err(|_| "mint")?;
        let s_ep = give(&server, &ep, Rights::RECV, 0)?;
        let (s_reply, _) = create(&server, ObjectType::Reply)?;
        user_words(&server, DATA_VA + 16, Some([BADGE]))?;
        let target = recv_target(s_ep, s_reply);
        let args = [target, rounds, DATA_VA];
        let (hs, ts) = spawn_on(&server, &raw const user_ipc_server, args, 1, b)?;
        ensure!(wait_for(LIMIT, || parked(&ts)));
        ensure!(ts.cpu() == b);
        let (follows0, fast0) = (follows(), fast_switches());
        let t0 = ktime::now_ns();
        let args = [u64::from(c_ep.raw()), rounds, DATA_VA];
        let (hc, tc) = spawn_on(&client, &raw const user_ipc_client, args, 1, a)?;
        let done = wait_with(ipc_limit(rounds), a != 0, || gone(&ts) && gone(&tc));
        let ns = ktime::now_ns() - t0;
        let (followed, fast) = (follows() - follows0, fast_switches() - fast0);
        let [c_status, c_count] = user_words::<2>(&client, DATA_VA, None)?;
        let [s_status, s_count] = user_words::<2>(&server, DATA_VA, None)?;
        info!(
            "ktest: · servidor na cpu{b}, cliente na cpu{a}: {c_count} idas e voltas em {} ms \
             ({} ns cada), {followed} seguida(s), {fast} trocas diretas; terminaram na cpu{} e cpu{}",
            ns / MS,
            ns / c_count.max(1),
            ts.cpu(),
            tc.cpu()
        );
        ensure!(done);
        ensure!(c_status == STATUS_OK && s_status == STATUS_OK);
        ensure!(c_count == rounds && s_count == rounds);
        ensure!(followed >= 1);
        // O servidor seguiu o cliente e ficou. O cliente pode terminar
        // noutra CPU: a última resposta vai por `ipc_send`, que o acorda
        // pelo despertar comum, e a CPU dele está ocupada pelo servidor.
        ensure!(ts.cpu() == a);
        // Cada volta tem duas trocas (chamada e resposta); só a última
        // resposta (por `ipc_send`, que acorda) e a primeira chamada podem
        // não ser diretas.
        ensure!(fast + 2 >= 2 * rounds);
        drop((ts, tc, ep));
        delete(&client, &[hc])?;
        delete(&server, &[hs])?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Dois clientes, em CPUs distintas, chamam o mesmo servidor ao mesmo
/// tempo: o servidor ora segue um cliente para a CPU dele, ora pega da
/// fila o remetente que chegou enquanto estava ocupado e responde para a
/// outra CPU pelo despertar comum. Nenhuma chamada se perde nem se repete.
pub fn dois_clientes_em_cpus_distintas() -> Outcome {
    let online = ksmp::start::online_count();
    if online < 2 {
        info!("ktest: · só uma CPU; nada a disputar");
        return Ok(());
    }
    let rounds = option("smp.ipc2", DEFAULT_ROUNDS / 4);
    let (a, b) = if online >= 3 { (1u32, 2u32) } else { (0, 1) };
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let server = process(2)?;
        let clients = [process(2)?, process(2)?];
        let (s_ep, ep) = create(&server, ObjectType::Endpoint)?;
        let (s_reply, _) = create(&server, ObjectType::Reply)?;
        user_words(&server, DATA_VA + 16, Some([BADGE]))?;
        let target = recv_target(s_ep, s_reply);
        let args = [target, 2 * rounds, DATA_VA];
        let (hs, ts) = spawn_on(&server, &raw const user_ipc_server, args, 1, b)?;
        ensure!(wait_for(LIMIT, || parked(&ts)));
        let follows0 = follows();
        let t0 = ktime::now_ns();
        let mut handles = Vec::new();
        let mut threads = Vec::new();
        for (client, cpu) in clients.iter().zip([a, b]) {
            let c_ep = give(client, &ep, Rights::SEND, BADGE)?;
            let args = [u64::from(c_ep.raw()), rounds, DATA_VA];
            let (h, t) = spawn_on(client, &raw const user_ipc_client, args, 1, cpu)?;
            handles.push(h);
            threads.push(t);
        }
        let all_gone = || gone(&ts) && threads.iter().all(|t| gone(t));
        let done = wait_with(ipc_limit(2 * rounds), a != 0, all_gone);
        let ns = ktime::now_ns() - t0;
        let followed = follows() - follows0;
        let [s_status, s_count] = user_words::<2>(&server, DATA_VA, None)?;
        let mut counts = [0u64; 2];
        let mut statuses = [0u64; 2];
        for (i, c) in clients.iter().enumerate() {
            [statuses[i], counts[i]] = user_words::<2>(c, DATA_VA, None)?;
        }
        info!(
            "ktest: · clientes na cpu{a} e cpu{b}: {} + {} chamadas em {} ms, \
             servidor atendeu {s_count}, {followed} vez(es) seguiu quem chamou",
            counts[0],
            counts[1],
            ns / MS
        );
        ensure!(done);
        ensure!(s_status == STATUS_OK && statuses == [STATUS_OK; 2]);
        ensure!(counts == [rounds; 2] && s_count == 2 * rounds);
        ensure!(followed >= 1);
        drop((ts, threads, ep));
        delete(&server, &[hs])?;
        for (c, h) in clients.iter().zip(handles) {
            delete(c, &[h])?;
        }
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Aceite do T-327: 4 threads, cada uma começando numa CPU (com menos de
/// 4, repetindo), somam `smp.mutex` voltas cada sob um mutex de futex de
/// usuário. O total sai exato, todas terminam e cada espera no futex teve
/// exatamente um despertar, vindo de qualquer CPU.
pub fn mutex_de_usuario_em_4_cpus() -> Outcome {
    let online = ksmp::start::online_count();
    let rounds = option("smp.mutex", MUTEX_ROUNDS);
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    let before = FUTEXES.stats();
    {
        // Página 0: mutex (u32) e contador (u64); páginas 1 a 4: pilhas.
        let p = process(5)?;
        let mut handles = Vec::new();
        let mut threads = Vec::new();
        let mut cpus = Vec::new();
        for i in 0..4usize {
            let cpu = u32::try_from(i % online).map_err(|_| "cpu")?;
            let (h, t) = thread(&p)?;
            let entry = UserEntry {
                rip: user_symbol(&raw const user_mutex),
                rsp: DATA_VA + (i as u64 + 2) * PAGE_SIZE,
                args: [DATA_VA, DATA_VA + 8, rounds],
            };
            ensure!(start_on(&t, &entry, cpu).is_ok());
            handles.push(h);
            threads.push(t);
            cpus.push(cpu);
        }
        let limit = 60_000 * MS + rounds * 4 * 2_000_000;
        // O BSP também roda threads: gira cedendo a vez, sem `hlt`.
        let done = wait_with(limit, false, || threads.iter().all(|t| gone(t)));
        let [mutex, counter] = read_user::<2>(&p, DATA_VA)?;
        let after = FUTEXES.stats();
        let (blocked, woken) = (after.blocked - before.blocked, after.woken - before.woken);
        info!(
            "ktest: · cpus {cpus:?}: contador {counter} de {}; {blocked} esperas, \
             {woken} despertares, {} futex_wait recusados",
            4 * rounds,
            after.stale - before.stale
        );
        ensure!(done);
        ensure!(counter == 4 * rounds);
        ensure!(mutex == 0);
        ensure!(woken == blocked);
        drop(threads);
        delete(&p, &handles)?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Aceite do T-327: `Endpoint`, `Reply` e `Notification` destruídos do BSP
/// acordam com `PeerClosed` quem espera noutra CPU. Depois, em corrida, o
/// endpoint é apagado enquanto a thread noutra CPU ainda está entrando em
/// `ipc_recv`: ela termina sempre, com `PeerClosed` (já esperava, ou ainda
/// estava na janela e foi acordada na própria CPU) ou `InvalidHandle` (o
/// handle sumiu antes da syscall), nunca presa.
pub fn destruicao_concorrente_acorda_com_peer_closed() -> Outcome {
    let n = ksmp::start::online_count();
    if n < 2 {
        info!("ktest: · só uma CPU; nada a destruir de longe");
        return Ok(());
    }
    let far = u32::try_from(n - 1).map_err(|_| "id")?;
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    endpoint_de_longe(far)?;
    reply_de_longe(far)?;
    notificacao_de_longe(far)?;
    let rounds = option("smp.peer", PEER_ROUNDS);
    let (closed, invalid) = em_corrida(far, rounds)?;
    info!(
        "ktest: · {rounds} endpoints apagados em corrida com ipc_recv na cpu{far}: \
         {closed} PeerClosed, {invalid} InvalidHandle"
    );
    // Os atrasos longos pegam a thread já esperando.
    ensure!(closed > 0);
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Receptor parado em `ipc_recv` na CPU `far`; o endpoint é apagado daqui.
fn endpoint_de_longe(far: u32) -> Outcome {
    let p = process(2)?;
    let (ep_h, ep) = create(&p, ObjectType::Endpoint)?;
    let (reply, _) = create(&p, ObjectType::Reply)?;
    drop(ep);
    let args = [recv_target(ep_h, reply), 0, DATA_VA];
    let (h, t) = spawn_on(&p, &raw const user_ipc_recv, args, 1, far)?;
    ensure!(wait_for(LIMIT, || parked(&t)));
    delete(&p, &[ep_h])?;
    ensure!(wait_for(LIMIT, || gone(&t)));
    let [status] = user_words::<1>(&p, DATA_VA + 16, None)?;
    info!(
        "ktest: · endpoint apagado da cpu0: ipc_recv na cpu{far} voltou com {:?}",
        Error::try_from(status).ok()
    );
    ensure!(status == Error::PeerClosed.to_raw());
    drop(t);
    delete(&p, &[h, reply])
}

/// Cliente esperando a resposta na CPU `far`; o servidor recebe a chamada,
/// termina sem responder e o `Reply` é apagado daqui.
fn reply_de_longe(far: u32) -> Outcome {
    let (client, server) = (process(2)?, process(2)?);
    let (ep_h, ep) = create(&server, ObjectType::Endpoint)?;
    let (reply, _) = create(&server, ObjectType::Reply)?;
    let c_ep = give(&client, &ep, Rights::SEND, BADGE)?;
    drop(ep);
    let args = [recv_target(ep_h, reply), 0, DATA_VA];
    let (hs, ts) = spawn_on(&server, &raw const user_ipc_recv, args, 1, far)?;
    ensure!(wait_for(LIMIT, || parked(&ts)));
    let args = [u64::from(c_ep.raw()), 1, DATA_VA];
    let (hc, tc) = spawn_on(&client, &raw const user_ipc_client, args, 1, far)?;
    ensure!(wait_for(LIMIT, || gone(&ts) && parked(&tc)));
    delete(&server, &[reply])?;
    ensure!(wait_for(LIMIT, || gone(&tc)));
    let [status] = user_words::<1>(&client, DATA_VA, None)?;
    info!(
        "ktest: · Reply apagado da cpu0: ipc_call na cpu{} voltou com {:?}",
        tc.cpu(),
        Error::try_from(status).ok()
    );
    ensure!(status == Error::PeerClosed.to_raw());
    drop((ts, tc));
    delete(&server, &[hs])?;
    delete(&client, &[hc])
}

/// Thread esperando em `ntfy_wait` na CPU `far`; a notificação é apagada
/// daqui.
fn notificacao_de_longe(far: u32) -> Outcome {
    let p = process(1)?;
    let (ntfy_h, ntfy) = notification(&p)?;
    drop(ntfy);
    let (h, t) = park_on(&p, ntfy_h, far)?;
    delete(&p, &[ntfy_h])?;
    ensure!(wait_for(LIMIT, || gone(&t)));
    let [status, _, cpu] = read_user::<3>(&p, DATA_VA)?;
    info!(
        "ktest: · notificação apagada da cpu0: ntfy_wait na cpu{far} voltou com {:?} na cpu{cpu}",
        Error::try_from(status).ok()
    );
    ensure!(status == Error::PeerClosed.to_raw());
    drop(t);
    delete(&p, &[h])
}

/// `rounds` vezes: inicia na CPU `far` uma thread que entra em `ipc_recv`
/// e apaga o endpoint depois de um atraso que varre de 0 a 1,9 ms, para
/// cair antes da syscall, na janela de entrada na espera ou já com a
/// thread parada. Devolve quantas voltas deram `PeerClosed` e quantas
/// `InvalidHandle`.
pub(super) fn em_corrida(far: u32, rounds: u64) -> Result<(u64, u64), &'static str> {
    let p = process(2)?;
    let (mut closed, mut invalid) = (0u64, 0u64);
    for round in 0..rounds {
        let (ep_h, ep) = create(&p, ObjectType::Endpoint)?;
        let (reply, _) = create(&p, ObjectType::Reply)?;
        drop(ep);
        user_words(&p, DATA_VA + 16, Some([u64::MAX]))?;
        let args = [recv_target(ep_h, reply), 0, DATA_VA];
        let (h, t) = spawn_on(&p, &raw const user_ipc_recv, args, 1, far)?;
        let until = ktime::now_ns() + (round % 20) * 100_000;
        while ktime::now_ns() < until {
            ksmp::ipi::poll();
            core::hint::spin_loop();
        }
        delete(&p, &[ep_h])?;
        ensure!(wait_for(LIMIT, || gone(&t)));
        let [status] = user_words::<1>(&p, DATA_VA + 16, None)?;
        match Error::try_from(status) {
            Ok(Error::PeerClosed) => closed += 1,
            Ok(Error::InvalidHandle) => invalid += 1,
            _ => {
                info!("ktest: · status inesperado {status:#x}");
                return Err("ipc_recv voltou com outro status");
            }
        }
        drop(t);
        delete(&p, &[h, reply])?;
    }
    Ok((closed, invalid))
}
