//! Teste de kernel da doação de `SchedContext` em `ipc_call` (seção 6.6).
//!
//! Inversão de prioridade clássica: um cliente de prioridade 200 chama um
//! servidor de prioridade 10 enquanto uma thread de prioridade 100 gira
//! por 50 ms. Com a doação, o servidor atende com a prioridade do cliente
//! e o cliente termina antes de a do meio rodar; sem ela, o servidor
//! esperaria a do meio, e o cliente com ele.

use alloc::sync::Arc;
use alloc::vec::Vec;

use kabi::ipc::recv_target;
use kabi::vm::PAGE_SIZE;
use kabi::{ObjectType, Rights, STATUS_OK};
use okernel::sched::Params;
use okernel::thread::{RunState, Thread};

use super::{BADGE, create, give, run_until_blocked, user_words};
use crate::arch::x86_64::cpu;
use crate::ktest::Outcome;
use crate::kthread::tests::{DATA_VA, Process, delete, pin, process, thread_with, user_symbol};
use crate::kthread::{Event, UserEntry, start, trace_start, trace_take, yield_now};
use crate::ktime;

unsafe extern "C" {
    static user_ipc_server: u8;
    static user_ipc_client: u8;
    static user_spin: u8;
}

const MS: u64 = 1_000_000;

/// Inicia em `p` uma thread de prioridade `priority` (sem limite de
/// orçamento) em `sym`, com a pilha na página 1 e o buffer de IPC na página 0,
/// presa a esta CPU: a inversão e o registro são de uma CPU só.
fn spawn_at(
    p: &Process,
    priority: u64,
    sym: *const u8,
    args: [u64; 3],
) -> Result<(kabi::Handle, Arc<Thread>), &'static str> {
    let params = Params::new(MS, MS, priority).map_err(|_| "params")?;
    let (h, t) = thread_with(p, params)?;
    pin(&t, crate::arch::x86_64::percpu::cpu_id())?;
    t.set_ipc_buffer(DATA_VA).map_err(|_| "buffer")?;
    let e = UserEntry {
        rip: user_symbol(sym),
        rsp: DATA_VA + 2 * PAGE_SIZE,
        args,
    };
    ensure!(start(&t, &e).is_ok());
    Ok((h, t))
}

/// Voltas `[start, end)` da thread `t` no registro do escalonador.
fn spans(trace: &[Event], t: &Arc<Thread>) -> Vec<(u64, u64)> {
    let id = Arc::as_ptr(t).addr();
    trace
        .iter()
        .filter_map(|e| match *e {
            Event::Ran { thread, start, end } if thread == id => Some((start, end)),
            _ => None,
        })
        .collect()
}

pub fn sem_inversao_de_prioridade() -> Outcome {
    let (client, server, other) = (process(2)?, process(2)?, process(2)?);
    let (ep_h, ep) = create(&server, ObjectType::Endpoint)?;
    let (reply, _) = create(&server, ObjectType::Reply)?;
    let c_ep = give(&client, &ep, Rights::SEND, BADGE)?;
    drop(ep);
    user_words(&server, DATA_VA + 16, Some([BADGE]))?;
    let args = [recv_target(ep_h, reply), 1, DATA_VA];
    let (hs, ts) = spawn_at(&server, 10, &raw const user_ipc_server, args)?;
    run_until_blocked(&ts)?;
    ensure!(trace_start(256));
    let deadline = ktime::now_ns() + 50 * MS;
    let (ho, to) = spawn_at(&other, 100, &raw const user_spin, [deadline, 0, 0])?;
    let args = [u64::from(c_ep.raw()), 1, DATA_VA];
    let (hc, tc) = spawn_at(&client, 200, &raw const user_ipc_client, args)?;
    let all = [Arc::clone(&ts), Arc::clone(&to), Arc::clone(&tc)];
    let give_up = deadline + 2_000 * MS;
    while all.iter().any(|t| t.state() != RunState::Exited) {
        ensure!(ktime::now_ns() < give_up);
        yield_now();
        cpu::wait_for_interrupt();
    }
    let trace = trace_take();
    let [status, count] = user_words::<2>(&client, DATA_VA, None)?;
    let (c, s, o) = (spans(&trace, &tc), spans(&trace, &ts), spans(&trace, &to));
    let other_start = o.first().ok_or("a do meio não rodou")?.0;
    let client_end = c.last().ok_or("o cliente não rodou")?.1;
    let attended = s.first().ok_or("o servidor não rodou")?.0;
    info!(
        "ktest: · cliente terminou {} µs antes de a thread do meio começar; servidor atendeu em {} µs",
        other_start.saturating_sub(client_end) / 1000,
        attended.saturating_sub(c[0].0) / 1000
    );
    ensure!(status == STATUS_OK && count == 1);
    ensure!(client_end <= other_start && attended < other_start);
    drop(all);
    drop((ts, to, tc));
    delete(&server, &[hs])?;
    delete(&other, &[ho])?;
    delete(&client, &[hc])?;
    Ok(())
}
