//! Teste de kernel do escalonador com `SchedContext` (T-207).
//!
//! Duas threads de usuário giram lendo o relógio: H (prioridade 200,
//! 10 ms a cada 50 ms) e L (prioridade 100, sem limite). Pelo registro do
//! escalonador e pelo relógio, H nunca volta a rodar antes do fim da janela
//! em que esgotou o orçamento, as janelas dela se alinham ao período, ela
//! não passa (muito) do orçamento em janela alguma e L roda enquanto H
//! espera.

use alloc::sync::Arc;
use alloc::vec::Vec;

use kabi::vm::PAGE_SIZE;

use okernel::sched::Params;
use okernel::thread::RunState;

use super::super::{Event, UserEntry, start, trace_start, trace_take, yield_now};
use super::{DATA_VA, delete, process, thread_with, user_symbol};
use crate::arch::x86_64::cpu;
use crate::kcap::root_quota;
use crate::ktest::Outcome;
use crate::ktime;

unsafe extern "C" {
    static user_spin: u8;
}

const MS: u64 = 1_000_000;
const BUDGET: u64 = 10 * MS;
const PERIOD: u64 = 50 * MS;
const RUN_FOR: u64 = 300 * MS;
/// Atraso tolerado do timer ao cortar o orçamento (QEMU/TCG).
const SLACK: u64 = 5 * MS;
const TRACE: usize = 4096;

/// Uma volta `[start, end)` de uma thread.
type Span = (u64, u64);

pub fn sem_orcamento_espera() -> Outcome {
    ensure!(ktime::now_ns() != 0);
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let p = process(1)?;
        let h_params = Params::new(BUDGET, PERIOD, 200).map_err(|_| "params")?;
        let l_params = Params::new(MS, MS, 100).map_err(|_| "params")?;
        let (hh, h) = thread_with(&p, h_params)?;
        let (hl, l) = thread_with(&p, l_params)?;
        ensure!(trace_start(TRACE));
        let deadline = ktime::now_ns() + RUN_FOR;
        for t in [&h, &l] {
            let e = UserEntry {
                rip: user_symbol(&raw const user_spin),
                rsp: DATA_VA + PAGE_SIZE,
                args: [deadline, 0, 0],
            };
            ensure!(start(t, &e).is_ok());
        }
        // O ocioso roda as prontas e dorme até o próximo timer.
        let give_up = deadline + 2_000 * MS;
        while [&h, &l].iter().any(|t| t.state() != RunState::Exited) {
            ensure!(ktime::now_ns() < give_up);
            yield_now();
            cpu::wait_for_interrupt();
        }
        let trace = trace_take();
        ensure!(trace.len() < TRACE);
        let (h_id, l_id) = (Arc::as_ptr(&h).addr(), Arc::as_ptr(&l).addr());
        check(&trace, h_id, l_id)?;
        drop((h, l));
        delete(&p, &[hh, hl])?;
    }
    ensure!(quota.used() == used0);
    Ok(())
}

fn spans(trace: &[Event], id: usize) -> Vec<Span> {
    trace
        .iter()
        .filter_map(|e| match *e {
            Event::Ran { thread, start, end } if thread == id => Some((start, end)),
            _ => None,
        })
        .collect()
}

/// Tempo de `spans` dentro de `[from, to)`.
fn overlap(spans: &[Span], from: u64, to: u64) -> u64 {
    spans
        .iter()
        .map(|&(s, e)| e.min(to).saturating_sub(s.max(from)))
        .sum()
}

fn check(trace: &[Event], h_id: usize, l_id: usize) -> Outcome {
    let h_runs = spans(trace, h_id);
    let l_runs = spans(trace, l_id);
    let first = h_runs.first().ok_or("H não rodou")?.0;
    let throttles: Vec<Span> = trace
        .iter()
        .filter_map(|e| match *e {
            Event::Throttled { thread, at, until } if thread == h_id => Some((at, until)),
            _ => None,
        })
        .collect();
    let windows = (RUN_FOR / PERIOD) as usize;
    let mut used = Vec::new();
    for k in 0..windows as u64 {
        let from = first + k * PERIOD;
        used.push(overlap(&h_runs, from, from + PERIOD) / 1000);
    }
    info!(
        "ktest: · H: {} voltas, {} esperas; µs por janela de 50 ms: {used:?}; L: {} voltas",
        h_runs.len(),
        throttles.len(),
        l_runs.len()
    );
    ensure!(throttles.len() >= 3);
    for &(at, until) in &throttles {
        // A espera vai até um limite de período contado da primeira volta.
        ensure!(until > at && (until - first) % PERIOD == 0);
        // Nenhuma volta de H começa durante a espera.
        ensure!(!h_runs.iter().any(|&(s, _)| s >= at && s < until));
        // L usa a CPU enquanto H espera.
        ensure!(overlap(&l_runs, at, until) > 0);
    }
    // Em nenhuma janela H passa do orçamento (com a folga do timer), e roda
    // em pelo menos três delas. No TCG, uma preempção do QEMU pelo host
    // atrasa o timer e entra inteira numa janela: lá a exigência vale para
    // a mediana das janelas, e a pior só é registrada.
    let mut sorted = used.clone();
    sorted.sort_unstable();
    let within = |us: u64| us * 1000 <= BUDGET + SLACK;
    if cpu::under_tcg() {
        ensure!(within(sorted[sorted.len() / 2]));
    } else {
        ensure!(used.iter().all(|&us| within(us)));
    }
    ensure!(used.iter().filter(|&&us| us > 0).count() >= 3);
    Ok(())
}
