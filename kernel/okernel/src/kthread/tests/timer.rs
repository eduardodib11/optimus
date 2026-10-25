//! Testes de kernel do objeto `Timer` (T-349; ADR 0035, item 6): disparo
//! pelo tratador do timer da CPU dona, mil timers no prazo, periódico com
//! coalescência, desarme, migração entre CPUs e destruição de um `Timer`
//! armado noutra CPU, também durante o disparo.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};

use okernel::cap::MemoryQuota;
use okernel::notify::Notification;
use okernel::sync::{LockClass, SpinLock};
use okernel::timer::{Arm, NO_DEADLINE, QUEUES, Timer};

use super::super::{timer_stats, timer_stats_reset, wake};
use super::settled;
use super::smp::{LIMIT, MS, wait_for};
use crate::arch::x86_64::{cpu, percpu};
use crate::kcap::root_quota;
use crate::ksmp;
use crate::ktest::Outcome;
use crate::ktime;

fn new_timer(q: &Arc<MemoryQuota>) -> Result<Pin<Arc<Timer>>, &'static str> {
    Timer::new(q, &QUEUES)
        .map(Arc::pin)
        .map_err(|_| "Timer::new")
}

fn new_ntfy(q: &Arc<MemoryQuota>) -> Result<Arc<Notification>, &'static str> {
    Notification::new(q)
        .map(Arc::new)
        .map_err(|_| "Notification::new")
}

/// Arma `t` nesta CPU como `obj_bind_notify` faz: prazo vencido sinaliza
/// já, e um primeiro prazo mais cedo arma o timer de hardware.
fn arm(t: &Pin<Arc<Timer>>, n: &Arc<Notification>, bits: u64, deadline: u64, period: u64) {
    let armed = t.as_ref().arm(Arm {
        cpu: percpu::cpu_id(),
        now: ktime::now_ns(),
        deadline,
        period,
        binding: (Arc::clone(n), bits),
    });
    if let Some(at) = armed.earlier {
        ktime::arm_by(at);
    }
    drop(armed.old);
    if let Some((n, bits)) = armed.fire
        && let Some((t, word)) = n.signal(bits)
    {
        wake(t, word);
    }
}

/// Atraso aceito no disparo (aceite da T-349): 100 µs com KVM, 1 ms no TCG.
fn late_limit() -> u64 {
    if cpu::under_tcg() { MS } else { 100_000 }
}

/// Aceite da T-349: mil `Timer`s armados nesta CPU, com prazos
/// embaralhados ao longo de 20 ms, disparam todos, uma vez cada, com os
/// bits certos, e a cota volta. O atraso (do prazo ao tratador) fica no
/// limite em 99% deles com KVM; no TCG, na mediana (o pior caso e o p99 só
/// são registrados: lá o despertar do `hlt` é do QEMU).
pub fn mil_no_prazo() -> Outcome {
    const N: u64 = 1000;
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    let limit = late_limit();
    {
        let ns = (0..16)
            .map(|_| new_ntfy(&quota))
            .collect::<Result<Vec<_>, _>>()?;
        let ts = (0..N)
            .map(|_| new_timer(&quota))
            .collect::<Result<Vec<_>, _>>()?;
        let me = percpu::cpu_id();
        let queued0 = QUEUES.len(me);
        let fires0 = timer_stats().fires;
        timer_stats_reset();
        // Folga para armar os mil antes do primeiro prazo (a inserção
        // procura a posição a partir do fim: com prazos embaralhados, até
        // mil passos cada, no build de depuração sob TCG).
        let t0 = ktime::now_ns();
        let base = t0 + 200 * MS;
        let mut want = [0u64; 16];
        for (i, t) in (0..N).zip(&ts) {
            let k = (i % 16) as usize;
            let bit = 1 << (i / 16);
            want[k] |= bit;
            arm(t, &ns[k], bit, base + (i * 7919 % N) * 20_000, 0);
        }
        let took = ktime::now_ns() - t0;
        info!("ktest: · {N} timers armados em {} µs", took / 1000);
        ensure!(QUEUES.len(me) == queued0 + usize::try_from(N).unwrap_or(usize::MAX));
        ensure!(QUEUES.first(me) <= base);
        let done = wait_for(LIMIT, || timer_stats().fires >= fires0 + N);
        let st = timer_stats();
        let (median, p99) = (st.quantile(1, 2), st.quantile(99, 100));
        info!(
            "ktest: · {} disparos de {N} timers; atraso: mediana ≤ {} µs, p99 ≤ {} µs, pior {} µs (faixas {:?})",
            st.fires - fires0,
            median / 1000,
            p99 / 1000,
            st.late_max / 1000,
            st.late
        );
        ensure!(done);
        ensure!(st.fires - fires0 == N);
        // No TCG o tempo de acordar do `hlt` é do QEMU (o teste
        // `time.timer_dispara_no_prazo` já mostra milissegundos), então só a
        // mediana é exigida; com KVM, o p99.
        ensure!(if cpu::under_tcg() {
            median <= limit
        } else {
            p99 <= limit
        });
        for (n, &w) in ns.iter().zip(&want) {
            ensure!(n.poll() == w);
        }
        ensure!(ts.iter().all(|t| t.armed().is_none()));
        ensure!(QUEUES.len(me) == queued0);
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Periódico de 1 ms: dez disparos em pelo menos 10 ms; 5 ms sem atender
/// interrupções viram um disparo só (coalescência) e o próximo prazo fica
/// depois de agora; desarmado, não dispara mais; rearmado com prazo vencido,
/// sinaliza antes de voltar e fica desarmado.
pub fn periodico_coalesce_e_desarme() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let n = new_ntfy(&quota)?;
        let t = new_timer(&quota)?;
        let f0 = timer_stats().fires;
        let start = ktime::now_ns();
        arm(&t, &n, 1, start + MS, MS);
        ensure!(t.owner() == percpu::cpu_id());
        ensure!(wait_for(LIMIT, || timer_stats().fires >= f0 + 10));
        ensure!(ktime::now_ns() - start >= 10 * MS);
        ensure!(n.poll() == 1);
        // Sem interrupções (IF=0) por cinco períodos.
        let f1 = timer_stats().fires;
        let until = ktime::now_ns() + 5 * MS;
        while ktime::now_ns() < until {
            ksmp::ipi::poll();
            core::hint::spin_loop();
        }
        ensure!(wait_for(LIMIT, || timer_stats().fires > f1));
        let f2 = timer_stats().fires;
        let (next, period) = t.armed().ok_or("o periódico desarmou")?;
        info!(
            "ktest: · 5 períodos sem interrupção deram {} disparo(s)",
            f2 - f1
        );
        ensure!(f2 - f1 <= 2);
        ensure!(period == MS && next > until);
        // Desarmado: nada mais.
        drop(t.disarm());
        let f3 = timer_stats().fires;
        let _ = wait_for(5 * MS, || false);
        ensure!(timer_stats().fires == f3);
        ensure!(t.armed().is_none());
        let _ = n.poll();
        // Prazo vencido: o bit chega antes de `arm` voltar.
        arm(&t, &n, 2, 1, 0);
        ensure!(n.poll() == 2);
        ensure!(t.armed().is_none());
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Um `Timer` e a notificação ligada a ele.
type Pair = (Pin<Arc<Timer>>, Arc<Notification>);
/// O `Timer` e a notificação que os APs usam ([`ap_job`]).
static SHARED: SpinLock<Option<Pair>> = SpinLock::with_class(LockClass::Diagnostic, None);
/// O que [`ap_job`] faz.
static MODE: AtomicUsize = AtomicUsize::new(0);
/// APs que terminaram o trabalho.
static JOBS: AtomicUsize = AtomicUsize::new(0);
/// `Timer`s por AP na corrida de disparo × destruição.
const PER_AP: usize = 32;
/// APs que entram na corrida (os primeiros oito).
const RACERS: usize = 8;
/// Os `Timer`s da corrida, `PER_AP` por AP.
static SLOTS: [SpinLock<Option<Pin<Arc<Timer>>>>; PER_AP * RACERS] =
    [const { SpinLock::with_class(LockClass::Diagnostic, None) }; PER_AP * RACERS];

/// Trabalho dos APs: rearmar o `Timer` comum (modo 0, cem vezes, migrando),
/// armá-lo longe só no AP 1 (modo 1) ou armar `PER_AP` `Timer`s próprios
/// com prazos nos próximos 2 ms (modo 2).
fn ap_job() {
    let me = percpu::cpu_id();
    let shared = SHARED.lock().clone();
    if let Some((t, n)) = shared {
        match MODE.load(Ordering::Acquire) {
            0 => {
                for k in 0..100 {
                    arm(&t, &n, 1 << me, ktime::now_ns() + 30 * MS + k, 0);
                }
            }
            1 if me == 1 => arm(&t, &n, 2, ktime::now_ns() + 10_000 * MS, 0),
            2 if (1..=RACERS).contains(&(me as usize)) => {
                let quota = root_quota();
                let base = (me as usize - 1) * PER_AP;
                for (k, slot) in SLOTS[base..base + PER_AP].iter().enumerate() {
                    let Some(timer) = quota.as_ref().and_then(|q| new_timer(q).ok()) else {
                        continue;
                    };
                    let k = k as u64;
                    let period = if k.is_multiple_of(4) { 200_000 } else { 0 };
                    arm(
                        &timer,
                        &n,
                        1 << (k % 64),
                        ktime::now_ns() + k * 60_000,
                        period,
                    );
                    let old = slot.lock().replace(timer);
                    drop(old);
                }
            }
            _ => {}
        }
    }
    JOBS.fetch_add(1, Ordering::AcqRel);
}

/// Roda [`ap_job`] no modo `mode` em todos os APs e espera terminarem.
fn run_aps(mode: usize, aps: usize) -> bool {
    MODE.store(mode, Ordering::Release);
    JOBS.store(0, Ordering::Release);
    ksmp::start::post_ap_job(ap_job);
    wait_for(LIMIT, || JOBS.load(Ordering::Acquire) >= aps)
}

/// Com várias CPUs: o `Timer` rearmado ao mesmo tempo do BSP e de todos os
/// APs fica numa fila só, a da última CPU que armou, e dispara lá com os
/// bits dela; armado longe no AP 1 e destruído do BSP, sai da fila do AP 1;
/// e `Timer`s armados nos APs, disparando no tratador deles enquanto o BSP
/// os destrói, não deixam nó na fila nem cota presa.
pub fn migra_e_morre_armado() -> Outcome {
    let n_cpus = ksmp::start::online_count();
    if n_cpus < 2 {
        info!("ktest: · só uma CPU; nada a migrar");
        return Ok(());
    }
    let aps = n_cpus - 1;
    let cpus = 0..u32::try_from(n_cpus).map_err(|_| "cpus demais")?;
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let n = new_ntfy(&quota)?;
        let t = new_timer(&quota)?;
        *SHARED.lock() = Some((t.clone(), Arc::clone(&n)));
        // Migração concorrente.
        MODE.store(0, Ordering::Release);
        JOBS.store(0, Ordering::Release);
        ksmp::start::post_ap_job(ap_job);
        for k in 0..100 {
            arm(&t, &n, 1, ktime::now_ns() + 30 * MS + k, 0);
            ksmp::ipi::poll();
        }
        ensure!(wait_for(LIMIT, || JOBS.load(Ordering::Acquire) >= aps));
        let owner = t.owner();
        ensure!(t.armed().is_some());
        let mut holding = 0;
        for c in cpus.clone() {
            if QUEUES.first(c) != NO_DEADLINE {
                holding += 1;
                ensure!(c == owner);
            }
        }
        ensure!(holding == 1 && QUEUES.len(owner) == 1);
        let _ = n.poll();
        ensure!(wait_for(LIMIT, || n.pending() != 0));
        let bits = n.poll();
        info!("ktest: · o timer migrou para a cpu{owner} e disparou lá");
        ensure!(bits == 1 << owner);
        ensure!(t.armed().is_none() && QUEUES.is_empty(owner));
        // Armado longe no AP 1 e destruído daqui.
        ensure!(run_aps(1, aps));
        ensure!(t.owner() == 1 && QUEUES.len(1) == 1);
        ensure!(QUEUES.first(1) != NO_DEADLINE);
        *SHARED.lock() = Some((new_timer(&quota)?, Arc::clone(&n)));
        drop(t);
        ensure!(QUEUES.is_empty(1) && QUEUES.first(1) == NO_DEADLINE);
        // Disparo nos APs × destruição no BSP.
        ensure!(run_aps(2, aps));
        let armed: usize = cpus
            .clone()
            .skip(1)
            .take(RACERS)
            .map(|c| QUEUES.len(c))
            .sum();
        let end = ktime::now_ns() + 3 * MS;
        let mut i = 0;
        while ktime::now_ns() < end {
            let old = SLOTS[i % SLOTS.len()].lock().take();
            drop(old);
            i += 7;
            for _ in 0..200 {
                ksmp::ipi::poll();
                core::hint::spin_loop();
            }
        }
        for slot in &SLOTS {
            let old = slot.lock().take();
            drop(old);
        }
        let old = SHARED.lock().take();
        drop(old);
        info!("ktest: · {armed} timers armados nos APs, destruídos durante o disparo");
        for c in cpus {
            ensure!(QUEUES.is_empty(c));
            ensure!(QUEUES.first(c) == NO_DEADLINE);
        }
        // Um tratador pode ainda estar sinalizando um disparo de antes.
        ensure!(wait_for(LIMIT, || Arc::strong_count(&n) == 1));
    }
    ensure!(settled(&quota, used0));
    Ok(())
}
