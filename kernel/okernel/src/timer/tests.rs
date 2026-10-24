//! Testes no host do `Timer` e da fila de timers por CPU (T-349).

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::*;

const MS: u64 = 1_000_000;

fn queues() -> &'static TimerQueues {
    Box::leak(Box::new(TimerQueues::new()))
}

fn timer(quota: &Arc<MemoryQuota>, queues: &'static TimerQueues) -> Pin<Arc<Timer>> {
    Arc::pin(Timer::new(quota, queues).unwrap())
}

fn ntfy(quota: &Arc<MemoryQuota>) -> Arc<Notification> {
    Arc::new(Notification::new(quota).unwrap())
}

fn arm(
    t: &Pin<Arc<Timer>>,
    cpu: u32,
    now: u64,
    deadline: u64,
    period: u64,
    n: &Arc<Notification>,
    bits: u64,
) -> Armed {
    t.as_ref().arm(Arm {
        cpu,
        now,
        deadline,
        period,
        binding: (Arc::clone(n), bits),
    })
}

fn deadlines(q: &TimerQueues, cpu: u32) -> Vec<u64> {
    let mut out = [0u64; 64];
    let n = q.deadlines(cpu, &mut out);
    out[..n].to_vec()
}

/// Sinaliza o que venceu na CPU `cpu` em `now` (como o tratador) e devolve
/// os prazos que venceram.
fn fire(q: &TimerQueues, cpu: u32, now: u64) -> Vec<u64> {
    let mut fired = Vec::new();
    while let Some(Fired { binding, deadline }) = q.expire(cpu, now) {
        assert!(binding.0.signal(binding.1).is_none());
        fired.push(deadline);
    }
    fired
}

#[test]
fn argumentos_de_obj_bind_notify() {
    assert_eq!(parse(100, 1, 50, 0, 0), Ok(Some((50, 0))));
    assert_eq!(parse(100, 1, 50, 0, RELATIVE), Ok(Some((150, 0))));
    assert_eq!(
        parse(100, 1, u64::MAX, 0, RELATIVE),
        Ok(Some((u64::MAX, 0)))
    );
    // Período mínimo de 100 µs (ADR 0035, decisão de 2026-10-20).
    assert_eq!(
        parse(0, 1, 5, MIN_PERIOD_NS, 0),
        Ok(Some((5, MIN_PERIOD_NS)))
    );
    for period in [1, MIN_PERIOD_NS - 1] {
        assert_eq!(parse(0, 1, 5, period, 0), Err(Error::InvalidArgument));
        // Também ao desarmar.
        assert_eq!(parse(0, 0, 0, period, 0), Err(Error::InvalidArgument));
    }
    for flags in [2, 1 << 63, u64::MAX] {
        assert_eq!(parse(0, 1, 5, 0, flags), Err(Error::InvalidArgument));
    }
    // `bits = 0` ou `prazo = 0` desarmam (com ou sem `RELATIVE`).
    assert_eq!(parse(9, 0, 5, 0, 0), Ok(None));
    assert_eq!(parse(9, 1, 0, 0, 0), Ok(None));
    assert_eq!(parse(9, 1, 0, MIN_PERIOD_NS, RELATIVE), Ok(None));
}

#[test]
fn proximo_prazo_coalesce() {
    assert_eq!(next_after(100, 10, 100), 110);
    assert_eq!(next_after(100, 10, 105), 110);
    assert_eq!(next_after(100, 10, 110), 120);
    // Três períodos de atraso: um disparo só, e o próximo depois de agora.
    assert_eq!(next_after(100, 10, 135), 140);
    assert_eq!(next_after(u64::MAX - 5, 10, u64::MAX - 1), u64::MAX);
}

#[test]
fn fila_ordenada_por_prazo() {
    let quota = MemoryQuota::root(1 << 20);
    let q = queues();
    let n = ntfy(&quota);
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut ts = Vec::new();
    for i in 0..40u64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        // Prazos repetidos de propósito (FIFO entre iguais).
        let d = 1 + (state % 20) * MS;
        let t = timer(&quota, q);
        assert!(arm(&t, 3, 0, d, 0, &n, 1 << i).fire.is_none());
        ts.push((d, t));
    }
    let got = deadlines(q, 3);
    let mut want: Vec<u64> = ts.iter().map(|(d, _)| *d).collect();
    want.sort_unstable();
    assert_eq!(got, want);
    assert_eq!((q.len(3), q.first(3)), (40, want[0]));
    assert!(q.is_empty(0) && q.first(0) == NO_DEADLINE);
    // Disparo em ordem, só os vencidos.
    let fired = fire(q, 3, 10 * MS);
    assert!(fired.windows(2).all(|w| w[0] <= w[1]));
    assert!(fired.iter().all(|&d| d <= 10 * MS));
    assert_eq!(fired.len(), want.iter().filter(|&&d| d <= 10 * MS).count());
    assert_eq!(q.len(3), 40 - fired.len());
    assert!(q.first(3) > 10 * MS);
    let all: u64 = (0..40).map(|i| 1u64 << i).sum();
    let seen = n.poll();
    assert_ne!(seen, 0);
    assert_eq!(fire(q, 3, u64::MAX - 1).len(), 40 - fired.len());
    assert_eq!(seen | n.poll(), all);
    assert!(q.is_empty(3) && q.first(3) == NO_DEADLINE);
    // Disparo único desarma e solta a ligação.
    for (_, t) in &ts {
        assert_eq!(t.armed(), None);
    }
    assert_eq!(Arc::strong_count(&n), 1);
}

#[test]
fn rearme_troca_prazo_periodo_e_ligacao() {
    let quota = MemoryQuota::root(1 << 20);
    let q = queues();
    let (a, b) = (ntfy(&quota), ntfy(&quota));
    let t = timer(&quota, q);
    let first = arm(&t, 0, 0, 5 * MS, 0, &a, 1);
    assert_eq!(first.earlier, Some(5 * MS));
    assert!(first.old.is_none() && first.fire.is_none());
    let other = timer(&quota, q);
    assert_eq!(arm(&other, 0, 0, 7 * MS, 0, &a, 4).earlier, None);
    let again = arm(&t, 0, 0, 9 * MS, MIN_PERIOD_NS, &b, 2);
    let (old, bits) = again.old.expect("a ligação antiga volta");
    assert!(Arc::ptr_eq(&old, &a) && bits == 1);
    // O primeiro da fila ficou mais tarde: não precisa reprogramar.
    assert_eq!(again.earlier, None);
    assert_eq!(t.armed(), Some((9 * MS, MIN_PERIOD_NS)));
    assert_eq!(deadlines(q, 0), [7 * MS, 9 * MS]);
    assert_eq!(fire(q, 0, 9 * MS), [7 * MS, 9 * MS]);
    assert_eq!((a.poll(), b.poll()), (4, 2));
    // O periódico voltou com o próximo prazo.
    assert_eq!(t.armed(), Some((9 * MS + MIN_PERIOD_NS, MIN_PERIOD_NS)));
    assert_eq!(deadlines(q, 0), [9 * MS + MIN_PERIOD_NS]);
}

#[test]
fn desarme_sai_da_fila() {
    let quota = MemoryQuota::root(1 << 20);
    let q = queues();
    let n = ntfy(&quota);
    let ts: Vec<_> = (1..=3)
        .map(|i| {
            let t = timer(&quota, q);
            arm(&t, 1, 0, i * MS, 0, &n, 1);
            t
        })
        .collect();
    // Do meio, do começo e do fim.
    for (k, want) in [(1, [MS, 3 * MS].as_slice()), (0, &[3 * MS]), (2, &[])] {
        let (bound, bits) = ts[k].disarm().expect("estava armado");
        assert!(Arc::ptr_eq(&bound, &n) && bits == 1);
        assert_eq!(deadlines(q, 1), want);
        assert_eq!(ts[k].armed(), None);
    }
    assert!(ts[0].disarm().is_none());
    assert_eq!(q.first(1), NO_DEADLINE);
    assert!(fire(q, 1, u64::MAX - 1).is_empty());
    assert_eq!(n.poll(), 0);
}

#[test]
fn vencido_dispara_na_hora() {
    let quota = MemoryQuota::root(1 << 20);
    let q = queues();
    let n = ntfy(&quota);
    let t = timer(&quota, q);
    // Único vencido: dispara e fica desarmado, fora da fila.
    let armed = arm(&t, 2, 10 * MS, 10 * MS, 0, &n, 8);
    let (f, bits) = armed.fire.expect("prazo vencido dispara já");
    assert!(Arc::ptr_eq(&f, &n) && bits == 8);
    assert_eq!((t.armed(), q.len(2)), (None, 0));
    // Periódico vencido: dispara e volta com o próximo prazo.
    let armed = arm(&t, 2, 10 * MS, 3 * MS, MS, &n, 8);
    assert!(armed.fire.is_some());
    assert_eq!(armed.earlier, Some(11 * MS));
    assert_eq!(t.armed(), Some((11 * MS, MS)));
    // Único vencido sobre um armado: o armado sai, a ligação antiga volta.
    let armed = arm(&t, 2, 10 * MS, 1, 0, &n, 16);
    assert!(armed.fire.is_some() && armed.old.is_some());
    assert_eq!((t.armed(), q.len(2)), (None, 0));
}

#[test]
fn rearmar_noutra_cpu_migra() {
    let quota = MemoryQuota::root(1 << 20);
    let q = queues();
    let n = ntfy(&quota);
    let t = timer(&quota, q);
    assert_eq!(t.owner(), 0);
    arm(&t, 1, 0, 5 * MS, 0, &n, 1);
    assert_eq!((t.owner(), q.len(1)), (1, 1));
    // Rearmar de outra CPU: sai da fila da dona e entra na desta.
    let armed = arm(&t, 2, 0, 6 * MS, 0, &n, 1);
    assert!(armed.old.is_some());
    assert_eq!(armed.earlier, Some(6 * MS));
    assert_eq!((t.owner(), q.len(1), q.len(2)), (2, 0, 1));
    assert_eq!(q.first(1), NO_DEADLINE);
    // Desarmar (de qualquer CPU) toma a fila da dona e não muda a dona.
    assert!(t.disarm().is_some());
    assert_eq!((t.owner(), q.len(2)), (2, 0));
    // Armado e desarmado, armar noutra CPU também migra.
    arm(&t, 3, 0, 7 * MS, 0, &n, 1);
    assert_eq!((t.owner(), q.len(3)), (3, 1));
    // Vencido noutra CPU sem estar armado: dispara sem migrar.
    t.disarm();
    assert!(arm(&t, 4, 9 * MS, MS, 0, &n, 1).fire.is_some());
    assert_eq!(t.owner(), 3);
    assert!(fire(q, 3, u64::MAX - 1).is_empty());
}

#[test]
fn destruido_armado_sai_da_fila_e_devolve_a_cota() {
    let quota = MemoryQuota::root(1 << 20);
    let q = queues();
    let n = ntfy(&quota);
    let used = quota.used();
    let mut ts: Vec<_> = (1..=5u64)
        .map(|i| {
            let t = timer(&quota, q);
            arm(&t, 7, 0, i * MS, if i % 2 == 0 { MS } else { 0 }, &n, i);
            t
        })
        .collect();
    assert_eq!(Arc::strong_count(&n), 6);
    drop(ts.remove(2));
    drop(ts.remove(0));
    assert_eq!(deadlines(q, 7), [2 * MS, 4 * MS, 5 * MS]);
    drop(ts.pop());
    assert_eq!(deadlines(q, 7), [2 * MS, 4 * MS]);
    assert_eq!(q.first(7), 2 * MS);
    drop(ts);
    assert!(q.is_empty(7) && q.first(7) == NO_DEADLINE);
    assert_eq!(Arc::strong_count(&n), 1);
    assert_eq!(quota.used(), used);
    assert!(fire(q, 7, u64::MAX - 1).is_empty());
}

/// Disparo × rearme × desarme × destruição em quatro "CPUs" (threads do
/// host): cada uma arma `Timer`s de um conjunto comum (migrando-os), dispara
/// a própria fila, desarma e troca `Timer`s (o velho é destruído armado, às
/// vezes noutra fila). No fim, toda fila está consistente e a cota e as
/// referências à notificação voltam.
#[test]
fn corrida_entre_disparo_rearme_e_destruicao() {
    use std::sync::Mutex;
    type Slot = Mutex<Option<Pin<Arc<Timer>>>>;
    const CPUS: u32 = 4;
    const SLOTS: usize = 16;
    // Sob o Miri, poucas voltas (ele é umas mil vezes mais lento).
    const ROUNDS: u64 = if cfg!(miri) { 400 } else { 100_000 };
    let quota = MemoryQuota::root(4 << 20);
    let q = queues();
    let n = ntfy(&quota);
    let used = quota.used();
    let pool: Arc<Vec<Slot>> = Arc::new(
        (0..SLOTS)
            .map(|_| Mutex::new(Some(timer(&quota, q))))
            .collect(),
    );
    let clock = Arc::new(AtomicU64::new(1));
    let fired = Arc::new(AtomicU64::new(0));
    let workers: Vec<_> = (0..CPUS)
        .map(|cpu| {
            let (pool, clock, fired) = (Arc::clone(&pool), Arc::clone(&clock), Arc::clone(&fired));
            let (quota, n) = (Arc::clone(&quota), Arc::clone(&n));
            std::thread::spawn(move || {
                let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from(cpu);
                for i in 0..ROUNDS {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let now = clock.fetch_add(1, Ordering::Relaxed);
                    let slot = &pool[usize::try_from(state % SLOTS as u64).unwrap()];
                    let t = slot.lock().unwrap().clone();
                    let Some(t) = t else { continue };
                    match (state >> 32) % 8 {
                        0..=3 => {
                            let period = if state & 1 == 0 {
                                0
                            } else {
                                1 + (state >> 40) % 64
                            };
                            let deadline = now + (state >> 48) % 64;
                            let armed = arm(&t, cpu, now, deadline, period, &n, 1 << cpu);
                            if armed.fire.is_some() {
                                fired.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        4 => {
                            drop(t.disarm());
                        }
                        5 => {
                            // Troca o `Timer` do slot; o velho morre aqui ou
                            // com a última referência de outra thread.
                            drop(t);
                            let new = timer(&quota, q);
                            drop(slot.lock().unwrap().replace(new));
                        }
                        _ => {
                            drop(t);
                            while let Some(f) = q.expire(cpu, now) {
                                let _ = f.binding.0.signal(f.binding.1);
                                fired.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    if i % 64 == 0 {
                        std::thread::yield_now();
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert!(fired.load(Ordering::Relaxed) > 0);
    // Toda fila em ordem, com o tamanho certo, e cada `Timer` armado numa só.
    let armed: usize = pool
        .iter()
        .filter(|s| {
            s.lock()
                .unwrap()
                .as_ref()
                .is_some_and(|t| t.armed().is_some())
        })
        .count();
    let mut total = 0;
    for cpu in 0..CPUS {
        let d = deadlines(q, cpu);
        assert!(d.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(d.len(), q.len(cpu));
        total += d.len();
    }
    assert_eq!(total, armed);
    drop(pool);
    for cpu in 0..CPUS {
        assert!(q.is_empty(cpu), "cpu {cpu}");
        assert_eq!(q.first(cpu), NO_DEADLINE);
    }
    assert_eq!(Arc::strong_count(&n), 1);
    assert_eq!(quota.used(), used);
}

/// Mil `Timer`s numa fila (o aceite da T-349 fala em 1000): a ordem se
/// mantém e o disparo os entrega todos, cada um uma vez.
#[test]
fn mil_timers_numa_fila() {
    let quota = MemoryQuota::root(4 << 20);
    let q = queues();
    let ns: Vec<_> = (0..16).map(|_| ntfy(&quota)).collect();
    let ts: Vec<_> = (0..1000u64)
        .map(|i| {
            let t = timer(&quota, q);
            // Prazos fora de ordem.
            let d = 1 + (i * 7919) % 1000 * 1000;
            arm(&t, 5, 0, d, 0, &ns[(i % 16) as usize], 1 << (i / 16 % 63));
            t
        })
        .collect();
    assert_eq!(q.len(5), 1000);
    let mut last = 0;
    let mut count = 0;
    let mut now = 0;
    while now < 1_000_000 {
        now += 37_000;
        for d in fire(q, 5, now) {
            assert!(d >= last && d <= now);
            last = d;
            count += 1;
        }
    }
    assert_eq!(count, 1000);
    assert!(ts.iter().all(|t| t.armed().is_none()));
}
