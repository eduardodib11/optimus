//! Testes de `ostd::time` e dos prazos de espera (T-338; ADR 0035, item 6;
//! ADR 0039): `Instant`, `sleep` curto e longo, `sleep` em várias threads,
//! `Condvar::wait_timeout` que estoura e que é acordada antes, e
//! `JoinHandle::join_timeout`.
//!
//! Folga declarada: o limite de baixo é rígido (nunca antes do prazo); o de
//! cima do aceite do backlog (`sleep(10 ms)` entre 10 e 15 ms) vale para a
//! **melhor** de várias medidas, e cada medida tem o teto largo de
//! [`SLACK`]: sob TCG com várias vCPUs emuladas na mesma máquina, uma vCPU
//! pode ficar centenas de ms parada.

use alloc::sync::Arc;
use alloc::vec::Vec;

use ostd::sync::{Condvar, Mutex};
use ostd::thread;
use ostd::time::{Duration, Instant, now_ns, sleep, sleep_until};

use crate::{Ctx, Outcome};

const MS: Duration = Duration::from_millis(1);
/// Teto de cada medida (ver o módulo).
const SLACK: Duration = Duration::from_secs(2);

/// `Instant` monótono (inclusive lido por threads em várias CPUs) e a
/// aritmética de `Instant` e `Duration`.
pub fn instant(_: &Ctx) -> Outcome {
    let mut last = Instant::now();
    for _ in 0..20_000 {
        let now = Instant::now();
        if now < last {
            return Err("Instant voltou atrás");
        }
        last = now;
    }
    // Várias threads: o que uma lê depois de outra terminar não é menor.
    let hs: Vec<_> = (0..3)
        .map(|_| {
            thread::spawn(|| {
                let mut last = Instant::now();
                for _ in 0..5_000 {
                    let now = Instant::now();
                    if now < last {
                        return false;
                    }
                    last = now;
                }
                true
            })
        })
        .collect();
    for h in hs {
        if !h.join().map_err(|_| "thread de Instant")? {
            return Err("Instant voltou atrás numa thread");
        }
    }
    let a = Instant::now();
    let b = a + 5 * MS;
    if b - a != 5 * MS || a - b != Duration::ZERO || b.duration_since(a) != 5 * MS {
        return Err("aritmética de Instant");
    }
    if a.checked_duration_since(b).is_some() || b.checked_duration_since(a) != Some(5 * MS) {
        return Err("checked_duration_since");
    }
    if (b - 5 * MS) != a || a.checked_add(Duration::MAX).is_some() {
        return Err("subtração ou soma que estoura");
    }
    if (a + Duration::MAX).as_ns() != u64::MAX || Instant::from_ns(3).as_ns() != 3 {
        return Err("soma saturada ou from_ns");
    }
    if Instant::from_ns(1) - Duration::from_secs(1) != Instant::from_ns(0) {
        return Err("subtração saturada");
    }
    if a.elapsed() > SLACK {
        return Err("elapsed absurdo");
    }
    Ok(())
}

/// `sleep(10 ms)`: nunca menos de 10 ms e, na melhor de 8 medidas, até 15
/// ms (aceite do backlog); `sleep(0)` e `sleep_until` no passado voltam
/// logo.
pub fn sleep_curto(_: &Ctx) -> Outcome {
    let mut best = Duration::MAX;
    for _ in 0..8 {
        let t0 = Instant::now();
        sleep(10 * MS);
        let took = t0.elapsed();
        if took < 10 * MS {
            return Err("sleep(10 ms) voltou antes do prazo");
        }
        if took > 10 * MS + SLACK {
            return Err("sleep(10 ms) passou do teto");
        }
        best = best.min(took);
    }
    ostd::debug::print_fmt(format_args!(
        "utest: sleep(10 ms): melhor medida {} us",
        best.as_micros()
    ));
    if best > 15 * MS {
        return Err("sleep(10 ms): nem a melhor medida ficou até 15 ms");
    }
    let t0 = Instant::now();
    sleep(Duration::ZERO);
    sleep_until(t0);
    sleep_until(Instant::from_ns(1));
    if t0.elapsed() > SLACK {
        return Err("sleep(0) ou sleep_until no passado demorou");
    }
    // Muitos sleeps seguidos com o mesmo par de objetos (um por thread, no
    // TLS): nada se acumula nem trava.
    let t0 = Instant::now();
    for _ in 0..300 {
        sleep(Duration::from_micros(200));
    }
    if t0.elapsed() < Duration::from_micros(200) * 300 {
        return Err("300 sleeps de 200 µs voltaram cedo demais");
    }
    Ok(())
}

/// `sleep` longo (300 ms) e `sleep_until`, com o relógio do kernel.
pub fn sleep_longo(_: &Ctx) -> Outcome {
    let t0 = now_ns();
    sleep(300 * MS);
    let took = now_ns() - t0;
    if !(300_000_000..=2_300_000_000).contains(&took) {
        return Err("sleep(300 ms) fora da faixa");
    }
    let until = Instant::now() + 50 * MS;
    sleep_until(until);
    if Instant::now() < until {
        return Err("sleep_until voltou antes do prazo");
    }
    Ok(())
}

/// Quatro threads dormem ao mesmo tempo, cada uma várias vezes: cada
/// `sleep` cumpre o prazo, e os sonos se sobrepõem (o total fica longe da
/// soma).
pub fn sleep_em_threads(_: &Ctx) -> Outcome {
    const N: u64 = 4;
    let t0 = Instant::now();
    let hs: Vec<_> = (0..N)
        .map(|i| {
            thread::spawn(move || {
                let each = Duration::from_millis(20 + 15 * i);
                for _ in 0..5 {
                    let s = Instant::now();
                    sleep(each);
                    let took = s.elapsed();
                    if took < each || took > each + SLACK {
                        return false;
                    }
                }
                true
            })
        })
        .collect();
    for h in hs {
        if !h.join().map_err(|_| "thread de sleep")? {
            return Err("um sleep numa thread fora da faixa");
        }
    }
    // Em série seriam 5 × (20 + 35 + 50 + 65) = 850 ms.
    if t0.elapsed() > Duration::from_millis(700) {
        return Err("os sleeps das threads não se sobrepuseram");
    }
    Ok(())
}

/// `wait_timeout` que estoura (volta com a trava, depois do prazo, uma vez
/// só) e com prazo zero.
pub fn condvar_estoura(_: &Ctx) -> Outcome {
    let m = Mutex::new(0u32);
    let cv = Condvar::new();
    for _ in 0..3 {
        let g = m.lock();
        let t0 = Instant::now();
        let (mut g, r) = cv.wait_timeout(g, 20 * MS);
        let took = t0.elapsed();
        if !r.timed_out() {
            return Err("ninguém notificou: devia estourar");
        }
        if took < 20 * MS || took > 20 * MS + SLACK {
            return Err("wait_timeout(20 ms) fora da faixa");
        }
        // Voltou com a trava: tocar no dado é seguro e outro `lock` falha.
        *g += 1;
        if m.try_lock().is_some() {
            return Err("wait_timeout voltou sem a trava");
        }
    }
    let g = m.lock();
    let t0 = Instant::now();
    let (g, r) = cv.wait_timeout(g, Duration::ZERO);
    if !r.timed_out() || t0.elapsed() > SLACK {
        return Err("wait_timeout(0) devia estourar logo");
    }
    let (g, r) = cv.wait_timeout_while(g, 15 * MS, |v| *v == 3);
    if !r.timed_out() || *g != 3 {
        return Err("wait_timeout_while sem notificação devia estourar");
    }
    Ok(())
}

/// `wait_timeout` acordada antes do prazo, por `notify_one` e por
/// `notify_all` (esperas com e sem prazo juntas).
pub fn condvar_acordada(_: &Ctx) -> Outcome {
    struct S {
        flag: Mutex<u32>,
        cv: Condvar,
    }
    let s = Arc::new(S {
        flag: Mutex::new(0),
        cv: Condvar::new(),
    });
    // notify_one a uma espera com prazo de 5 s.
    let t0 = Instant::now();
    let h = {
        let s = Arc::clone(&s);
        thread::spawn(move || {
            sleep(20 * MS);
            *s.flag.lock() = 1;
            s.cv.notify_one();
        })
    };
    let g = s.flag.lock();
    let (g, r) =
        s.cv.wait_timeout_while(g, Duration::from_secs(5), |v| *v == 0);
    if r.timed_out() || *g != 1 {
        return Err("notify_one não acordou a espera com prazo");
    }
    drop(g);
    if t0.elapsed() > Duration::from_secs(3) {
        return Err("a espera acordada demorou quase o prazo todo");
    }
    h.join().map_err(|_| "notificadora")?;
    // notify_all: 3 com prazo e 2 sem.
    *s.flag.lock() = 0;
    let waiters: Vec<_> = (0..5)
        .map(|i| {
            let s = Arc::clone(&s);
            thread::spawn(move || {
                let g = s.flag.lock();
                if i < 3 {
                    let (g, r) =
                        s.cv.wait_timeout_while(g, Duration::from_secs(10), |v| *v == 0);
                    !r.timed_out() && *g == 1
                } else {
                    let g = s.cv.wait_while(g, |v| *v == 0);
                    *g == 1
                }
            })
        })
        .collect();
    sleep(60 * MS);
    *s.flag.lock() = 1;
    s.cv.notify_all();
    for h in waiters {
        if !h.join().map_err(|_| "esperadora")? {
            return Err("notify_all não acordou todas");
        }
    }
    Ok(())
}

/// Um produtor e dois consumidores com `wait_timeout_while`: 5 000 itens,
/// cada um uma vez, e nenhum estouro de prazo (de 1 s) — um `notify` perdido
/// custaria o prazo inteiro.
pub fn condvar_sem_perda(_: &Ctx) -> Outcome {
    use alloc::collections::VecDeque;
    struct Q {
        items: Mutex<(VecDeque<u32>, bool)>,
        cv: Condvar,
    }
    const N: u32 = 5_000;
    let q = Arc::new(Q {
        items: Mutex::new((VecDeque::new(), false)),
        cv: Condvar::new(),
    });
    let consumers: Vec<_> = (0..2)
        .map(|_| {
            let q = Arc::clone(&q);
            thread::spawn(move || {
                let mut got = Vec::new();
                let mut timeouts = 0u32;
                loop {
                    let g = q.items.lock();
                    let (mut g, r) = q
                        .cv
                        .wait_timeout_while(g, Duration::from_secs(1), |s| s.0.is_empty() && !s.1);
                    timeouts += u32::from(r.timed_out());
                    let Some(v) = g.0.pop_front() else { break };
                    drop(g);
                    got.push(v);
                }
                (got, timeouts)
            })
        })
        .collect();
    for i in 0..N {
        q.items.lock().0.push_back(i);
        q.cv.notify_one();
        if i % 64 == 0 {
            thread::yield_now();
        }
    }
    q.items.lock().1 = true;
    q.cv.notify_all();
    let mut seen = alloc::vec![0u8; N as usize];
    let mut stalls = 0;
    for h in consumers {
        let (got, timeouts) = h.join().map_err(|_| "consumidor")?;
        stalls += timeouts;
        for v in got {
            *seen.get_mut(v as usize).ok_or("item fora da faixa")? += 1;
        }
    }
    if seen.iter().any(|&n| n != 1) {
        return Err("item perdido ou repetido");
    }
    if stalls > 1 {
        // O último `wait` de cada consumidor pode acabar em prazo se o
        // encerramento chegar depois; mais que isso é `notify` perdido.
        return Err("espera com prazo estourou: notify perdido");
    }
    Ok(())
}

/// `join_timeout`: prazo curto devolve o `JoinHandle` (a thread segue e
/// pode ser juntada depois), prazo largo junta com o resultado; thread que
/// já terminou junta logo.
pub fn join_com_prazo(_: &Ctx) -> Outcome {
    let h = thread::spawn(|| {
        sleep(120 * MS);
        7u32
    });
    let t0 = Instant::now();
    let Err(h) = h.join_timeout(10 * MS) else {
        return Err("join_timeout(10 ms) devia estourar");
    };
    let took = t0.elapsed();
    if took < 10 * MS || took > 10 * MS + SLACK {
        return Err("join_timeout(10 ms) fora da faixa");
    }
    match h.join_timeout(Duration::from_secs(20)) {
        Ok(Ok(7)) => {}
        _ => return Err("join_timeout largo devia juntar o resultado"),
    }
    let h = thread::spawn(|| 9u32);
    sleep(30 * MS);
    match h.join_timeout(Duration::ZERO) {
        Ok(Ok(9)) => {}
        _ => return Err("thread terminada devia juntar com prazo zero"),
    }
    // Thread que morre por falta: o registro de morte volta em `Ok(Err)`.
    let h = thread::spawn(|| -> u32 { thread::exit_with(5) });
    match h.join_timeout(Duration::from_secs(20)) {
        Ok(Err(d)) if d.code == 5 => {}
        _ => return Err("saída com código devia voltar como Ok(Err(morte))"),
    }
    Ok(())
}
