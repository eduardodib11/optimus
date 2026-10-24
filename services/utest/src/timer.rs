//! Testes do objeto `Timer` (T-349; ADR 0035, item 6): disparo único e
//! periódico, desarme, rearme noutra CPU (e de várias ao mesmo tempo),
//! `Timer` destruído armado e mil timers de uma vez.

use alloc::vec::Vec;

use ostd::cap::{self, arm_timer, create, delete, disarm_timer, mint};
use ostd::kabi::sched::CpuMask;
use ostd::kabi::timer::{MIN_PERIOD_NS, RELATIVE};
use ostd::kabi::{Error, Handle, ObjectType, Rights, Syscall};
use ostd::sys::syscall;
use ostd::thread;
use ostd::time::now_ns;

use crate::{Ctx, Outcome, child_quota, quota_pages};

const MS: u64 = 1_000_000;
/// Folga para um disparo chegar ao usuário: sob TCG, com outras CPUs
/// emuladas na mesma máquina, uma vCPU pode ficar centenas de ms parada.
const SLACK: u64 = 2_000 * MS;

fn ntfy_wait(n: Handle) -> Result<u64, &'static str> {
    syscall(Syscall::NtfyWait, [u64::from(n.raw()), 0, 0, 0, 0, 0])
        .map(|[bits, ..]| bits)
        .map_err(|_| "ntfy_wait")
}

fn ntfy_poll(n: Handle) -> Result<u64, &'static str> {
    syscall(Syscall::NtfyPoll, [u64::from(n.raw()), 0, 0, 0, 0, 0])
        .map(|[bits, ..]| bits)
        .map_err(|_| "ntfy_poll")
}

/// Cede a vez por uns `ms` milissegundos.
fn settle(ms: u64) {
    let until = now_ns() + ms * MS;
    while now_ns() < until {
        thread::yield_now();
    }
}

/// Um `Timer` e uma notificação na cota `q`, apagados no fim.
struct Pair {
    timer: Handle,
    ntfy: Handle,
}

impl Pair {
    fn new(q: Handle) -> Result<Self, &'static str> {
        let ntfy = create(q, ObjectType::Notification, 0).map_err(|_| "create(ntfy)")?;
        let Ok(timer) = create(q, ObjectType::Timer, 0) else {
            let _ = delete(ntfy);
            return Err("create(Timer)");
        };
        Ok(Self { timer, ntfy })
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        let _ = (delete(self.timer), delete(self.ntfy));
    }
}

/// Disparo único relativo: chega depois do prazo, uma vez só; prazo
/// vencido sinaliza antes de a syscall voltar; a capability nasce só com
/// `BIND`; argumentos ruins e direitos faltando são recusados.
pub fn disparo_unico(ctx: &Ctx) -> Outcome {
    let p = Pair::new(ctx.quota)?;
    let info = cap::info(p.timer).map_err(|_| "cap_info")?;
    if info.object_type != ObjectType::Timer || info.rights != Rights::BIND {
        return Err("o Timer devia nascer só com BIND");
    }
    if create(ctx.quota, ObjectType::Timer, 1) != Err(Error::InvalidArgument) {
        return Err("obj_create(Timer, 1) devia dar InvalidArgument");
    }
    let t0 = now_ns();
    arm_timer(p.timer, p.ntfy, 0b100, 3 * MS, 0, RELATIVE).map_err(|_| "arm")?;
    let bits = ntfy_wait(p.ntfy)?;
    let took = now_ns() - t0;
    if bits != 0b100 {
        return Err("bits errados");
    }
    if !(3 * MS..=3 * MS + SLACK).contains(&took) {
        return Err("o disparo único veio fora do prazo");
    }
    settle(5);
    if ntfy_poll(p.ntfy)? != 0 {
        return Err("o disparo único repetiu");
    }
    // Prazo absoluto no passado: o bit já está lá na volta da syscall.
    arm_timer(p.timer, p.ntfy, 0b1, 1, 0, 0).map_err(|_| "arm vencido")?;
    if ntfy_poll(p.ntfy)? != 0b1 {
        return Err("prazo vencido devia sinalizar antes de voltar");
    }
    let refused = [
        (
            arm_timer(p.timer, p.ntfy, 1, MS, MIN_PERIOD_NS - 1, RELATIVE),
            "período abaixo do mínimo",
        ),
        (arm_timer(p.timer, p.ntfy, 1, MS, 0, 2), "flag desconhecida"),
        (
            disarm_timer(p.timer, p.ntfy).and(arm_timer(p.timer, p.ntfy, 1, MS, 1, 0)),
            "período 1 ns",
        ),
    ];
    for (r, why) in refused {
        if r != Err(Error::InvalidArgument) {
            return Err(why);
        }
    }
    let no_bind = mint(p.timer, Rights::NONE, 0, None).map_err(|_| "mint")?;
    let quiet = mint(p.ntfy, Rights::WAIT, 0, None).map_err(|_| "mint")?;
    let denied = (
        arm_timer(no_bind, p.ntfy, 1, MS, 0, RELATIVE),
        arm_timer(p.timer, quiet, 1, MS, 0, RELATIVE),
    );
    let _ = (delete(no_bind), delete(quiet));
    if denied != (Err(Error::AccessDenied), Err(Error::AccessDenied)) {
        return Err("sem BIND no Timer ou SIGNAL na notificação devia dar AccessDenied");
    }
    if arm_timer(p.ntfy, p.ntfy, 1, MS, 0, RELATIVE) != Err(Error::AccessDenied) {
        return Err("notificação não tem BIND");
    }
    Ok(())
}

/// Periódico de 1 ms: cinco disparos em pelo menos 4 ms; desarmado, para;
/// rearmado com prazo e ligação novos, dispara a nova.
pub fn periodico_e_desarme(ctx: &Ctx) -> Outcome {
    let p = Pair::new(ctx.quota)?;
    let t0 = now_ns();
    arm_timer(p.timer, p.ntfy, 1, MS, MS, RELATIVE).map_err(|_| "arm")?;
    for _ in 0..5 {
        if ntfy_wait(p.ntfy)? != 1 {
            return Err("bits errados");
        }
    }
    let took = now_ns() - t0;
    if took < 4 * MS {
        return Err("cinco disparos de 1 ms em menos de 4 ms");
    }
    disarm_timer(p.timer, p.ntfy).map_err(|_| "desarme")?;
    // Um disparo que já estava sendo entregue pode chegar logo depois.
    settle(2);
    let _ = ntfy_poll(p.ntfy)?;
    settle(5);
    if ntfy_poll(p.ntfy)? != 0 {
        return Err("disparou depois de desarmado");
    }
    // Rearme com outra notificação, no período mínimo, e desarme por
    // `bits = 0`.
    let other = create(ctx.quota, ObjectType::Notification, 0).map_err(|_| "create")?;
    let result = (|| {
        arm_timer(p.timer, other, 0b10, MIN_PERIOD_NS, MIN_PERIOD_NS, RELATIVE)
            .map_err(|_| "arm mínimo")?;
        for _ in 0..3 {
            if ntfy_wait(other)? != 0b10 {
                return Err("bits errados no rearme");
            }
        }
        arm_timer(p.timer, other, 0, 5 * MS, MS, RELATIVE).map_err(|_| "bits = 0")?;
        settle(2);
        let _ = ntfy_poll(other)?;
        settle(3);
        if ntfy_poll(other)? != 0 || ntfy_poll(p.ntfy)? != 0 {
            return Err("bits = 0 devia desarmar");
        }
        Ok(())
    })();
    let _ = delete(other);
    result
}

/// CPU para fixar as threads `k` (a 0 e outra, se houver).
fn cpu_of(k: usize) -> usize {
    let online = thread::cpus().map_or(1, |(online, _)| usize::try_from(online).unwrap_or(1));
    k % online.max(1)
}

/// Arma `timer` numa thread presa à CPU `cpu`.
fn arm_on(cpu: usize, timer: Handle, ntfy: Handle, bits: u64, rel: u64) -> Outcome {
    let h = thread::Builder::new()
        .affinity(CpuMask::only(cpu))
        .spawn(move || arm_timer(timer, ntfy, bits, rel, 0, RELATIVE).is_ok())
        .map_err(|_| "spawn")?;
    if h.join() == Ok(true) {
        Ok(())
    } else {
        Err("arm na outra CPU falhou")
    }
}

/// Armado numa CPU para daqui a 200 ms e rearmado de outra para 2 ms: só
/// o rearme dispara (o `Timer` saiu da fila da primeira). Depois, threads
/// em até quatro CPUs rearmam o mesmo `Timer` ao mesmo tempo, empurrando o
/// prazo, e ele dispara uma vez, com os bits de uma delas.
pub fn rearme_noutra_cpu(ctx: &Ctx) -> Outcome {
    let p = Pair::new(ctx.quota)?;
    arm_on(cpu_of(0), p.timer, p.ntfy, 0b01, 200 * MS)?;
    let t0 = now_ns();
    arm_on(cpu_of(1), p.timer, p.ntfy, 0b10, 2 * MS)?;
    if ntfy_wait(p.ntfy)? != 0b10 {
        return Err("devia chegar só o rearme");
    }
    if now_ns() - t0 > SLACK {
        return Err("o rearme demorou demais");
    }
    settle(250);
    if ntfy_poll(p.ntfy)? != 0 {
        return Err("o arme antigo disparou na CPU antiga");
    }
    let online = thread::cpus().map_or(1, |(online, _)| usize::try_from(online).unwrap_or(1));
    let (timer, ntfy) = (p.timer, p.ntfy);
    let mut hs = Vec::new();
    for k in 0..online.clamp(2, 4) {
        hs.push(
            thread::Builder::new()
                .affinity(CpuMask::only(cpu_of(k)))
                .spawn(move || {
                    (0..200).all(|_| arm_timer(timer, ntfy, 1 << k, 300 * MS, 0, RELATIVE).is_ok())
                })
                .map_err(|_| "spawn")?,
        );
    }
    for h in hs {
        if h.join() != Ok(true) {
            return Err("rearme concorrente falhou");
        }
    }
    let bits = ntfy_wait(p.ntfy)?;
    if bits.count_ones() != 1 || bits >= 1 << 4 {
        return Err("o rearme concorrente devia disparar uma vez, com os bits de uma thread");
    }
    settle(10);
    if ntfy_poll(p.ntfy)? != 0 {
        return Err("o rearme concorrente disparou mais de uma vez");
    }
    Ok(())
}

/// `Timer`s armados (periódico no mínimo e único longe) destruídos com
/// `cap_delete`: param de sinalizar e a cota volta inteira.
pub fn destruido_armado(ctx: &Ctx) -> Outcome {
    let q = child_quota(ctx, 1 << 20)?;
    let before = quota_pages(q)?;
    let result = (|| {
        let n = create(ctx.quota, ObjectType::Notification, 0).map_err(|_| "create")?;
        let inner = (|| {
            let fast = create(q, ObjectType::Timer, 0).map_err(|_| "create(Timer)")?;
            let slow = create(q, ObjectType::Timer, 0).map_err(|_| "create(Timer)")?;
            arm_timer(fast, n, 1, MIN_PERIOD_NS, MIN_PERIOD_NS, RELATIVE).map_err(|_| "arm")?;
            arm_timer(slow, n, 2, 10_000 * MS, 0, RELATIVE).map_err(|_| "arm")?;
            if ntfy_wait(n)? != 1 {
                return Err("o periódico não disparou");
            }
            delete(fast).map_err(|_| "delete")?;
            delete(slow).map_err(|_| "delete")?;
            settle(2);
            let _ = ntfy_poll(n)?;
            settle(5);
            if ntfy_poll(n)? != 0 {
                return Err("Timer apagado seguiu disparando");
            }
            Ok(())
        })();
        let _ = delete(n);
        inner
    })();
    let back = quota_pages(q);
    let _ = delete(q);
    result?;
    if back? != before {
        return Err("a cota não voltou depois de apagar os Timers armados");
    }
    Ok(())
}

/// Mil `Timer`s (o aceite da T-349 fala em 1000) armados de uma vez, com
/// prazos embaralhados ao longo de 30 ms em 16 notificações: todos chegam,
/// uma vez cada, o último depois do maior prazo, e a cota volta depois de
/// apagá-los.
pub fn mil_timers(ctx: &Ctx) -> Outcome {
    const N: u64 = 1000;
    let q = child_quota(ctx, 2 << 20)?;
    let before = quota_pages(q)?;
    let mut handles = Vec::new();
    let result = (|| {
        let ns = (0..16)
            .map(|_| create(q, ObjectType::Notification, 0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "create(ntfy)")?;
        handles.extend_from_slice(&ns);
        let mut want = [0u64; 16];
        let t0 = now_ns();
        let base = t0 + 50 * MS;
        let mut last = 0;
        for i in 0..N {
            let t = create(q, ObjectType::Timer, 0).map_err(|_| "create(Timer)")?;
            handles.push(t);
            let k = (i % 16) as usize;
            let bit = 1 << (i / 16);
            want[k] |= bit;
            let at = base + (i * 7919 % N) * 30_000;
            last = last.max(at);
            arm_timer(t, ns[k], bit, at, 0, 0).map_err(|_| "arm")?;
        }
        for (k, &n) in ns.iter().enumerate() {
            let mut got = 0;
            while got != want[k] {
                got |= ntfy_wait(n)?;
                if got & !want[k] != 0 {
                    return Err("bit a mais");
                }
            }
        }
        let end = now_ns();
        if end < last {
            return Err("os Timers chegaram antes do maior prazo");
        }
        if end > last + SLACK {
            return Err("os mil Timers demoraram demais");
        }
        Ok(())
    })();
    for h in handles {
        let _ = delete(h);
    }
    let back = quota_pages(q);
    let _ = delete(q);
    result?;
    if back? != before {
        return Err("a cota não voltou depois de apagar os mil Timers");
    }
    Ok(())
}
