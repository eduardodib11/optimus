//! Testes de kernel da afinidade e do balanceamento (T-325; ADR 0032,
//! itens 4 e 7): a thread só começa a rodar nas CPUs da máscara do
//! `SchedContext` em que roda, trocar a máscara a leva para uma CPU nova e
//! a carga que começa toda numa CPU se espalha pelas outras.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use kabi::sched::CpuMask;
use kabi::vm::{PAGE_SIZE, WRITE};
use kabi::{Error, ObjectType, STATUS_OK};
use okernel::sched::Params;
use okernel::vm::vm_map;

use super::super::{UserEntry, affinity_misses, pulls, set_affinity, start_on};
use super::smp::{LIMIT, MS, gone, option, wait_for};
use super::{DATA_VA, Page, bare_thread, cap, delete, pin, process, settled, thread, user_symbol};
use crate::kcap::root_quota;
use crate::ksmp;
use crate::ktest::Outcome;
use crate::ktime;

unsafe extern "C" {
    static user_pingpong: u8;
    static user_where: u8;
    static user_spin_flag: u8;
}

/// Onde os testes mapeiam a página comum.
const SHARED_VA: u64 = 0x60_0000;
/// Jogadas de cada thread em [`presas_a_mascara`] sem `smp.mascara_voltas`.
const DEFAULT_ROUNDS: u64 = 2_000;
/// Threads por AP em [`carga_desigual_converge`].
const PER_CPU: usize = 3;

/// A máscara das CPUs `first..first + len`, dando a volta em `n`.
fn span(first: usize, len: usize, n: usize) -> CpuMask {
    (0..len).fold(CpuMask::NONE, |m, i| m.with((first + i) % n))
}

/// A primeira CPU de `mask` (as dos testes têm alguma).
fn first(mask: CpuMask) -> u32 {
    (0..kabi::MAX_CPUS)
        .find(|&c| mask.contains(c))
        .and_then(|c| u32::try_from(c).ok())
        .unwrap_or(0)
}

/// Aceite do T-325, "threads confinadas à máscara": `n` pares de threads,
/// em `n` CPUs, alternam a vez por futex; num par, cada uma tem metade das
/// CPUs, sem nenhuma em comum com a outra, e pares vizinhos dividem CPUs.
/// Toda passagem de vez acorda a outra numa CPU da máscara dela, o roubo do
/// ocioso e o balanço periódico disputam as prontas, e toda jogada tem de
/// acontecer numa CPU da máscara de quem joga.
pub fn presas_a_mascara() -> Outcome {
    let online = ksmp::start::online_count();
    if online < 2 {
        info!("ktest: · só uma CPU; nada a confinar");
        return Ok(());
    }
    let rounds = option("smp.mascara_voltas", DEFAULT_ROUNDS);
    let half = online / 2;
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    let (misses0, pulls0) = (affinity_misses(), pulls());
    let t0 = ktime::now_ns();
    {
        let mut pairs = Vec::new();
        for j in 0..online {
            let proc = process(2)?;
            let page = Page::new(&proc)?;
            ensure!(vm_map(&proc.aspace, &page.cap, SHARED_VA, 0, PAGE_SIZE, WRITE).is_ok());
            let masks = [span(j, half, online), span(j + half, half, online)];
            let mut threads = Vec::new();
            for (id, mask) in masks.into_iter().enumerate() {
                let (h, th) = thread(&proc)?;
                th.sched_context().ok_or("sem SchedContext")?.set_mask(mask);
                let entry = UserEntry {
                    rip: user_symbol(&raw const user_pingpong),
                    rsp: DATA_VA + (id as u64 + 1) * PAGE_SIZE,
                    args: [id as u64 | mask.0[0] << 8, rounds, SHARED_VA],
                };
                ensure!(start_on(&th, &entry, first(mask)).is_ok());
                threads.push((h, th));
            }
            pairs.push((proc, page, threads));
        }
        let limit = 60_000 * MS + rounds * online as u64 * 2_000_000;
        let done = wait_for(limit, || {
            pairs
                .iter()
                .all(|(_, _, ts)| ts.iter().all(|(_, t)| gone(t)))
        });
        let mut away = 0;
        for (j, (_, page, _)) in pairs.iter().enumerate() {
            let word = |i| page.word(i).load(Ordering::Relaxed);
            let (plays, out) = ([word(1), word(2)], [word(3), word(4)]);
            if plays != [rounds; 2] || out != [0; 2] {
                error!("ktest: · par {j}: jogadas {plays:?}, fora da máscara {out:?}");
            }
            ensure!(done && plays == [rounds; 2]);
            away += out[0] + out[1];
        }
        info!(
            "ktest: · {online} pares em {online} CPU(s), máscaras de {half} CPU(s): {} jogadas em {} ms, \
             {away} fora da máscara, {} roubos",
            2 * rounds * online as u64,
            (ktime::now_ns() - t0) / MS,
            pulls() - pulls0
        );
        ensure!(away == 0 && affinity_misses() == misses0);
        for (proc, page, threads) in pairs {
            let mut handles: Vec<_> = threads.iter().map(|(h, _)| *h).collect();
            handles.push(page.handle);
            drop(threads);
            delete(&proc, &handles)?;
        }
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Aceite do T-325 (ADR 0032, item 4): trocar a máscara de um
/// `SchedContext` em uso leva a thread que gira sem syscall para a CPU nova
/// (IPI de reescalonar na CPU que saiu da máscara); a própria thread troca a
/// máscara por `sched_configure` com `r8`, e a máscara sem CPU ligada é
/// recusada sem mudar nada. As CPUs são APs: o BSP roda o teste no ocioso
/// e uma thread que nunca bloqueia o tomaria.
pub fn mascara_nova_leva_a_thread() -> Outcome {
    let online = ksmp::start::online_count();
    if online < 3 {
        info!("ktest: · menos de dois APs; nada a trocar");
        return Ok(());
    }
    let (first_cpu, second, third) = (1u32, 2u32, if online > 3 { 3u32 } else { 1 });
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let proc = process(1)?;
        let (thread_h, th) = bare_thread(&proc)?;
        let sc_h = proc
            .cspace
            .lock()
            .obj_create(proc.quota, ObjectType::SchedContext, 0)
            .map_err(|_| "obj_create(SchedContext)")?;
        let sc = Arc::clone(
            cap(&proc.cspace, sc_h)?
                .object
                .as_sched_context()
                .map_err(|_| "tipo")?,
        );
        let params = Params::new(MS, MS, 100).map_err(|_| "params")?;
        sc.configure(params);
        th.bind_sched(Arc::clone(&sc)).map_err(|_| "bind")?;
        pin(&th, first_cpu)?;
        let page = Page::new(&proc)?;
        ensure!(vm_map(&proc.aspace, &page.cap, SHARED_VA, 0, PAGE_SIZE, WRITE).is_ok());
        let entry = UserEntry {
            rip: user_symbol(&raw const user_where),
            rsp: DATA_VA + PAGE_SIZE,
            args: [SHARED_VA, 0, 0],
        };
        ensure!(start_on(&th, &entry, first_cpu).is_ok());
        let word = |i: usize| page.word(i).load(Ordering::Acquire);
        let on = |cpu: u32| {
            let before = word(0);
            wait_for(LIMIT, || {
                word(1) == u64::from(cpu) && word(0) > before + 100
            })
        };
        let moved = on(first_cpu) && {
            set_affinity(&sc, CpuMask::only(second as usize));
            on(second)
        };
        // Depois de chegar, não volta: 100 ms de amostras, todas lá.
        let stays = moved && {
            let until = ktime::now_ns() + 100 * MS;
            let mut ok = true;
            while ktime::now_ns() < until && ok {
                ok = word(1) == u64::from(second);
            }
            ok && th.cpu() == second
        };
        // A própria thread pede a terceira CPU por `sched_configure`, e
        // depois uma máscara vazia, que fica recusada.
        let ask = |mask: CpuMask, at: usize| {
            for (i, bits) in mask.0.iter().enumerate() {
                page.word(at + i).store(*bits, Ordering::Relaxed);
            }
            page.word(4).store(u64::from(sc_h.raw()), Ordering::Relaxed);
            page.word(5).store(params.budget_ns, Ordering::Relaxed);
            page.word(6).store(params.period_ns, Ordering::Relaxed);
            page.word(7)
                .store(u64::from(params.priority), Ordering::Relaxed);
            page.word(8).store(u64::MAX, Ordering::Relaxed);
            page.word(3)
                .store(SHARED_VA + at as u64 * 8, Ordering::Release);
            wait_for(LIMIT, || word(3) == 0).then(|| word(8))
        };
        let asked = stays && ask(CpuMask::only(third as usize), 16) == Some(STATUS_OK) && on(third);
        let refused = asked && ask(CpuMask::NONE, 24) == Some(Error::InvalidArgument.to_raw());
        let kept = refused && on(third) && sc.mask() == CpuMask::only(third as usize);
        info!(
            "ktest: · cpu{first_cpu} → cpu{second} pela máscara nova (chegou: {moved}, ficou: \
             {stays}); → cpu{third} por sched_configure da própria thread: {asked}; máscara \
             vazia recusada: {refused}"
        );
        page.word(2).store(1, Ordering::Release);
        ensure!(wait_for(LIMIT, || gone(&th)));
        ensure!(kept);
        drop((th, sc));
        delete(&proc, &[thread_h, sc_h, page.handle])?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Aceite do T-325, "carga desigual em 4 CPUs converge (≤ 20% de desvio)":
/// [`PER_CPU`] threads por AP, que giram sem syscall, começam todas na
/// cpu1, com a máscara de todos os APs (o BSP roda o teste no ocioso).
/// Depois de 1 s, a média de threads em cada AP, amostrada por 2 s, fica a
/// até 20% de [`PER_CPU`].
pub fn carga_desigual_converge() -> Outcome {
    let online = ksmp::start::online_count();
    if online < 3 {
        info!("ktest: · menos de dois APs; nada a espalhar");
        return Ok(());
    }
    let aps = span(1, online - 1, online);
    let count = PER_CPU * (online - 1);
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    let pulls0 = pulls();
    {
        let proc = process(count as u64)?;
        let stop = Page::new(&proc)?;
        ensure!(vm_map(&proc.aspace, &stop.cap, SHARED_VA, 0, PAGE_SIZE, WRITE).is_ok());
        let mut threads = Vec::new();
        for i in 0..count {
            let (handle, th) = thread(&proc)?;
            th.sched_context().ok_or("sem SchedContext")?.set_mask(aps);
            let entry = UserEntry {
                rip: user_symbol(&raw const user_spin_flag),
                rsp: DATA_VA + (i as u64 + 1) * PAGE_SIZE,
                args: [SHARED_VA, 0, 0],
            };
            ensure!(start_on(&th, &entry, 1).is_ok());
            threads.push((handle, th));
        }
        let _ = wait_for(1_000 * MS, || false);
        let mut seen = [0u64; kabi::MAX_CPUS];
        let mut samples = 0u64;
        let until = ktime::now_ns() + 2_000 * MS;
        while ktime::now_ns() < until {
            for (_, th) in &threads {
                seen[th.cpu() as usize] += 1;
            }
            samples += 1;
            let _ = wait_for(2 * MS, || false);
        }
        stop.word(0).store(1, Ordering::Release);
        let ended = wait_for(LIMIT, || threads.iter().all(|(_, th)| gone(th)));
        // Média de threads por AP, em centésimos de `PER_CPU`.
        let share: Vec<u64> = (1..online)
            .map(|cpu| seen[cpu] * 100 / (samples.max(1) * PER_CPU as u64))
            .collect();
        info!(
            "ktest: · {count} threads começando na cpu1: média por AP {share:?}% de {PER_CPU} \
             em {samples} amostras, {} roubos, {} no BSP",
            pulls() - pulls0,
            seen[0]
        );
        ensure!(ended && seen[0] == 0);
        ensure!(share.iter().all(|s| (80..=120).contains(s)));
        let mut handles: Vec<_> = threads.iter().map(|(h, _)| *h).collect();
        handles.push(stop.handle);
        drop(threads);
        delete(&proc, &handles)?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}
