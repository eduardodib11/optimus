//! Testes de kernel da topologia, da partida, do relógio e dos IPIs entre
//! CPUs (T-316, T-318, T-319, T-321 e T-322).

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use okernel::time::{MAX_TSC_WARP_NS, NS_PER_SEC};

use crate::arch::x86_64::apic;
use crate::ktest::{Outcome, Test};
use crate::ktime;

/// Testes de kernel da topologia de CPUs.
pub const TESTS: &[Test] = &[
    Test {
        name: "smp.bsp_e_a_cpu_zero_da_topologia",
        run: bsp_e_a_cpu_zero,
    },
    Test {
        name: "smp.todas_as_cpus_ligadas",
        run: todas_ligadas,
    },
    Test {
        name: "smp.aps_ociosos_recebem_o_timer",
        run: aps_ociosos,
    },
    Test {
        name: "smp.salto_de_tsc_ate_1_us",
        run: salto_de_tsc,
    },
    Test {
        name: "smp.relogio_monotonico_entre_cpus",
        run: relogio_entre_cpus,
    },
    Test {
        name: "smp.funcao_remota_local_e_cpu_desligada",
        run: funcao_remota_local,
    },
    Test {
        name: "smp.resched_chega_a_todas_as_cpus",
        run: resched_chega,
    },
    Test {
        name: "smp.ipi_ida_e_volta_entre_todos_os_pares",
        run: ipi_todos_os_pares,
    },
];

static LOCAL: AtomicU64 = AtomicU64::new(0);

/// Na própria CPU, `call_on` chama direto; CPU fora da topologia, `false`.
fn funcao_remota_local() -> Outcome {
    let me = crate::arch::x86_64::percpu::cpu_id() as usize;
    ensure!(super::ipi::call_on(
        me,
        |v| LOCAL.store(v, Ordering::Relaxed),
        7
    ));
    ensure!(LOCAL.load(Ordering::Relaxed) == 7);
    ensure!(!super::ipi::call_on(super::count(), |_| {}, 0));
    ensure!(!super::ipi::call_on(kabi::MAX_CPUS, |_| {}, 0));
    Ok(())
}

/// Espera `done()` por até 100 ms, atendendo a própria caixa.
fn wait_polling(done: impl Fn() -> bool) -> bool {
    let end = ktime::now_ns() + 100_000_000;
    while !done() {
        if ktime::now_ns() > end {
            return false;
        }
        super::ipi::poll();
        core::hint::spin_loop();
    }
    true
}

/// O IPI de reescalonar liga `need_resched` em cada AP (ocioso, IF=1).
fn resched_chega() -> Outcome {
    for cpu in 1..super::start::online_count() {
        super::ipi::resched_pending(cpu, true);
        ensure!(super::ipi::resched(cpu));
        ensure!(wait_polling(|| super::ipi::resched_pending(cpu, false)));
        ensure!(super::ipi::resched_pending(cpu, true));
    }
    ensure!(!super::ipi::resched(super::count()));
    Ok(())
}

/// Linha `from` da matriz: bit `to` ligado quando `to` atendeu `from`.
static PAIRS: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
/// APs que terminaram de chamar todas as outras.
static PAIRS_DONE: AtomicUsize = AtomicUsize::new(0);

fn ping(from: u64) {
    let to = crate::arch::x86_64::percpu::cpu_id();
    if let Some(row) = usize::try_from(from).ok().and_then(|f| PAIRS.get(f)) {
        row.fetch_or(1 << to, Ordering::Relaxed);
    }
}

/// Esta CPU chama `ping` em todas as outras.
fn ping_all() -> bool {
    let me = crate::arch::x86_64::percpu::cpu_id();
    let n = super::start::online_count().min(64);
    (0..n)
        .filter(|&to| to != me as usize)
        .all(|to| super::ipi::call_on(to, ping, u64::from(me)))
}

fn ping_job() {
    if ping_all() {
        PAIRS_DONE.fetch_add(1, Ordering::AcqRel);
    }
}

/// Toda CPU manda função remota a toda outra, todas ao mesmo tempo (o BSP
/// pelo teste, os APs pelo trabalho do ocioso), e cada uma atende a sua
/// caixa enquanto espera: a matriz de pares fecha sem travar.
fn ipi_todos_os_pares() -> Outcome {
    let n = super::start::online_count().min(64);
    if n < 2 {
        info!("ktest: · só uma CPU; nada a comparar");
        return Ok(());
    }
    for row in &PAIRS {
        row.store(0, Ordering::Relaxed);
    }
    PAIRS_DONE.store(0, Ordering::Relaxed);
    // Ida e volta medida do BSP a cada AP, antes do teste cruzado.
    let mut worst = 0;
    let mut total = 0;
    for to in 1..n {
        let t0 = ktime::now_ns();
        ensure!(super::ipi::call_on(to, |_| {}, 0));
        let dt = ktime::now_ns() - t0;
        worst = worst.max(dt);
        total += dt;
    }
    super::start::post_ap_job(ping_job);
    ensure!(ping_all());
    let end = ktime::now_ns() + 2 * NS_PER_SEC;
    while PAIRS_DONE.load(Ordering::Acquire) < n - 1 {
        ensure!(ktime::now_ns() < end);
        super::ipi::poll();
        core::hint::spin_loop();
    }
    let all = (1u64 << n) - 1;
    for (from, row) in PAIRS.iter().enumerate().take(n) {
        let got = row.load(Ordering::Relaxed);
        ensure!(got == all & !(1 << from));
    }
    info!(
        "ktest: · {} pares; ida e volta BSP→AP média {} ns, pior {worst} ns",
        n * (n - 1),
        total / (n as u64 - 1)
    );
    Ok(())
}

/// Segundos de uma opção `nome=N` da linha de comando, ou `default`.
fn seconds(name: &str, default: u64) -> u64 {
    crate::bootinfo::get()
        .and_then(|i| i.cmdline())
        .and_then(|c| okernel::log::option(c, name))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Todo AP ligado passou no teste de salto da partida com até 1 µs.
fn salto_de_tsc() -> Outcome {
    for cpu in 1..super::count() {
        let ns = super::tsc::warp_ns(cpu);
        info!("ktest: · cpu{cpu}: salto de TSC de até {ns} ns na partida");
        ensure!(super::start::is_online(cpu));
        ensure!(ns <= MAX_TSC_WARP_NS);
    }
    Ok(())
}

/// Fim da rodada do teste de relógio (ns do relógio).
static CLOCK_END: AtomicU64 = AtomicU64::new(0);
/// Maior leitura publicada até agora, por qualquer CPU.
static CLOCK_LAST: AtomicU64 = AtomicU64::new(0);
/// Leituras que voltaram atrás e o maior recuo (ns).
static CLOCK_BACK: AtomicU64 = AtomicU64::new(0);
static CLOCK_WORST: AtomicU64 = AtomicU64::new(0);
static CLOCK_READS: AtomicU64 = AtomicU64::new(0);
/// APs que terminaram a rodada.
static CLOCK_DONE: AtomicUsize = AtomicUsize::new(0);

/// Até `CLOCK_END`: lê a maior leitura publicada, lê o relógio (que, pelo
/// `lfence`, vem depois) e exige que não seja menor; depois publica.
fn clock_round() -> u64 {
    let end = CLOCK_END.load(Ordering::Acquire);
    let mut reads = 0;
    loop {
        let seen = CLOCK_LAST.load(Ordering::Acquire);
        let now = ktime::now_ns();
        if now < seen {
            CLOCK_BACK.fetch_add(1, Ordering::Relaxed);
            CLOCK_WORST.fetch_max(seen - now, Ordering::Relaxed);
        }
        CLOCK_LAST.fetch_max(now, Ordering::AcqRel);
        reads += 1;
        if now >= end {
            return reads;
        }
    }
}

fn clock_job() {
    let reads = clock_round();
    CLOCK_READS.fetch_add(reads, Ordering::Relaxed);
    CLOCK_DONE.fetch_add(1, Ordering::AcqRel);
}

/// `clock_get` (`ktime::now_ns`) não volta atrás entre CPUs: todas leem e
/// publicam ao mesmo tempo por `smp.clock_s` segundos (10 por padrão, o
/// aceite do T-321).
fn relogio_entre_cpus() -> Outcome {
    let aps = super::start::online_count() - 1;
    if aps == 0 {
        info!("ktest: · só uma CPU; nada a comparar");
        return Ok(());
    }
    let secs = seconds("smp.clock_s", 10);
    for a in [&CLOCK_LAST, &CLOCK_BACK, &CLOCK_WORST, &CLOCK_READS] {
        a.store(0, Ordering::Relaxed);
    }
    CLOCK_DONE.store(0, Ordering::Relaxed);
    // Os APs pegam o trabalho no próximo disparo do timer (até 10 ms).
    let start = ktime::now_ns();
    CLOCK_END.store(start + secs * NS_PER_SEC, Ordering::Release);
    super::start::post_ap_job(clock_job);
    let mine = clock_round();
    while CLOCK_DONE.load(Ordering::Acquire) < aps {
        ensure!(ktime::now_ns() < start + (secs + 1) * NS_PER_SEC);
        core::hint::spin_loop();
    }
    let reads = CLOCK_READS.load(Ordering::Relaxed) + mine;
    let back = CLOCK_BACK.load(Ordering::Relaxed);
    info!(
        "ktest: · {} CPUs, {secs} s, {reads} leituras ({mine} no BSP), {back} recuos (pior {} ns)",
        aps + 1,
        CLOCK_WORST.load(Ordering::Relaxed)
    );
    ensure!(back == 0);
    ensure!(reads > mine);
    Ok(())
}

/// Os APs ficam ociosos com o timer ligado por `smp.idle_s` segundos (1 por
/// padrão; o aceite do T-319 pede 60) e seguem ligados, recebendo disparos.
fn aps_ociosos() -> Outcome {
    let secs = seconds("smp.idle_s", 1);
    let n = super::count();
    let fires = |cpu: usize| {
        super::start::percpu_of(cpu).map_or(0, |p| p.timer_stats()[0].load(Ordering::Acquire))
    };
    let before: [u64; 8] = core::array::from_fn(fires);
    let end = ktime::now_ns() + secs * NS_PER_SEC;
    while ktime::now_ns() < end {
        core::hint::spin_loop();
    }
    // Um disparo a cada 10 ms; no TCG, metade disso já basta.
    let want = secs * 1000 / 10 / 2;
    for (cpu, before) in before.iter().enumerate().take(n).skip(1) {
        let got = fires(cpu) - before;
        info!("ktest: · cpu{cpu}: {got} disparos do timer em {secs} s");
        ensure!(super::start::is_online(cpu));
        ensure!(got >= want);
    }
    Ok(())
}

fn todas_ligadas() -> Outcome {
    let n = super::count();
    let online = super::start::online_count();
    info!("ktest: · {online} de {n} CPU(s) ligadas");
    ensure!(online == n);
    for cpu in 0..n {
        ensure!(super::start::is_online(cpu));
    }
    ensure!(!super::start::is_online(n));
    Ok(())
}

fn bsp_e_a_cpu_zero() -> Outcome {
    let n = super::count();
    ensure!(n >= 1);
    ensure!(super::apic_id(0) == Some(apic::id_and_version().0));
    ensure!(super::apic_id(n).is_none());
    // Ids de APIC distintos.
    for i in 0..n {
        for j in i + 1..n {
            ensure!(super::apic_id(i) != super::apic_id(j));
        }
    }
    info!("ktest: · {n} CPU(s) na topologia");
    Ok(())
}
