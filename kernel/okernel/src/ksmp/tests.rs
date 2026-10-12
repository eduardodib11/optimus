//! Testes de kernel da topologia (T-316).

use crate::arch::x86_64::apic;
use crate::ktest::{Outcome, Test};

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
];

/// Os APs ficam ociosos com o timer ligado por `smp.idle_s` segundos (1 por
/// padrão; o aceite do T-319 pede 60) e seguem ligados, recebendo disparos.
fn aps_ociosos() -> Outcome {
    let secs = crate::bootinfo::get()
        .and_then(|i| i.cmdline())
        .and_then(|c| okernel::log::option(c, "smp.idle_s"))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1);
    let n = super::count();
    let fires = |cpu: usize| {
        super::start::percpu_of(cpu).map_or(0, |p| {
            p.timer_stats()[0].load(core::sync::atomic::Ordering::Acquire)
        })
    };
    let before: [u64; 8] = core::array::from_fn(fires);
    let end = crate::ktime::now_ns() + secs * okernel::time::NS_PER_SEC;
    while crate::ktime::now_ns() < end {
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
