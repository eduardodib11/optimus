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
];

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
