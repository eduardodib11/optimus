//! Testes de kernel do relógio e do timer (T-109).
//!
//! O aceite do SDD (desvio ≤ 0,1% contra o HPET em 10 s) foi reduzido para
//! uma janela de `ktime_s=` segundos (padrão 1) para caber no CI sem KVM.
//! O limite é 0,1% (1000 ppm) com KVM ou hardware real. No TCG do QEMU o TSC
//! segue o relógio do host e o HPET o relógio virtual, e cada leitura do HPET
//! é uma saída para o emulador; o limite lá é [`TCG_LIMIT_PPM`] (1%).

use okernel::log::option;
use okernel::time::{NS_PER_SEC, deviation_ppm};

use super::{hpet_ns_since, now_ns, set_timer_at, tsc_hz};
use crate::arch::x86_64::{apic, cpu, hpet};
use crate::bootinfo;
use crate::ktest::{Outcome, Test};

/// Desvio aceito no TCG, em ppm.
pub const TCG_LIMIT_PPM: u64 = 10_000;
/// Desvio aceito com KVM ou em hardware real, em ppm (0,1%, SDD T-109).
pub const LIMIT_PPM: u64 = 1_000;

/// Testes de kernel do relógio.
pub const TESTS: &[Test] = &[
    Test {
        name: "time.apic_ligado",
        run: apic_ligado,
    },
    Test {
        name: "time.relogio_monotonico",
        run: monotonico,
    },
    Test {
        name: "time.desvio_contra_o_hpet",
        run: desvio,
    },
    Test {
        name: "time.timer_dispara_no_prazo",
        run: timer,
    },
];

fn apic_ligado() -> Outcome {
    let x2 = cpu::cpuid(1, 0).ecx & (1 << 21) != 0;
    let expected = if x2 {
        apic::Mode::X2Apic
    } else {
        apic::Mode::XApic
    };
    ensure!(apic::mode() == expected);
    let (_, version) = apic::id_and_version();
    // Versões de APIC integrado vão de 0x10 a 0x15.
    ensure!((0x10..=0x15).contains(&(version & 0xff)));
    Ok(())
}

fn monotonico() -> Outcome {
    ensure!(tsc_hz() > 0);
    let mut last = now_ns();
    ensure!(last > 0);
    for _ in 0..100_000 {
        let now = now_ns();
        ensure!(now >= last);
        last = now;
    }
    Ok(())
}

fn under_tcg() -> bool {
    cpu::hypervisor().is_some_and(|sig| &sig == b"TCGTCGTCGTCG")
}

fn desvio() -> Outcome {
    let seconds = bootinfo::get()
        .and_then(|i| option(i.cmdline()?, "ktime_s")?.parse::<u64>().ok())
        .unwrap_or(1)
        .clamp(1, 60);
    let (h0, n0) = (hpet::counter(), now_ns());
    while hpet_ns_since(h0) < seconds * NS_PER_SEC {
        core::hint::spin_loop();
    }
    let (reference, measured) = (hpet_ns_since(h0), now_ns() - n0);
    let ppm = deviation_ppm(measured, reference);
    let limit = if under_tcg() {
        TCG_LIMIT_PPM
    } else {
        LIMIT_PPM
    };
    info!("ktest: · desvio de {ppm} ppm contra o HPET em {seconds} s (limite {limit} ppm)");
    ensure!(ppm <= limit);
    Ok(())
}

fn timer() -> Outcome {
    let (before, _) = apic::timer_fires();
    let deadline = now_ns() + 5_000_000;
    set_timer_at(deadline);
    let give_up = deadline + NS_PER_SEC;
    while apic::timer_fires().0 == before && now_ns() < give_up {
        cpu::wait_for_interrupt();
    }
    let (after, tsc) = apic::timer_fires();
    ensure!(after == before + 1);
    let fired = super::clock().ok_or("sem relógio")?.ns(tsc);
    let late = fired.saturating_sub(deadline);
    info!(
        "ktest: · timer disparou {late} ns depois do prazo ({})",
        if apic::tsc_deadline() {
            "TSC-deadline"
        } else {
            "one-shot"
        }
    );
    // TSC-deadline nunca dispara cedo; o one-shot pode errar pela calibragem.
    let early_ok = if apic::tsc_deadline() { 0 } else { 100_000 };
    ensure!(fired + early_ok >= deadline);
    ensure!(late < 50_000_000);
    ensure!(apic::unexpected() == 0);
    Ok(())
}
