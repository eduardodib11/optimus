//! Entropia do kernel (T-337; ADR 0039, item 4): o DRBG principal, um por
//! CPU e a mistura de hardware.
//!
//! No boot, [`init`] tira o DRBG principal da semente do `optboot`
//! (`BootInfo.rng_seed`) e apaga a semente da `BootInfo`; o BSP ganha o
//! filho 0 na hora e cada AP ganha o seu na partida ([`fork_for`], ainda no
//! BSP, antes de o AP rodar). Ligados os APs, [`seal`] apaga o principal:
//! dali em diante só existem os DRBGs por CPU, cada um na `PerCpu` da sua
//! CPU e tocado só por ela, com IF=0 e sem trava (como os caches por CPU,
//! ADR 0031, item 3).
//!
//! Cada pedido ([`fill`]) mistura o TSC e uma palavra de `RDSEED` (ou, se
//! ela falhar ou não existir, de `RDRAND`) quando a CPU os tiver. Semente
//! toda zero (o `optboot` não achou fonte) deixa o kernel sem DRBG, e a
//! `sys_info` de entropia devolve `NotSupported`.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use kabi::Error;
use kabi::boot::RNG_SEED_LEN;
use okernel::rand::Drbg;

use crate::arch::x86_64::{cpu, percpu};
use crate::ktest::{Outcome, Test};

/// O principal ainda não existe (ou a semente era zero).
const MAIN_ABSENT: u8 = 0;
/// O principal está em [`MAIN_KEY`].
const MAIN_READY: u8 = 1;
/// O principal foi apagado ([`seal`]).
const MAIN_SEALED: u8 = 2;

static MAIN_STATE: AtomicU8 = AtomicU8::new(MAIN_ABSENT);
/// Chave do DRBG principal. Só o BSP a toca, no boot (até [`seal`]).
static MAIN_KEY: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// A CPU tem `RDRAND`.
const HW_RDRAND: u8 = 1;
/// A CPU tem `RDSEED`.
const HW_RDSEED: u8 = 2;
/// Fontes de hardware achadas no boot (as CPUs são iguais).
static HW: AtomicU8 = AtomicU8::new(0);
/// Tentativas de `RDRAND` antes de desistir (a Intel recomenda 10).
const RDRAND_TRIES: u32 = 10;

/// Semeia o DRBG principal com `seed` e apaga a semente; o BSP ganha o
/// seu DRBG. No boot do BSP, uma vez, depois de a `PerCpu` dele existir.
pub fn init(seed: &mut [u8; RNG_SEED_LEN]) {
    let mut hw = 0;
    if cpu::has_rdrand() {
        hw |= HW_RDRAND;
    }
    if cpu::has_rdseed() {
        hw |= HW_RDSEED;
    }
    HW.store(hw, Ordering::Relaxed);
    let main = Drbg::from_seed(seed);
    // A semente fica na `BootInfo` para sempre: apagada, um vazamento
    // posterior da memória do kernel não refaz a chave inicial.
    seed.fill(0);
    core::hint::black_box(&mut *seed);
    let Some(mut main) = main else {
        warn!(
            "okernel: AVISO: semente de entropia do optboot zerada; sem DRBG (sys_info de entropia devolve NotSupported)"
        );
        return;
    };
    let bsp = main.fork(0, &mix());
    percpu::with_drbg(|d| *d = Some(bsp));
    store_main(main.into_key());
    MAIN_STATE.store(MAIN_READY, Ordering::Release);
    info!(
        "okernel: DRBG semeado pelo optboot; mistura: TSC{}{}",
        if hw & HW_RDSEED != 0 { " + RDSEED" } else { "" },
        if hw & HW_RDRAND != 0 { " + RDRAND" } else { "" },
    );
}

/// DRBG novo para a CPU `cpu`, tirado do principal. Só no BSP, no boot
/// (partida dos APs); `None` sem principal (semente zero ou já selado).
pub fn fork_for(cpu: u32) -> Option<Drbg> {
    debug_assert_eq!(percpu::cpu_id(), 0, "fork_for fora do BSP");
    if MAIN_STATE.load(Ordering::Acquire) != MAIN_READY {
        return None;
    }
    let mut main = Drbg::from_key(load_main());
    let child = main.fork(cpu, &mix());
    store_main(main.into_key());
    Some(child)
}

/// Apaga o DRBG principal (depois da partida dos APs).
pub fn seal() {
    store_main([0; 32]);
    MAIN_STATE.store(MAIN_SEALED, Ordering::Release);
}

/// Enche `out` com bytes do DRBG desta CPU, com a mistura de hardware.
///
/// # Errors
///
/// `NotSupported` se esta CPU não tem DRBG (semente zero no boot).
pub fn fill(out: &mut [u8]) -> Result<(), Error> {
    let extra = mix();
    percpu::with_drbg(|d| match d {
        Some(d) => {
            d.fill(&extra, out);
            Ok(())
        }
        None => Err(Error::NotSupported),
    })
}

/// Mistura de um pedido: o TSC e uma palavra de hardware (zero sem ela).
fn mix() -> [u8; 16] {
    let mut out = [0; 16];
    out[..8].copy_from_slice(&cpu::rdtsc().to_le_bytes());
    out[8..].copy_from_slice(&hw_word().unwrap_or(0).to_le_bytes());
    out
}

/// Uma palavra de `RDSEED` (uma tentativa) ou de `RDRAND` (até
/// [`RDRAND_TRIES`]), as que a CPU tiver.
fn hw_word() -> Option<u64> {
    let hw = HW.load(Ordering::Relaxed);
    if hw & HW_RDSEED != 0
        && let Some(w) = cpu::rdseed()
    {
        return Some(w);
    }
    if hw & HW_RDRAND != 0 {
        return (0..RDRAND_TRIES).find_map(|_| cpu::rdrand());
    }
    None
}

fn load_main() -> [u8; 32] {
    let mut key = [0; 32];
    for (chunk, w) in key.chunks_exact_mut(8).zip(&MAIN_KEY) {
        chunk.copy_from_slice(&w.load(Ordering::Relaxed).to_le_bytes());
    }
    key
}

fn store_main(key: [u8; 32]) {
    for (chunk, w) in key.chunks_exact(8).zip(&MAIN_KEY) {
        let mut word = [0; 8];
        word.copy_from_slice(chunk);
        w.store(u64::from_le_bytes(word), Ordering::Relaxed);
    }
}

/// Testes de kernel da entropia.
pub const TESTS: &[Test] = &[
    Test {
        name: "rand.semente_apagada",
        run: semente_apagada,
    },
    Test {
        name: "rand.sys_info_entropia",
        run: sys_info_entropia,
    },
    Test {
        name: "rand.um_drbg_por_cpu",
        run: um_drbg_por_cpu,
    },
];

/// A semente sumiu da `BootInfo` e o principal foi apagado depois da
/// partida dos APs; o QEMU dos testes sempre tem fonte (`virtio-rng`), então
/// o BSP tem DRBG.
fn semente_apagada() -> Outcome {
    let info = crate::bootinfo::get().ok_or("sem BootInfo")?;
    ensure!(info.rng_seed.iter().all(|&b| b == 0));
    ensure!(MAIN_STATE.load(Ordering::Acquire) == MAIN_SEALED);
    ensure!(MAIN_KEY.iter().all(|w| w.load(Ordering::Relaxed) == 0));
    ensure!(fork_for(1).is_none());
    ensure!(percpu::with_drbg(|d| d.is_some()));
    Ok(())
}

/// `sys_info(5, 0)` devolve três palavras que mudam a cada chamada;
/// argumento diferente de zero é `InvalidArgument`.
fn sys_info_entropia() -> Outcome {
    use kabi::sched::SYS_INFO_ENTROPY;
    let a = crate::kthread::sys_info(SYS_INFO_ENTROPY, 0).map_err(|_| "sys_info(5) falhou")?;
    let b = crate::kthread::sys_info(SYS_INFO_ENTROPY, 0).map_err(|_| "sys_info(5) falhou")?;
    ensure!(a != b);
    ensure!(a != [0; 3] && b != [0; 3]);
    ensure!(crate::kthread::sys_info(SYS_INFO_ENTROPY, 1) == Err(Error::InvalidArgument));
    ensure!(crate::kthread::sys_info(SYS_INFO_ENTROPY, u64::MAX) == Err(Error::InvalidArgument));
    let mut buf = [0u8; 200];
    fill(&mut buf).map_err(|_| "fill falhou")?;
    ensure!(buf.chunks(8).all(|c| c.iter().any(|&b| b != 0)));
    Ok(())
}

/// Primeira palavra tirada por cada CPU em [`um_drbg_por_cpu`] (zero: sem
/// DRBG).
static PER_CPU: [AtomicU64; kabi::MAX_CPUS] = [const { AtomicU64::new(0) }; kabi::MAX_CPUS];

/// Cada CPU ligada tem o seu DRBG, e os fluxos diferem entre CPUs.
fn um_drbg_por_cpu() -> Outcome {
    fn sample(_: u64) {
        let mut w = [0u8; 8];
        let v = if fill(&mut w).is_ok() {
            u64::from_le_bytes(w).max(1)
        } else {
            0
        };
        PER_CPU[percpu::cpu_id() as usize].store(v, Ordering::Relaxed);
    }
    let cpus: alloc::vec::Vec<usize> = (0..crate::ksmp::count().max(1))
        .filter(|&c| crate::ksmp::ipi::call_on(c, sample, 0))
        .collect();
    ensure!(cpus.len() == crate::ksmp::start::online_count().max(1));
    let mut seen: alloc::vec::Vec<u64> = cpus
        .iter()
        .map(|&c| PER_CPU[c].load(Ordering::Relaxed))
        .collect();
    ensure!(seen.iter().all(|&v| v != 0));
    seen.sort_unstable();
    seen.dedup();
    ensure!(seen.len() == cpus.len());
    Ok(())
}
