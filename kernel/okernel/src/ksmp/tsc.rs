//! Teste de salto do TSC entre o BSP e cada AP na partida (ADR 0030, item
//! 5; T-321).
//!
//! O relógio de todas as CPUs é o TSC com a escala calibrada no BSP. Para
//! que duas leituras ordenadas por memória compartilhada nunca andem para
//! trás entre CPUs (o que `clock_get` promete), cada AP, antes de entrar na
//! máscara de ligadas, roda com o BSP [`ROUNDS`] rodadas em que cada lado,
//! sob uma trava, lê o próprio TSC e o compara com o último valor que o
//! outro publicou: um valor próprio menor é salto. Acima de
//! [`MAX_TSC_WARP_NS`] o AP corrige uma vez pelo `TSC_ADJUST` e mede de
//! novo; persistindo, fica fora.
//!
//! Os APs sobem um por vez, então um só par usa o estado daqui de cada vez.

use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

use kabi::MAX_CPUS;
use okernel::sync::{LockClass, SpinLock};
use okernel::time::{MAX_TSC_WARP_NS, Warp, WarpVerdict};

use crate::arch::x86_64::{cpu, cpustate};
use crate::ktime;

/// Rodadas de cada lado por medição.
pub const ROUNDS: u32 = 10_000;
/// Quanto o BSP espera o AP em cada passo do protocolo.
const TIMEOUT_NS: u64 = 2_000_000_000;

const NONE: u8 = 0;
const BSP: u8 = 1;
const AP: u8 = 2;

const CMD_RUN: u32 = 1;
const CMD_ACCEPT: u32 = 2;
const CMD_REJECT: u32 = 3;

/// Último TSC publicado e por qual lado.
struct Last {
    tsc: u64,
    side: u8,
}

/// Folha (ADR 0031, item 3): ninguém toma outra trava com esta na mão.
static LAST: SpinLock<Last> =
    SpinLock::with_class(LockClass::Diagnostic, Last { tsc: 0, side: NONE });
/// Comando do BSP ao AP; vale quando `GEN` muda.
static CMD: AtomicU32 = AtomicU32::new(0);
static GEN: AtomicU32 = AtomicU32::new(0);
/// Correção a somar ao `TSC_ADJUST` do AP antes de medir.
static ADJUST: AtomicI64 = AtomicI64::new(0);
/// Geração em que o AP ficou pronto para medir e em que terminou.
static AP_READY: AtomicU32 = AtomicU32::new(0);
static AP_DONE: AtomicU32 = AtomicU32::new(0);
/// Maior salto visto pelo AP (contagens).
static AP_BEHIND: AtomicU64 = AtomicU64::new(0);
/// Salto medido de cada CPU aceita, em ns (o BSP fica com zero).
static WARP_NS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Salto de TSC medido na partida da CPU `cpu`, em ns.
pub fn warp_ns(cpu: usize) -> u64 {
    WARP_NS.get(cpu).map_or(0, |w| w.load(Ordering::Relaxed))
}

/// [`ROUNDS`] rodadas do lado `side`; devolve o maior salto visto.
fn rounds(side: u8) -> u64 {
    let mut warp = 0;
    for _ in 0..ROUNDS {
        let mut last = LAST.lock();
        let now = cpu::rdtsc_ordered();
        if last.side != side && last.side != NONE && now < last.tsc {
            warp = warp.max(last.tsc - now);
        }
        *last = Last { tsc: now, side };
    }
    warp
}

/// Geração atual, lida pelo AP antes de se dar por ligado.
pub fn generation() -> u32 {
    GEN.load(Ordering::Acquire)
}

/// Lado do AP: atende os comandos do BSP a partir da geração `seen` até
/// ser aceito (`true`) ou recusado (`false`). Roda com IF=0, antes de a CPU
/// entrar na máscara de ligadas.
pub fn ap_side(mut seen: u32) -> bool {
    loop {
        while GEN.load(Ordering::Acquire) == seen {
            core::hint::spin_loop();
        }
        seen = GEN.load(Ordering::Acquire);
        match CMD.load(Ordering::Acquire) {
            CMD_RUN => {
                let adjust = ADJUST.load(Ordering::Relaxed);
                if adjust != 0 && cpustate::has_tsc_adjust() {
                    // SAFETY: a CPU tem `TSC_ADJUST` e ainda não está na
                    // máscara de ligadas: nada nela depende do relógio.
                    unsafe { cpustate::add_tsc_adjust(adjust) };
                }
                AP_READY.store(seen, Ordering::Release);
                AP_BEHIND.store(rounds(AP), Ordering::Relaxed);
                AP_DONE.store(seen, Ordering::Release);
            }
            CMD_ACCEPT => return true,
            _ => return false,
        }
    }
}

fn wait(flag: &AtomicU32, generation: u32) -> bool {
    let end = ktime::now_ns() + TIMEOUT_NS;
    while flag.load(Ordering::Acquire) != generation {
        if ktime::now_ns() > end {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

fn command(cmd: u32, adjust: i64) -> u32 {
    ADJUST.store(adjust, Ordering::Relaxed);
    CMD.store(cmd, Ordering::Relaxed);
    GEN.fetch_add(1, Ordering::AcqRel) + 1
}

/// Uma medição; `None` se o AP não respondeu.
fn measure(adjust: i64) -> Option<Warp> {
    *LAST.lock() = Last { tsc: 0, side: NONE };
    let generation = command(CMD_RUN, adjust);
    if !wait(&AP_READY, generation) {
        return None;
    }
    let ap_ahead = rounds(BSP);
    if !wait(&AP_DONE, generation) {
        return None;
    }
    Some(Warp {
        ap_behind: AP_BEHIND.load(Ordering::Relaxed),
        ap_ahead,
    })
}

/// Resultado do teste de salto de um AP.
pub enum Outcome {
    /// Aceito, com o salto final em ns e se precisou de correção.
    Accepted { ns: u64, adjusted: bool },
    /// Recusado pelo salto (ns, depois da correção se houve).
    Rejected { ns: u64 },
    /// O AP parou de responder no meio do protocolo.
    Silent,
}

/// Lado do BSP: mede o salto contra a CPU `cpu` (que já deu sinal e
/// espera em [`ap_side`]), corrige uma vez se preciso e diz ao AP se ele
/// entra.
pub fn bsp_side(cpu: usize) -> Outcome {
    let Some(scale) = ktime::tsc_scale() else {
        command(CMD_ACCEPT, 0);
        return Outcome::Accepted {
            ns: 0,
            adjusted: false,
        };
    };
    let mut adjust = 0;
    loop {
        let Some(warp) = measure(adjust) else {
            return Outcome::Silent;
        };
        let ns = warp.ns(scale);
        match warp.verdict(scale, adjust != 0, cpustate::has_tsc_adjust()) {
            WarpVerdict::Accept => {
                WARP_NS[cpu].store(ns, Ordering::Relaxed);
                command(CMD_ACCEPT, 0);
                return Outcome::Accepted {
                    ns,
                    adjusted: adjust != 0,
                };
            }
            WarpVerdict::Adjust(delta) => {
                info!("okernel: cpu{cpu}: salto de TSC de {ns} ns; corrigindo pelo TSC_ADJUST");
                adjust = delta;
            }
            WarpVerdict::Reject => {
                command(CMD_REJECT, 0);
                return Outcome::Rejected { ns };
            }
        }
    }
}

/// Avisa quando o TSC não se diz invariante (o TCG do QEMU): o teste de
/// salto decide sozinho.
pub fn warn_if_not_invariant() {
    let invariant =
        cpu::max_leaf(true) >= 0x8000_0007 && cpu::cpuid(0x8000_0007, 0).edx & (1 << 8) != 0;
    if !invariant {
        warn!(
            "okernel: TSC sem a marca de invariante; o teste de salto (até {MAX_TSC_WARP_NS} ns) decide sozinho"
        );
    }
}
