//! IPIs entre CPUs (ADR 0031, item 5; T-322).
//!
//! Cada `PerCpu` tem uma caixa de pedidos (`okernel::ipi::Mailbox`). Quem
//! pede liga o bit na caixa do destino e manda o vetor do pedido; o destino
//! atende com [`poll`] no tratador do IPI e em toda espera ativa (volta de
//! trava, espera de outra CPU, entrada no ocioso), porque o kernel roda com
//! IF=0 e só recebe a interrupção no anel 3 ou no ocioso.
//!
//! - `RESCHED` (`0xF0`): liga `need_resched` do destino ([`resched`]); quem
//!   o consome é o escalonador por CPU (T-324).
//! - `CALL` (`0xF1`): função remota síncrona ([`call_on`]), restrita a
//!   funções que não tomam trava, não esperam e não mandam IPI.
//! - `TLB` (`0xF2`): reservado ao shootdown (T-326).

use okernel::ipi::{RESCHED, RemoteFn};

use crate::arch::x86_64::{apic, percpu};
use crate::ktime;

/// Prazo de [`call_on`] para o destino atender.
const CALL_TIMEOUT_NS: u64 = 100_000_000;

/// Atende a caixa desta CPU. Barato sem pedidos (uma carga); não toma
/// trava, então serve em qualquer espera.
pub fn poll() {
    percpu::mailbox().poll();
}

/// Pede à CPU `cpu` que reavalie quem roda. `false` se ela não está ligada.
pub fn resched(cpu: usize) -> bool {
    let Some(target) = super::start::percpu_of(cpu) else {
        return false;
    };
    target.mailbox().post(RESCHED);
    apic::send_ipi(target.apic_id(), apic::RESCHED_VECTOR);
    true
}

/// Roda `func(arg)` na CPU `cpu` e espera terminar, atendendo a própria
/// caixa enquanto isso (duas CPUs que pedem uma à outra não travam). Na
/// própria CPU, chama direto. `false` se `cpu` não está ligada.
///
/// `func` não toma trava, não espera e não manda IPI (ADR 0031, item 5).
///
/// # Panics
///
/// Se o destino não atender em 100 ms: ele está preso com IF=0 sem passar
/// por espera nenhuma, o que é bug do kernel.
pub fn call_on(cpu: usize, func: RemoteFn, arg: u64) -> bool {
    if cpu == percpu::cpu_id() as usize {
        func(arg);
        return true;
    }
    let Some(target) = super::start::percpu_of(cpu) else {
        return false;
    };
    let mailbox = target.mailbox();
    let deadline = ktime::now_ns() + CALL_TIMEOUT_NS;
    let waited = |what: &str| {
        poll();
        core::hint::spin_loop();
        assert!(
            ktime::now_ns() < deadline,
            "cpu{cpu} não atendeu a função remota ({what}) em 100 ms"
        );
    };
    while !mailbox.claim_call() {
        waited("pedido ocupado");
    }
    mailbox.post_call(func, arg);
    apic::send_ipi(target.apic_id(), apic::CALL_VECTOR);
    while !mailbox.call_done() {
        waited("sem resposta");
    }
    mailbox.release_call();
    true
}

/// Tratador dos vetores de IPI (`0xF0`–`0xF2`), com o EOI já feito.
pub fn on_ipi() {
    poll();
}

/// Há `RESCHED` pendente na CPU `cpu`; com `take`, consome.
pub fn resched_pending(cpu: usize, take: bool) -> bool {
    super::start::percpu_of(cpu).is_some_and(|p| {
        if take {
            p.mailbox().take_resched()
        } else {
            p.mailbox().resched_pending()
        }
    })
}
