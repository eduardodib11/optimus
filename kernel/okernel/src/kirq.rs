//! Linhas de IRQ como objetos `Interrupt` (T-209; SDD v1.0, seção 6.8).
//!
//! O kernel cria um `Interrupt` por vetor ([`create`]) e guarda uma
//! referência fraca dele na tabela de vetores; a capability vai para quem
//! recebe as capabilities iniciais. Um disparo do vetor ([`fire`], chamado
//! pela IDT) sinaliza o bit de notificação ligado por `obj_bind_notify` e
//! acorda quem espera; a linha fica mascarada até `irq_ack`.

use alloc::sync::{Arc, Weak};

use kabi::Error;
use okernel::cap::MemoryQuota;
use okernel::notify::Interrupt;
use okernel::sync::{LockClass, SpinLock};

use crate::arch::x86_64::apic::{SPURIOUS_VECTOR, TIMER_VECTOR};
use crate::kthread;

/// Primeiro vetor entregue a objetos `Interrupt` (abaixo ficam exceções,
/// o timer e reservas do kernel).
pub const FIRST_VECTOR: u8 = 0x30;

static LINES: SpinLock<[Option<Weak<Interrupt>>; 256]> =
    SpinLock::with_class(LockClass::Object, [const { None }; 256]);

/// Cria o `Interrupt` do vetor `vector`, cobrado de `quota`.
///
/// # Errors
///
/// [`Error::InvalidArgument`] para vetores do kernel; [`Error::Busy`] se
/// o vetor já tem objeto vivo; [`Error::QuotaExceeded`] sem cota.
pub fn create(quota: &Arc<MemoryQuota>, vector: u8) -> Result<Arc<Interrupt>, Error> {
    if vector < FIRST_VECTOR || vector == TIMER_VECTOR || vector == SPURIOUS_VECTOR {
        return Err(Error::InvalidArgument);
    }
    let mut lines = LINES.lock();
    let slot = &mut lines[usize::from(vector)];
    if slot.as_ref().is_some_and(|w| w.strong_count() > 0) {
        return Err(Error::Busy);
    }
    let irq = Arc::new(Interrupt::new(quota, vector)?);
    *slot = Some(Arc::downgrade(&irq));
    Ok(irq)
}

/// Disparo de `vector` vindo da IDT: devolve se o vetor é de um objeto
/// `Interrupt` vivo (quem chama faz o EOI e o ponto de preempção).
pub fn fire(vector: u64) -> bool {
    let irq = {
        let lines = LINES.lock();
        usize::try_from(vector)
            .ok()
            .and_then(|v| lines.get(v)?.as_ref()?.upgrade())
    };
    let Some(irq) = irq else {
        return false;
    };
    if let Some((ntfy, bits)) = irq.fire()
        && let Some((thread, word)) = ntfy.signal(bits)
    {
        kthread::wake(thread, word);
    }
    true
}
