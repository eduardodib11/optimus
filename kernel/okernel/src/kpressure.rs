//! Pressão de memória como dois `Interrupt`s sintéticos (T-360; ADR 0038,
//! item 5).
//!
//! O alocador de frames ([`crate::kmem`]) só marca, com a trava dele na
//! mão, que o buddy mudou ([`touch`], um atômico). O recálculo dos níveis
//! (com os livres do buddy e dos caches por CPU) e a sinalização ficam para
//! um ponto sem travas, [`poll`]: a volta ao usuário e a espera ociosa. Cada nível é
//! uma linha de nível: afirmada, dispara e fica mascarada até `irq_ack`, e
//! um `ack` com ela ainda afirmada dispara de novo.
//!
//! O kernel cria as linhas ([`create`]); elas chegam ao `root` pela tabela
//! de handles de partida (ADR 0036, item 5; T-355), que as passa a quem tem
//! `kernel:mem-pressure` no manifesto.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, Ordering};

use kabi::Error;
use okernel::cap::MemoryQuota;
use okernel::mm::pressure::Pressure;
use okernel::notify::Interrupt;
use okernel::sync::{LockClass, SpinLock};

use crate::kthread;

mod tests;
pub use tests::TESTS;

static STATE: Pressure = Pressure::new();

/// O buddy mudou desde o último recálculo.
static DIRTY: AtomicBool = AtomicBool::new(true);

/// Os testes simulam os quadros livres: sem recálculo pelo buddy.
static FROZEN: AtomicBool = AtomicBool::new(false);

static LINES: SpinLock<[Option<Weak<Interrupt>>; 2]> =
    SpinLock::with_class(LockClass::Object, [None, None]);

/// Cria as linhas baixa e crítica (nessa ordem), cobradas de `quota`. Os
/// "vetores" 0 e 1 só as identificam: não há IRQ de hardware por trás.
///
/// # Errors
///
/// [`Error::Busy`] se as linhas já existem; [`Error::QuotaExceeded`] sem
/// cota.
pub fn create(quota: &Arc<MemoryQuota>) -> Result<[Arc<Interrupt>; 2], Error> {
    let mut lines = LINES.lock();
    if lines.iter().flatten().any(|w| w.strong_count() > 0) {
        return Err(Error::Busy);
    }
    let made = [
        Arc::new(Interrupt::new(quota, 0)?),
        Arc::new(Interrupt::new(quota, 1)?),
    ];
    *lines = made.each_ref().map(|i| Some(Arc::downgrade(i)));
    drop(lines);
    // O estado atual vale para as linhas novas.
    for (irq, asserted) in made.iter().zip(asserted()) {
        deliver(irq, asserted);
    }
    Ok(made)
}

/// O buddy mudou: [`poll`] recalcula os níveis.
pub fn touch() {
    DIRTY.store(true, Ordering::Relaxed);
}

/// Recalcula os níveis com `free` de `total` quadros livres.
pub fn note(free: usize, total: usize) {
    STATE.update(free, total);
}

/// Liga ou desliga o recálculo pelo buddy (testes); devolve o anterior.
pub fn freeze(on: bool) -> bool {
    FROZEN.swap(on, Ordering::AcqRel)
}

/// Os níveis baixo e crítico agora.
fn asserted() -> [bool; 2] {
    STATE.peek()
}

fn deliver(irq: &Interrupt, asserted: bool) {
    if let Some((ntfy, bits)) = irq.set_level(asserted)
        && let Some((thread, word)) = ntfy.signal(bits)
    {
        kthread::wake(thread, word);
    }
}

/// Ponto sem travas: recalcula os níveis se o buddy mudou e entrega às
/// linhas a mudança, se houver. Sem nada novo, custa duas leituras.
pub fn poll() {
    if DIRTY.load(Ordering::Relaxed)
        && !FROZEN.load(Ordering::Relaxed)
        && DIRTY.swap(false, Ordering::AcqRel)
    {
        let (free, total) = crate::kmem::frame_stats();
        note(free, total);
    }
    signal();
}

/// Entrega às linhas a mudança de nível, se houver.
pub fn signal() {
    let Some(levels) = STATE.take() else {
        return;
    };
    let lines = LINES.lock().clone();
    for (line, asserted) in lines.iter().zip(levels) {
        if let Some(irq) = line.as_ref().and_then(Weak::upgrade) {
            deliver(&irq, asserted);
        }
    }
}
