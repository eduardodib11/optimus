//! Objetos do kernel e capabilities no kernel (T-202 em diante).
//!
//! A lógica é a de `okernel::cap`, portável; aqui ficam a cota raiz, tirada
//! do limite do heap, e os testes de kernel. Syscalls chegam com as threads
//! (T-205 em diante) e usam estas APIs internas.

use alloc::sync::Arc;

use okernel::cap::MemoryQuota;
use okernel::sync::SpinLock;

use crate::kheap;

mod tests;
pub use tests::TESTS;

/// Fração do heap reservada ao próprio kernel, fora da cota raiz (1/8).
const KERNEL_RESERVE_SHIFT: u32 = 3;

static ROOT: SpinLock<Option<Arc<MemoryQuota>>> = SpinLock::new(None);

/// Cria a cota raiz com o heap livre menos a reserva do kernel. Chamar
/// depois de `kheap::init`.
pub fn init() {
    let (limit, used) = kheap::usage();
    let free = limit.saturating_sub(used);
    let bytes = free - (free >> KERNEL_RESERVE_SHIFT);
    *ROOT.lock() = Some(MemoryQuota::root(bytes));
    info!("okernel: cota raiz de {} KiB", bytes >> 10);
}

/// A cota raiz, de onde o `root` recebe toda a memória de objetos.
pub fn root_quota() -> Option<Arc<MemoryQuota>> {
    ROOT.lock().clone()
}
