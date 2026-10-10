//! Spinlock simples para o estado global do kernel (SDD v1.0, seção 6.9).
//!
//! Enquanto o kernel roda num núcleo só e nenhum tratador de interrupção toma
//! travas, um spinlock de teste-e-troca basta; o ticket spinlock com ordem
//! fixa e a versão que desliga interrupções vêm com o SMP.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// Trava de exclusão mútua por espera ativa.
pub struct SpinLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: o valor só é acessado por quem segura a trava (um por vez), então
// compartilhar a trava entre threads só exige que `T` possa mudar de thread.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Trava livre com `value`.
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Espera a trava ficar livre e a toma.
    pub fn lock(&self) -> SpinGuard<'_, T> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    /// Toma a trava se estiver livre; nunca espera (útil no pânico).
    pub fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinGuard { lock: self })
    }
}

/// Acesso exclusivo ao valor; solta a trava ao sair de escopo.
pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a guarda prova que esta é a única dona da trava.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: idem, e `&mut self` impede outro empréstimo pela guarda.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn exclusao_mutua_entre_threads() {
        let lock = Arc::new(SpinLock::new(0u64));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let lock = Arc::clone(&lock);
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        *lock.lock() += 1;
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(*lock.lock(), 40_000);
    }

    #[test]
    fn try_lock_nao_espera() {
        let lock = SpinLock::new(1);
        let guard = lock.lock();
        assert!(lock.try_lock().is_none());
        drop(guard);
        assert_eq!(lock.try_lock().map(|g| *g), Some(1));
    }
}
