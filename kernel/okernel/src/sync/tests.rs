//! Testes de host do ticket spinlock (ADR 0031, verificação do T-314).

use super::*;
use std::cell::Cell;
use std::sync::{Arc, Mutex, Once};
use std::vec::Vec;

thread_local! {
    /// Pilha de travas desta thread de teste, ligada só por [`checked`].
    static HELD: &'static HeldLocks = Box::leak(Box::new(HeldLocks::new()));
    static CHECKING: Cell<bool> = const { Cell::new(false) };
}

fn host_held() -> Option<&'static HeldLocks> {
    CHECKING.with(Cell::get).then(|| HELD.with(|h| *h))
}

static HOST_HOOKS: Hooks = Hooks {
    held: host_held,
    relax: || {},
    interrupts_enabled: || false,
};

/// Liga a verificação de ordem nesta thread enquanto `f` roda (os outros
/// testes do processo seguem sem verificação).
fn checked<R>(f: impl FnOnce(&'static HeldLocks) -> R) -> R {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| install(&HOST_HOOKS));
    CHECKING.with(|c| c.set(true));
    let r = f(HELD.with(|h| *h));
    CHECKING.with(|c| c.set(false));
    r
}

#[test]
fn exclusao_mutua_em_um_milhao_de_operacoes() {
    let lock = Arc::new(SpinLock::with_class(LockClass::Object, (0u64, 0u64)));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let lock = Arc::clone(&lock);
            std::thread::spawn(move || {
                for _ in 0..250_000 {
                    let mut g = lock.lock();
                    // Dois campos que só ficam iguais se ninguém mais estiver
                    // dentro da seção crítica.
                    g.0 += 1;
                    assert_eq!(g.0, g.1 + 1);
                    g.1 += 1;
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(*lock.lock(), (1_000_000, 1_000_000));
}

#[test]
fn justica_fifo_pela_ordem_das_senhas() {
    const WAITERS: u32 = 6;
    let lock = Arc::new(SpinLock::with_class(LockClass::Object, Vec::new()));
    let guard = lock.lock();
    let mut threads = Vec::new();
    for id in 0..WAITERS {
        let l = Arc::clone(&lock);
        threads.push(std::thread::spawn(move || l.lock().push(id)));
        // Só cria a próxima depois que esta pegou a senha.
        while lock.queued() != id + 2 {
            std::thread::yield_now();
        }
    }
    drop(guard);
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(*lock.lock(), (0..WAITERS).collect::<Vec<_>>());
}

#[test]
fn try_lock_sob_disputa() {
    let lock = Arc::new(SpinLock::with_class(LockClass::Object, 0u64));
    let ok = Arc::new(Mutex::new(0u64));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let (lock, ok) = (Arc::clone(&lock), Arc::clone(&ok));
            std::thread::spawn(move || {
                for _ in 0..50_000 {
                    if let Some(mut g) = lock.try_lock() {
                        *g += 1;
                        *ok.lock().unwrap() += 1;
                    } else {
                        *lock.lock() += 1;
                        *ok.lock().unwrap() += 1;
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(*lock.lock(), *ok.lock().unwrap());
    assert_eq!(*lock.lock(), 200_000);
    let g = lock.lock();
    assert!(lock.try_lock().is_none());
    drop(g);
    assert!(lock.try_lock().is_some());
}

#[test]
fn contadores_perto_do_limite_de_32_bits() {
    let lock = SpinLock::with_class(LockClass::Object, 0u32);
    lock.next.store(u32::MAX - 2, Ordering::Relaxed);
    lock.serving.store(u32::MAX - 2, Ordering::Relaxed);
    for i in 1..=6 {
        *lock.lock() += 1;
        assert_eq!(lock.queued(), 0, "volta {i}");
    }
    assert_eq!(lock.serving.load(Ordering::Relaxed), 3);
    let g = lock.try_lock().expect("livre depois de dar a volta");
    assert!(lock.try_lock().is_none());
    drop(g);
    assert_eq!(*lock.lock(), 6);
}

#[test]
fn ordem_crescente_passa_e_a_pilha_esvazia() {
    let cdt = SpinLock::with_class(LockClass::Cdt, ());
    let obj = SpinLock::with_class(LockClass::Object, ());
    let q0 = SpinLock::with_key(LockClass::RunQueue, 0, ());
    let q3 = SpinLock::with_key(LockClass::RunQueue, 3, ());
    let frames = SpinLock::with_class(LockClass::Frames, ());
    checked(|held| {
        let v = held.catch_violation(|| {
            let _a = cdt.lock();
            let _b = obj.lock();
            let _c = q0.lock();
            let _d = q3.lock();
            assert_eq!(held.depth(), 4);
            let _e = frames.lock();
        });
        assert_eq!(v, None);
        assert_eq!(held.depth(), 0);
    });
}

#[test]
fn fila_antes_de_objeto_e_acusada() {
    let obj = SpinLock::with_class(LockClass::Object, ());
    let q = SpinLock::with_key(LockClass::RunQueue, 1, ());
    checked(|held| {
        let v = held.catch_violation(|| {
            let _q = q.lock();
            let _o = obj.lock();
        });
        assert_eq!(
            v,
            Some(Violation {
                held: (LockClass::RunQueue, 1),
                wanted: (LockClass::Object, 0),
            })
        );
        assert_eq!(held.depth(), 0);
    });
}

#[test]
fn duas_filas_fora_de_ordem_e_mesma_classe_sao_acusadas() {
    let q1 = SpinLock::with_key(LockClass::RunQueue, 1, ());
    let q2 = SpinLock::with_key(LockClass::RunQueue, 2, ());
    let a = SpinLock::with_class(LockClass::CapSpace, ());
    let b = SpinLock::with_class(LockClass::CapSpace, ());
    checked(|held| {
        let v = held.catch_violation(|| {
            let _x = q2.lock();
            let _y = q1.lock();
        });
        assert_eq!(v.map(|v| v.wanted), Some((LockClass::RunQueue, 1)));
        let v = held.catch_violation(|| {
            let _x = a.lock();
            let _y = b.lock();
        });
        assert_eq!(v.map(|v| v.held.0), Some(LockClass::CapSpace));
    });
}

#[test]
#[should_panic(expected = "ordem de travas violada: Alocador(frames)#0 antes de Alocador(heap)#0")]
fn violacao_sem_captura_e_panico() {
    let heap = SpinLock::with_class(LockClass::Heap, ());
    let frames = SpinLock::with_class(LockClass::Frames, ());
    checked(|_| {
        let _f = frames.lock();
        let _h = heap.lock();
    });
}

#[test]
fn guardas_soltas_fora_de_ordem_saem_da_pilha() {
    let a = SpinLock::with_class(LockClass::Cdt, ());
    let b = SpinLock::with_class(LockClass::Object, ());
    let c = SpinLock::with_class(LockClass::Diagnostic, ());
    checked(|held| {
        let ga = a.lock();
        let gb = b.lock();
        drop(ga);
        assert_eq!(held.depth(), 1);
        let gc = c.lock();
        drop(gb);
        drop(gc);
        assert_eq!(held.depth(), 0);
    });
}

#[test]
fn travas_sem_classe_ficam_fora_da_verificacao() {
    let u = SpinLock::new(());
    let q = SpinLock::with_key(LockClass::RunQueue, 0, ());
    let o = SpinLock::with_class(LockClass::Object, ());
    checked(|held| {
        let v = held.catch_violation(|| {
            let _q = q.lock();
            let _u = u.lock();
            assert_eq!(held.depth(), 1);
        });
        assert_eq!(v, None);
        let v = held.catch_violation(|| {
            let _u = u.lock();
            let _o = o.lock();
        });
        assert_eq!(v, None);
    });
}

#[test]
fn niveis_da_adr() {
    assert_eq!(LockClass::Cdt.level(), 1);
    assert_eq!(LockClass::RunQueue.level(), 6);
    assert_eq!(
        LockClass::KernelStacks.level(),
        LockClass::KernelPageTables.level()
    );
    assert_eq!(LockClass::Heap.level(), 9);
    assert_eq!(LockClass::Diagnostic.level(), 10);
    assert!(order_allows(
        (LockClass::KernelStacks, 0),
        (LockClass::KernelPageTables, 0)
    ));
    assert!(!order_allows(
        (LockClass::KernelPageTables, 0),
        (LockClass::KernelStacks, 0)
    ));
}
