//! Testes de kernel da ordem de travas (T-314): violações provocadas de
//! propósito são acusadas pela pilha da CPU.

use okernel::sync::{LockClass, SpinLock, Violation};

use crate::ktest::{Outcome, Test};

/// Testes de kernel das travas.
pub const TESTS: &[Test] = &[
    Test {
        name: "sync.ordem_crescente_nao_acusa",
        run: ordem_crescente,
    },
    Test {
        name: "sync.fila_antes_de_objeto_e_acusada",
        run: fila_antes_de_objeto,
    },
    Test {
        name: "sync.duas_filas_fora_de_ordem_sao_acusadas",
        run: filas_fora_de_ordem,
    },
];

static CDT: SpinLock<()> = SpinLock::with_class(LockClass::Cdt, ());
static OBJ: SpinLock<()> = SpinLock::with_class(LockClass::Object, ());
static Q0: SpinLock<()> = SpinLock::with_key(LockClass::RunQueue, 0, ());
static Q1: SpinLock<()> = SpinLock::with_key(LockClass::RunQueue, 1, ());
static DIAG: SpinLock<()> = SpinLock::with_class(LockClass::Diagnostic, ());

fn ordem_crescente() -> Outcome {
    let held = super::held_locks();
    let before = held.depth();
    let v = held.catch_violation(|| {
        let _c = CDT.lock();
        let _o = OBJ.lock();
        let _a = Q0.lock();
        let _b = Q1.lock();
        let _d = DIAG.lock();
    });
    ensure!(v.is_none());
    ensure!(held.depth() == before);
    Ok(())
}

fn fila_antes_de_objeto() -> Outcome {
    let held = super::held_locks();
    let v = held.catch_violation(|| {
        let _q = Q0.lock();
        let _o = OBJ.lock();
    });
    ensure!(
        v == Some(Violation {
            held: (LockClass::RunQueue, 0),
            wanted: (LockClass::Object, 0),
        })
    );
    if let Some(v) = v {
        info!("ktest: · acusada: {v}");
    }
    ensure!(held.depth() == 0);
    Ok(())
}

fn filas_fora_de_ordem() -> Outcome {
    let held = super::held_locks();
    let v = held.catch_violation(|| {
        let _b = Q1.lock();
        let _a = Q0.lock();
    });
    ensure!(v.is_some_and(
        |v| v.held == (LockClass::RunQueue, 1) && v.wanted == (LockClass::RunQueue, 0)
    ));
    if let Some(v) = v {
        info!("ktest: · acusada: {v}");
    }
    ensure!(held.depth() == 0);
    Ok(())
}
