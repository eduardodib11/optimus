//! Ganchos da verificação de travas no kernel (ADR 0031, itens 2 a 4).
//!
//! A biblioteca ([`okernel::sync`]) não sabe em que CPU roda: o kernel
//! instala aqui a pilha de travas da CPU, a leitura de RFLAGS.IF e o que
//! fazer a cada volta de espera. Enquanto só o BSP roda, a pilha é uma
//! estática; com o estado por CPU (T-317) ela passa para a `PerCpu`.

use okernel::sync::{HeldLocks, Hooks, install};

use crate::arch::x86_64::cpu;

pub mod tests;
pub use tests::TESTS;

/// Pilha de travas do BSP.
static BSP_HELD: HeldLocks = HeldLocks::new();

#[allow(
    clippy::unnecessary_wraps,
    reason = "assinatura de `Hooks::held`, que pode não ter pilha"
)]
fn held() -> Option<&'static HeldLocks> {
    Some(&BSP_HELD)
}

static HOOKS: Hooks = Hooks {
    held,
    // A caixa de IPIs vem com o T-322; por ora só há uma CPU.
    relax: || {},
    interrupts_enabled: cpu::interrupts_enabled,
};

/// Liga a verificação (no boot, antes da primeira trava).
pub fn init() {
    install(&HOOKS);
}

/// Pilha de travas da CPU atual.
pub fn held_locks() -> &'static HeldLocks {
    &BSP_HELD
}

/// Em debug, acusa pânico se esta CPU tem alguma trava na mão num ponto
/// em que não pode ter: troca de contexto, volta ao usuário e ocioso (ADR
/// 0031, item 4, regra 5).
#[track_caller]
pub fn assert_none_held(point: &str) {
    if cfg!(debug_assertions) {
        let n = BSP_HELD.depth();
        assert!(n == 0, "{n} trava(s) na mão em {point}");
    }
}
