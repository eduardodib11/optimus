//! Harness de testes de kernel no QEMU (T-111; SDD v1.0, seção 18).
//!
//! Com `test=kernel` na linha de comando, o kernel termina a inicialização,
//! roda cada [`Test`] registrado em [`SUITES`] e desliga o QEMU pelo
//! `isa-debug-exit`: sucesso (status 33) se todos passarem, falha (35) se
//! algum falhar. `ktest=prefixo` restringe aos testes cujo nome começa com o
//! prefixo. O `cargo xtask test kernel` confere as linhas `ktest:` da serial e
//! o código de saída.
//!
//! Um teste devolve `Err(mensagem)` para falhar; um pânico durante um teste
//! derruba o kernel com status de falha, o que o xtask também reporta.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::{QemuExit, qemu_exit};

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// O kernel está rodando os testes (`test=kernel`).
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Resultado de um teste: `Err` leva o local e a condição que falhou.
pub type Outcome = Result<(), &'static str>;

/// Um teste de kernel: nome único (`subsistema.o_que_verifica`) e função.
pub struct Test {
    /// Nome mostrado na serial.
    pub name: &'static str,
    /// Corpo do teste.
    pub run: fn() -> Outcome,
}

/// Falha o teste com local e condição se `cond` for falso.
macro_rules! ensure {
    ($cond:expr) => {
        if !$cond {
            return Err(concat!(file!(), ":", line!(), ": ", stringify!($cond)));
        }
    };
}

/// Suítes registradas, na ordem de execução.
const SUITES: &[&[Test]] = &[
    crate::bootinfo::TESTS,
    crate::arch::x86_64::TESTS,
    crate::kmem::TESTS,
    crate::kheap::TESTS,
    crate::ktime::TESTS,
    crate::kcap::TESTS,
    crate::kvm::TESTS,
    crate::kthread::TESTS,
];

/// Roda os testes selecionados e desliga o QEMU com o resultado.
pub fn run(filter: Option<&str>) -> ! {
    ACTIVE.store(true, Ordering::Relaxed);
    let selected = || {
        SUITES
            .iter()
            .flat_map(|suite| suite.iter())
            .filter(|t| filter.is_none_or(|prefix| t.name.starts_with(prefix)))
    };
    info!("ktest: início, {} testes", selected().count());
    let (mut passed, mut failed) = (0u32, 0u32);
    for test in selected() {
        match (test.run)() {
            Ok(()) => {
                passed += 1;
                info!("ktest: ok {}", test.name);
            }
            Err(why) => {
                failed += 1;
                error!("ktest: FALHOU {}: {why}", test.name);
            }
        }
    }
    crate::kheap::log_stats();
    info!("ktest: fim: {passed} ok, {failed} falharam");
    qemu_exit(if failed == 0 && passed > 0 {
        QemuExit::Success
    } else {
        QemuExit::Failure
    })
}
