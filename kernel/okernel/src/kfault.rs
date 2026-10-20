//! Faltas e exceções de usuário no kernel (T-210; SDD v1.0, seção 6.4).
//!
//! Uma exceção vinda do anel 3 vira um `ipc_call` ao endpoint de exceções
//! da thread (`okernel::fault`), feito na pilha de kernel dela: a thread
//! espera a resposta ali mesmo, como numa syscall, e volta à instrução que
//! faltou. Se não houver quem atenda, a thread é encerrada e a falta vai
//! para o registro do kernel.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use okernel::fault::{self, Fault, Kill};
use okernel::sync::{LockClass, SpinLock};

use crate::arch::x86_64::idt::{TrapFrame, exception_name};
use crate::kthread::{self, KernelEnv};

mod tests;
pub use tests::TESTS;

/// Uma thread encerrada por falta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// Endereço do objeto `Thread`.
    pub thread: usize,
    /// A falta.
    pub fault: Fault,
    /// Por que foi encerrada.
    pub kill: Kill,
}

/// Threads encerradas por falta desde o boot.
static KILLED: AtomicU64 = AtomicU64::new(0);
/// O último encerramento (para os testes).
static LAST: SpinLock<Option<Report>> = SpinLock::with_class(LockClass::Diagnostic, None);

/// Threads encerradas por falta desde o boot.
pub fn killed() -> u64 {
    KILLED.load(Ordering::Relaxed)
}

/// O último encerramento por falta.
pub fn last() -> Option<Report> {
    *LAST.lock()
}

/// Chamado pelo tratador de exceções para uma exceção vinda do anel 3,
/// com o quadro do usuário e o CR2. Volta se a thread deve retomar a
/// instrução que faltou; senão, a encerra.
pub fn user_exception(frame: &TrapFrame, cr2: u64) {
    let fault = Fault {
        vector: frame.vector,
        error: frame.error,
        addr: if frame.vector == kabi::fault::PAGE_FAULT {
            cr2
        } else {
            0
        },
        rip: frame.rip,
        rsp: frame.rsp,
        rflags: frame.rflags,
    };
    let Some(me) = kthread::current() else {
        panic!("exceção do anel 3 sem thread atual");
    };
    let Err(kill) = fault::handle(&me, &fault, &mut KernelEnv) else {
        return;
    };
    let thread = Arc::as_ptr(&me).addr();
    me.record_death(kabi::exit::CAUSE_FAULTED, fault.vector, fault.addr);
    // `exit_current` nunca volta: nada pode ficar vivo nesta pilha.
    drop(me);
    let (name, what) = exception_name(fault.vector);
    warn!(
        "okernel: thread {thread:#x} encerrada por {name} ({what}): rip {:#x}, endereço {:#x}, erro {:#x}; {kill}",
        fault.rip, fault.addr, fault.error
    );
    *LAST.lock() = Some(Report {
        thread,
        fault,
        kill,
    });
    KILLED.fetch_add(1, Ordering::Relaxed);
    kthread::exit_current()
}
