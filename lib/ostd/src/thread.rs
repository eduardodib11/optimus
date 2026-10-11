//! Threads e escalonamento (SDD v1.0, seções 6.1, 6.6 e 14.2; ADR 0029).

use kabi::thread::{CONFIGURE_EXCEPTION, CONFIGURE_IPC_BUFFER};
use kabi::{Error, Handle, Syscall};

use crate::cap::raw;
use crate::sys::syscall;

/// Termina a thread atual (`thread_exit`).
pub fn exit() -> ! {
    let _ = syscall(Syscall::ThreadExit, [0; 6]);
    // O kernel nunca volta de `thread_exit`.
    loop {
        core::hint::spin_loop();
    }
}

/// Cede a CPU (`yield`).
pub fn yield_now() {
    let _ = syscall(Syscall::Yield, [0; 6]);
}

/// `thread_configure` só da ligação: a thread passa a rodar com o
/// `CapSpace` `cspace` e o `AddressSpace` `aspace` (antes de
/// [`start`]).
///
/// # Errors
///
/// Os do kernel (`Busy` se a thread já começou).
pub fn bind(thread: Handle, cspace: Handle, aspace: Handle) -> Result<(), Error> {
    let args = [raw(thread), raw(cspace), raw(aspace), 0, 0, 0];
    syscall(Syscall::ThreadConfigure, args).map(drop)
}

/// `thread_configure` do buffer de IPC: `va` (uma página alinhada
/// mapeada no espaço da thread) ou `None` para tirar.
///
/// # Errors
///
/// Os do kernel.
pub fn set_ipc_buffer(thread: Handle, va: Option<u64>) -> Result<(), Error> {
    let args = [raw(thread), 0, 0, va.unwrap_or(0), 0, CONFIGURE_IPC_BUFFER];
    syscall(Syscall::ThreadConfigure, args).map(drop)
}

/// `thread_configure` do endpoint de exceções: `ep` é um handle no
/// `CapSpace` da thread (T-210), ou `None` para tirar.
///
/// # Errors
///
/// Os do kernel.
pub fn set_exception_handler(thread: Handle, ep: Option<Handle>) -> Result<(), Error> {
    let ep = ep.map_or(0, raw);
    let args = [raw(thread), 0, 0, 0, ep, CONFIGURE_EXCEPTION];
    syscall(Syscall::ThreadConfigure, args).map(drop)
}

/// `thread_start`: a thread começa em `rip` com a pilha em `rsp` e `args`
/// em `rdi`, `rsi` e `rdx`.
///
/// # Errors
///
/// Os do kernel (`InvalidArgument` sem ligação ou `SchedContext`).
pub fn start(thread: Handle, rip: u64, rsp: u64, args: [u64; 3]) -> Result<(), Error> {
    let [a0, a1, a2] = args;
    syscall(Syscall::ThreadStart, [raw(thread), rip, rsp, a0, a1, a2]).map(drop)
}

/// `sched_configure`: `budget_ns` a cada `period_ns`, com `priority`
/// (0 a 255; seção 6.6).
///
/// # Errors
///
/// Os do kernel.
pub fn sched_configure(
    sc: Handle,
    budget_ns: u64,
    period_ns: u64,
    priority: u8,
) -> Result<(), Error> {
    let args = [raw(sc), budget_ns, period_ns, u64::from(priority), 0, 0];
    syscall(Syscall::SchedConfigure, args).map(drop)
}

/// `sched_bind`: a thread passa a rodar sobre o `SchedContext` `sc`.
///
/// # Errors
///
/// Os do kernel.
pub fn sched_bind(sc: Handle, thread: Handle) -> Result<(), Error> {
    syscall(Syscall::SchedBind, [raw(sc), raw(thread), 0, 0, 0, 0]).map(drop)
}
