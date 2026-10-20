//! Threads e escalonamento (SDD v1.0, seções 6.1, 6.6 e 14.2; ADR 0029).

use kabi::sched::{CpuMask, SYS_INFO_CPUS};
use kabi::thread::{CONFIGURE_EXCEPTION, CONFIGURE_IPC_BUFFER, CONFIGURE_TLS};
use kabi::{Error, Handle, Syscall};

use crate::cap::raw;
use crate::sys::syscall;

/// `thread = SELF` em `thread_configure`: a própria thread, sem capability
/// (ADR 0039, item 3; o `kabi::thread::SELF`, zero). Vale para [`set_ipc_buffer`],
/// [`set_exception_handler`] e [`set_tls`]; [`bind`] exige a capability.
pub const SELF: Handle = Handle::from_raw(0);
const _: () = assert!(kabi::thread::SELF == 0);

/// Termina a thread atual (`thread_exit`) com o código 0.
pub fn exit() -> ! {
    exit_with(0)
}

/// Termina a thread atual com `code`, que vai ao registro de morte dela
/// (ADR 0035, item 2).
pub fn exit_with(code: u64) -> ! {
    let _ = syscall(Syscall::ThreadExit, [code, 0, 0, 0, 0, 0]);
    // O kernel nunca volta de `thread_exit` sem flags.
    loop {
        core::hint::spin_loop();
    }
}

/// `thread_exit` com `EXIT_GROUP`: encerra o processo inteiro com `code`
/// (ADR 0039, item 5). Só volta com o erro do kernel: `NotSupported` até o
/// encerramento de processos da T-348.
#[must_use]
pub fn exit_group(code: u64) -> Error {
    match syscall(Syscall::ThreadExit, [code, kabi::exit::GROUP, 0, 0, 0, 0]) {
        Err(e) => e,
        Ok(_) => Error::NotSupported,
    }
}

/// `thread_configure` do TLS: o `FS_BASE` de `thread` ([`SELF`] para a
/// própria) passa a ser `va`, zero ou um endereço da metade de usuário
/// (ADR 0039, item 3). Na própria thread vale já; noutra que roda, na
/// próxima vez que ela entrar numa CPU.
///
/// # Errors
///
/// Os do kernel (`InvalidArgument` fora da metade de usuário).
pub fn set_tls(thread: Handle, va: u64) -> Result<(), Error> {
    let args = [raw(thread), 0, 0, va, 0, CONFIGURE_TLS];
    syscall(Syscall::ThreadConfigure, args).map(drop)
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

/// Como [`sched_configure`], e o `SchedContext` passa a permitir só as CPUs
/// de `mask` (ADR 0032, item 4): as threads que rodam sobre ele, inclusive
/// por doação, só começam a rodar nelas.
///
/// # Errors
///
/// Os do kernel (`InvalidArgument` se `mask` não tem CPU ligada).
pub fn sched_configure_on(
    sc: Handle,
    budget_ns: u64,
    period_ns: u64,
    priority: u8,
    mask: &CpuMask,
) -> Result<(), Error> {
    let addr = core::ptr::from_ref(mask).addr() as u64;
    let args = [raw(sc), budget_ns, period_ns, u64::from(priority), addr, 0];
    syscall(Syscall::SchedConfigure, args).map(drop)
}

/// CPUs ligadas e total de ids lógicos da topologia (`sys_info` com
/// `SYS_INFO_CPUS`).
///
/// # Errors
///
/// Os do kernel.
pub fn cpus() -> Result<(u64, u64), Error> {
    syscall(Syscall::SysInfo, [SYS_INFO_CPUS, 0, 0, 0, 0, 0])
        .map(|[online, total, _]| (online, total))
}

/// `sched_bind`: a thread passa a rodar sobre o `SchedContext` `sc`.
///
/// # Errors
///
/// Os do kernel.
pub fn sched_bind(sc: Handle, thread: Handle) -> Result<(), Error> {
    syscall(Syscall::SchedBind, [raw(sc), raw(thread), 0, 0, 0, 0]).map(drop)
}
