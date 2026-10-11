//! Threads de usuário no kernel: partida, troca de contexto, fila de
//! prontas e entrada das syscalls (T-206; SDD v1.0, seções 6.1, 6.6 e 14).
//!
//! Cada thread tem pilha de kernel própria. A entrada no kernel (SYSCALL ou
//! interrupção vinda do anel 3) salva os registradores de usuário num quadro
//! no topo dessa pilha; trocar de thread é trocar de pilha de kernel
//! ([`switch_context`]), salvar e restaurar o estado de FPU (XSAVE) e, se
//! preciso, o CR3. O contexto de boot é a thread ociosa: roda quando
//! ninguém mais está pronto, sempre com o CR3 do kernel.
//!
//! O kernel não é preemptível (ADR 0009) e roda com interrupções desligadas;
//! elas só chegam no anel 3 ou no ocioso. Por isso a fila tem uma trava
//! simples, nunca segura durante a troca.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};

use kabi::vm::{USER_END, USER_START};
use kabi::{Error, Syscall};
use okernel::sync::SpinLock;
use okernel::sys::{self, Values};
use okernel::thread::{RunState, Thread};

use crate::arch::x86_64::gdt::{USER_CODE, USER_DATA};
use crate::arch::x86_64::idt::TrapFrame;
use crate::arch::x86_64::syscall::{self, switch_context, thread_trampoline};
use crate::arch::x86_64::{cpu, fpu, probe};
use crate::{kcap, kmem, ktest, ktime};

mod tests;
pub use tests::TESTS;

/// Syscall de depuração dos testes de kernel, fora da ABI v1 da `kabi`:
/// `debug_print(ptr, len)` copia até 64 bytes do usuário para um registro
/// que os testes leem. Só existe em build de depuração com `test=kernel`;
/// fora disso devolve `NotSupported`. Temporária: sai quando `debug_write`
/// ganhar a capability de depuração.
pub const DEBUG_PRINT: u64 = 0x8000_0000;

/// Registradores iniciais de uma thread de usuário.
#[derive(Clone, Copy, Debug)]
pub struct UserEntry {
    /// Primeira instrução.
    pub rip: u64,
    /// Pilha de usuário.
    pub rsp: u64,
    /// `rdi`, `rsi` e `rdx`.
    pub args: [u64; 3],
}

struct Sched {
    /// Thread na CPU; `None` é o ocioso (o contexto de boot).
    current: Option<Arc<Thread>>,
    ready: VecDeque<Arc<Thread>>,
    /// Thread que terminou e cuja pilha ainda estava em uso na troca; a
    /// próxima a rodar a solta.
    dead: Option<Arc<Thread>>,
}

static SCHED: SpinLock<Sched> = SpinLock::new(Sched {
    current: None,
    ready: VecDeque::new(),
    dead: None,
});
/// rsp salvo do ocioso.
static IDLE_RSP: AtomicU64 = AtomicU64::new(0);
static DEBUG_LOG: SpinLock<([u8; 256], usize)> = SpinLock::new(([0; 256], 0));

/// A thread na CPU (`None` no ocioso).
pub fn current() -> Option<Arc<Thread>> {
    SCHED.lock().current.clone()
}

fn user_addr(addr: u64) -> bool {
    (USER_START..USER_END).contains(&addr)
}

/// `thread_start`: monta o quadro de usuário na pilha de kernel e põe a
/// thread na fila de prontas.
///
/// # Errors
///
/// [`Error::Busy`] se já iniciada; [`Error::InvalidArgument`] sem
/// `thread_configure` ou com `rip`/`rsp` fora da metade de usuário;
/// [`Error::QuotaExceeded`] sem memória para a fila.
pub fn start(thread: &Arc<Thread>, entry: &UserEntry) -> Result<(), Error> {
    if thread.state() != RunState::Inactive {
        return Err(Error::Busy);
    }
    if thread.root().is_none() || !user_addr(entry.rip) || !user_addr(entry.rsp) {
        return Err(Error::InvalidArgument);
    }
    let [rdi, rsi, rdx] = entry.args;
    let frame = TrapFrame {
        rdi,
        rsi,
        rdx,
        rip: entry.rip,
        cs: u64::from(USER_CODE),
        rflags: syscall::user_rflags(0),
        rsp: entry.rsp,
        ss: u64::from(USER_DATA),
        ..TrapFrame::default()
    };
    let frame_at = thread.stack().top - size_of::<TrapFrame>() as u64;
    // Abaixo do quadro: rbp, rbx, r12-r15 zerados e o retorno de
    // `switch_context` para o trampolim.
    let switch_at = frame_at - 7 * 8;
    let mut sched = SCHED.lock();
    sched
        .ready
        .try_reserve(1)
        .map_err(|_| Error::QuotaExceeded)?;
    // SAFETY: a pilha de kernel da thread está mapeada (RW) e é só dela;
    // a thread nunca rodou, então nada mais a usa.
    unsafe {
        (frame_at as *mut TrapFrame).write(frame);
        let switch = switch_at as *mut u64;
        for i in 0..6 {
            switch.add(i).write(0);
        }
        switch
            .add(6)
            .write((thread_trampoline as *const ()).addr() as u64);
    }
    thread.saved_rsp().store(switch_at, Ordering::Release);
    thread.set_state(RunState::Ready);
    sched.ready.push_back(Arc::clone(thread));
    Ok(())
}

/// Por que a thread atual deixa a CPU.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Why {
    /// Cede a vez e volta para o fim da fila.
    Yield,
    /// Terminou.
    Exit,
}

/// Escolhe a próxima thread e troca para ela. Volta quando a que chamou
/// for escolhida de novo (nunca, se ela saiu).
fn schedule(why: Why) {
    let mut s = SCHED.lock();
    let prev = s.current.take();
    if let Some(p) = &prev {
        if why == Why::Exit {
            p.set_state(RunState::Exited);
        } else if s.ready.try_reserve(1).is_ok() {
            p.set_state(RunState::Ready);
            s.ready.push_back(Arc::clone(p));
        }
    }
    let next = s.ready.pop_front();
    let same = match (&prev, &next) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    };
    if let Some(n) = &next {
        n.set_state(RunState::Running);
    }
    s.current.clone_from(&next);
    if same {
        return;
    }
    let prev_slot = prev
        .as_ref()
        .map_or(IDLE_RSP.as_ptr(), |p| p.saved_rsp().as_ptr());
    let prev_fpu = prev
        .as_ref()
        .filter(|p| p.state() != RunState::Exited)
        .map(|p| p.fpu_area());
    // A pilha da que saiu segue em uso até a troca; a fila (ou `dead`)
    // mantém viva a anterior enquanto o asm grava em `prev_slot`.
    let buried = if why == Why::Exit {
        core::mem::replace(&mut s.dead, prev)
    } else {
        None
    };
    drop(s);
    drop(buried);
    // SAFETY: as áreas são das threads (alinhadas a 64, do tamanho que
    // `fpu::area_bytes` pede), só a troca de contexto as acessa, e a pilha
    // de `next` está mapeada.
    unsafe {
        if let Some(area) = prev_fpu {
            fpu::save(core::ptr::with_exposed_provenance_mut(area));
        }
        if let Some(t) = &next {
            fpu::restore(core::ptr::with_exposed_provenance(t.fpu_area()));
            syscall::set_kernel_stack(t.stack().top);
        }
    }
    let (next_rsp, root) = next
        .as_ref()
        .map_or((IDLE_RSP.load(Ordering::Acquire), None), |t| {
            (t.saved_rsp().load(Ordering::Acquire), t.root())
        });
    let root = root.or_else(|| kmem::kernel_root().map(|r| r.0));
    if let Some(root) = root
        && cpu::read_cr3() & 0x000f_ffff_ffff_f000 != root
    {
        // SAFETY: o espaço da thread que vai rodar (vivo enquanto ela
        // estiver em `current`) ou o do kernel; ambos mapeiam o kernel.
        unsafe { cpu::write_cr3(root) };
    }
    drop(next);
    // SAFETY: `prev_slot` é o rsp salvo da anterior, viva (na fila, em
    // `dead` ou o ocioso); `next_rsp` foi salvo por esta mesma função ou
    // montado por `start`.
    unsafe { switch_context(prev_slot, next_rsp) };
    finish_switch();
}

/// Solta a thread que terminou, já fora da pilha dela.
fn finish_switch() {
    let dead = SCHED.lock().dead.take();
    drop(dead);
}

/// Primeira execução de uma thread, chamada por `thread_trampoline`.
#[unsafe(no_mangle)]
extern "sysv64" fn thread_first_run() {
    finish_switch();
}

/// Cede a CPU para a próxima pronta (do ocioso: roda as prontas).
pub fn yield_now() {
    schedule(Why::Yield);
}

/// `thread_exit`: a thread atual termina.
fn exit_current() -> ! {
    schedule(Why::Exit);
    unreachable!("thread terminada voltou a rodar");
}

/// Chamado por `syscall_entry` com o quadro do usuário. Devolve 1 se a
/// volta pode usar SYSRET.
#[unsafe(no_mangle)]
extern "sysv64" fn syscall_handler(frame: &mut TrapFrame) -> u64 {
    let args = [
        frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
    ];
    match dispatch(frame.rax, args) {
        Ok([a, b, c]) => {
            frame.rax = kabi::STATUS_OK;
            frame.rdx = a;
            frame.r10 = b;
            frame.r8 = c;
        }
        Err(e) => frame.rax = e.to_raw(),
    }
    frame.rflags = syscall::user_rflags(frame.rflags);
    u64::from(syscall::sysret_ok(frame.rip, frame.cs, frame.ss))
}

fn dispatch(nr: u64, a: [u64; 6]) -> Result<Values, Error> {
    if nr == DEBUG_PRINT {
        return debug_print(a[0], a[1]);
    }
    let call = Syscall::try_from(nr).map_err(|_| Error::NotSupported)?;
    match call {
        Syscall::Yield => {
            yield_now();
            Ok([0; 3])
        }
        Syscall::ThreadExit => exit_current(),
        Syscall::ClockGet => Ok([ktime::now_ns(), 0, 0]),
        _ => {
            let space = current()
                .and_then(|t| t.cspace())
                .ok_or(Error::NotSupported)?;
            sys::invoke(&space, call, a, kcap::REVOKE_SLICE_BUDGET, &mut || {})
        }
    }
}

fn debug_print(ptr: u64, len: u64) -> Result<Values, Error> {
    if !cfg!(debug_assertions) || !ktest::active() {
        return Err(Error::NotSupported);
    }
    let mut buf = [0u8; 64];
    let len = usize::try_from(len)
        .ok()
        .filter(|&n| n <= buf.len())
        .ok_or(Error::InvalidArgument)?;
    if !probe::copy_from_user(&mut buf[..len], ptr) {
        return Err(Error::InvalidArgument);
    }
    let mut log = DEBUG_LOG.lock();
    let (bytes, used) = &mut *log;
    let n = len.min(bytes.len() - *used);
    bytes[*used..*used + n].copy_from_slice(&buf[..n]);
    *used += n;
    Ok([len as u64, 0, 0])
}

/// Esvazia o registro de `debug_print` e devolve o que ele tinha.
pub fn take_debug_log() -> ([u8; 256], usize) {
    core::mem::replace(&mut *DEBUG_LOG.lock(), ([0; 256], 0))
}
