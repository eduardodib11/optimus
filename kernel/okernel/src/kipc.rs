//! IPC no kernel (T-208; SDD v1.0, seção 6.7; ADR 0027): os registradores
//! do quadro da syscall viram [`Regs`] para `okernel::ipc::ops`, e o
//! resultado volta para eles; o buffer de IPC de cada thread é lido e
//! gravado pelo mapa direto, a partir da tradução no espaço dela (as duas
//! pontas de uma mensagem estão em espaços diferentes).
//!
//! `ipc_call` e `ipc_reply_recv` tentam antes o caminho rápido
//! (`okernel::ipc::fast`, T-331), que recusa sem mudar nada ou deixa a
//! outra thread pronta para a troca direta; o bloqueio, o prazo e essa
//! troca ficam no escalonador (`kthread`).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use kabi::vm::PAGE_SIZE;
use kabi::{Error, IPC_BUFFER_BYTES, MAX_CPUS, Syscall};
use okernel::cap::SharedCapSpace;
use okernel::ipc::fast::{self, Fast};
use okernel::ipc::ops::{self, Out, Regs};
use okernel::thread::Thread;

use crate::arch::x86_64::idt::TrapFrame;
use crate::arch::x86_64::percpu;
use crate::kmem;
use crate::kthread::{self, KernelEnv, current};

pub(crate) mod tests;
pub use tests::TESTS;

/// Executa a syscall de IPC `call` com os registradores de `frame` e grava
/// o resultado nele.
pub fn syscall(frame: &mut TrapFrame, call: Syscall) {
    let regs = Regs {
        target: frame.rdi,
        label: frame.rsi,
        info: frame.rdx,
        deadline: frame.r10,
        words: [
            frame.r8, frame.r9, frame.r12, frame.r13, frame.r14, frame.r15,
        ],
    };
    let result = current()
        .and_then(|me| Some((me.cspace()?, me)))
        .ok_or(Error::NotSupported)
        .and_then(|(space, me)| invoke(&space, &me, call, &regs));
    match result {
        Ok(out) => {
            frame.rax = kabi::STATUS_OK;
            frame.rdi = out.badge;
            frame.rsi = out.label;
            frame.rdx = out.info;
            [
                frame.r8, frame.r9, frame.r12, frame.r13, frame.r14, frame.r15,
            ] = out.words;
        }
        Err(e) => frame.rax = e.to_raw(),
    }
}

/// Idas pelo caminho rápido, por CPU: só a própria CPU grava a dela, sem
/// RMW atômico.
static FAST_PATHS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Syscalls de IPC que foram pelo caminho rápido desde o boot.
pub fn fast_paths() -> u64 {
    FAST_PATHS.iter().map(|c| c.load(Ordering::Relaxed)).sum()
}

/// A syscall `call` de `me`: pelo caminho rápido, se as condições dele
/// valem, ou pelo comum.
fn invoke(
    space: &Arc<SharedCapSpace>,
    me: &Arc<Thread>,
    call: Syscall,
    regs: &Regs,
) -> Result<Out, Error> {
    let cpu = percpu::cpu_id();
    let fast = match call {
        Syscall::IpcCall => fast::call(space, me, regs, cpu),
        Syscall::IpcReplyRecv => fast::reply_recv(space, me, regs, cpu, &mut KernelEnv),
        _ => Fast::Slow,
    };
    match fast {
        Fast::Slow => ops::invoke_as(space, me, call, regs, &mut KernelEnv),
        Fast::Switch(to) => {
            if let Some(c) = FAST_PATHS.get(cpu as usize) {
                c.store(c.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
            }
            kthread::switch_direct(to);
            ops::finish(me)
        }
        Fast::Done(result) => result,
    }
}

/// Endereço no mapa direto da palavra `at` do buffer de IPC de `t`, com
/// `len` palavras dentro da página; com `write`, só se ela for gravável.
fn buffer_word(t: &Thread, at: usize, len: usize, write: bool) -> Option<*mut u64> {
    let end = at.checked_add(len)?;
    if end * 8 > IPC_BUFFER_BYTES {
        return None;
    }
    let va = t.ipc_buffer()?;
    let aspace = t.aspace()?;
    let (phys, perms) = aspace.lock().query(va)?;
    if write && !perms.write {
        return None;
    }
    debug_assert!(phys.0.is_multiple_of(PAGE_SIZE));
    Some(core::ptr::with_exposed_provenance_mut::<u64>(
        usize::try_from(kmem::direct(phys)).ok()? + at * 8,
    ))
}

/// Lê `out.len()` palavras do buffer de IPC de `t` a partir de `at`.
pub fn read_buffer(t: &Thread, at: usize, out: &mut [u64]) -> bool {
    let Some(src) = buffer_word(t, at, out.len(), false) else {
        return false;
    };
    // SAFETY: `src` aponta, pelo mapa direto, para dentro da página física
    // mapeada no buffer de `t` (a faixa cabe nela); o frame é RAM de um
    // `MemoryObject` vivo enquanto mapeado, alinhado a 8. Uma thread do
    // dono em outra CPU pode gravá-lo ao mesmo tempo; o que se lê é só
    // dado, conferido depois como qualquer entrada do usuário.
    unsafe { core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), out.len()) };
    true
}

/// Grava `data` no buffer de IPC de `t` a partir de `at`.
pub fn write_buffer(t: &Thread, at: usize, data: &[u64]) -> bool {
    let Some(dst) = buffer_word(t, at, data.len(), true) else {
        return false;
    };
    // SAFETY: como em `read_buffer`, e a página é gravável pelo dono do
    // buffer, então gravar nela não fura nenhuma proteção.
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len()) };
    true
}
