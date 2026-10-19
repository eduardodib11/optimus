//! IPC no kernel (T-208; SDD v1.0, seção 6.7; ADR 0027): os registradores
//! do quadro da syscall viram [`Regs`] para `okernel::ipc::ops`, e o
//! resultado volta para eles; o buffer de IPC de cada thread é lido e
//! gravado pelo mapa direto, a partir da tradução no espaço dela (as duas
//! pontas de uma mensagem estão em espaços diferentes).
//!
//! O bloqueio, o prazo e a troca direta do caminho rápido ficam no
//! escalonador (`kthread`).

use kabi::vm::PAGE_SIZE;
use kabi::{Error, IPC_BUFFER_BYTES, Syscall};
use okernel::ipc::ops::{self, Regs};
use okernel::thread::Thread;

use crate::arch::x86_64::idt::TrapFrame;
use crate::kmem;
use crate::kthread::{KernelEnv, current};

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
        .and_then(|t| t.cspace())
        .ok_or(Error::NotSupported)
        .and_then(|space| ops::invoke(&space, call, &regs, &mut KernelEnv));
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
