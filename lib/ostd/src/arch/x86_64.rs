//! x86-64: `syscall` e `_start`.

use core::arch::{asm, global_asm};

use crate::rt::Entry;

/* Entrada do processo: zera o rbp (fim da cadeia de quadros), alinha a
 * pilha a 16 bytes como o System V pede antes do `call` e chama
 * `rt::start` com `rdi`, `rsi` e `rdx` intactos. */
global_asm!(
    ".section .text._start, \"ax\"",
    ".global _start",
    "_start:",
    "    xor ebp, ebp",
    "    and rsp, -16",
    "    call {start}",
    "    ud2",
    start = sym crate::rt::start,
);

unsafe extern "Rust" {
    /// Início da seção `.ostd_entry` (script `user.ld`): o `OSTD_ENTRY`
    /// criado por `ostd::entry!`.
    static __ostd_entry: Entry;
}

/// A função principal registrada por `ostd::entry!`.
#[must_use]
pub fn entry() -> Entry {
    // SAFETY: `user.ld` põe em `__ostd_entry` exatamente um `OSTD_ENTRY`
    // (confere o tamanho na ligação), um `Entry` válido e só de leitura.
    unsafe { __ostd_entry }
}

/// Faz a syscall `nr` com `args`; devolve o status (`rax`) e os valores
/// (`rdx`, `r10`, `r8`).
#[must_use]
pub fn syscall(nr: u64, args: [u64; 6]) -> (u64, [u64; 3]) {
    let (status, v0, v1, v2);
    // SAFETY: `syscall` entra no kernel, que só lê os argumentos, pode ler
    // ou gravar memória de usuário que eles apontam (por isso sem
    // `nomem`) e volta com `rcx` e `r11` destruídos e `rax`, `rdx`, `r10`
    // e `r8` com o resultado; os demais registradores são preservados.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => status,
            in("rdi") args[0],
            in("rsi") args[1],
            inlateout("rdx") args[2] => v0,
            inlateout("r10") args[3] => v1,
            inlateout("r8") args[4] => v2,
            in("r9") args[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, [v0, v1, v2])
}
