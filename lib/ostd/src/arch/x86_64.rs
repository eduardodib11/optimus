//! x86-64: `syscall`, a syscall de IPC e `_start`.

use core::arch::{asm, global_asm};

use kabi::Syscall;

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

/// Syscall de IPC `nr` com os registradores da ADR 0027: `regs` vai para
/// `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`, `r12`–`r15`; devolve o status
/// (`rax`) e `rdi`, `rsi`, `rdx`, `r8`, `r9`, `r12`–`r15`.
#[must_use]
pub fn ipc(nr: u64, regs: [u64; 10]) -> (u64, [u64; 9]) {
    let [rdi, rsi, rdx, r10, r8, r9, r12, r13, r14, r15] = regs;
    let mut out = [0u64; 9];
    let status;
    // SAFETY: `syscall` entra no kernel, que pode ler e gravar o buffer de
    // IPC da thread (por isso sem `nomem`) e volta com `rcx` e `r11`
    // destruídos, `r10` indefinido e o resultado nos demais registradores
    // declarados; os outros são preservados.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => status,
            inlateout("rdi") rdi => out[0],
            inlateout("rsi") rsi => out[1],
            inlateout("rdx") rdx => out[2],
            inlateout("r10") r10 => _,
            inlateout("r8") r8 => out[3],
            inlateout("r9") r9 => out[4],
            inlateout("r12") r12 => out[5],
            inlateout("r13") r13 => out[6],
            inlateout("r14") r14 => out[7],
            inlateout("r15") r15 => out[8],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    (status, out)
}

/// O ponteiro da thread: `fs:[0]`, o endereço do bloco da thread, que ele
/// guarda em si mesmo (ABI x86-64; ADR 0039, item 3). Zero se a thread
/// ainda não tem `FS_BASE`.
#[must_use]
pub fn thread_pointer() -> u64 {
    let ptr: u64;
    // SAFETY: lê 8 bytes em `fs:[0]`. Com `FS_BASE` zero (thread sem TLS)
    // o endereço é 0 e o acesso daria falta de página; por isso quem chama
    // só usa isto depois de o `rt::start` e o `spawn` terem posto o
    // `FS_BASE` num bloco mapeado (`tls::current` confere a flag).
    unsafe {
        asm!("mov {}, fs:[0]", out(reg) ptr, options(nostack, readonly, preserves_flags));
    }
    ptr
}

/// Último ato de uma thread do `ostd` que outra vai juntar: grava 1 em
/// `*flag`, acorda com `futex_wake` quem espera nela e chama `thread_exit`
/// com `code`, tudo num bloco de assembly **sem tocar na pilha** nem na
/// memória depois do primeiro `mov`. É o que deixa quem espera desmapear a
/// pilha e o bloco da thread assim que vê a flag em 1: a thread só executa
/// mais duas instruções `syscall` com registradores (T-335).
pub fn exit_signalling(flag: &core::sync::atomic::AtomicU32, code: u64) -> ! {
    // SAFETY: `flag` é uma palavra válida e gravável (um `AtomicU32`); o
    // `mov` é um `store` de 4 bytes alinhado, atômico em x86-64. Os dois
    // `syscall` seguem a convenção da ABI (número em `rax`, argumentos em
    // `rdi` e `rsi`); `futex_wake` num endereço já desmapeado só dá erro, e
    // `thread_exit` sem flags nunca volta (o `ud2` é só a rede de segurança).
    // Nada acessa a pilha.
    unsafe {
        asm!(
            "mov dword ptr [r12], 1",
            "mov rdi, r12",
            "mov esi, 1",
            "mov eax, {wake}",
            "syscall",
            "mov rdi, r13",
            "xor esi, esi",
            "mov eax, {exit}",
            "syscall",
            "ud2",
            in("r12") flag.as_ptr(),
            in("r13") code,
            wake = const Syscall::FutexWake as u32,
            exit = const Syscall::ThreadExit as u32,
            options(noreturn),
        )
    }
}
