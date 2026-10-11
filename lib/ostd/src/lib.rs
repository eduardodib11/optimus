//! `ostd`: biblioteca base dos processos de usuário do Optimus (SDD v1.0,
//! seção 7.1).
//!
//! Por ora (T-211), o mínimo para um serviço rodar: a entrada do processo
//! ([`entry!`] e [`rt`]), as syscalls cruas ([`sys`]) e invólucros seguros
//! para depuração, threads e tempo. Alocador, `Mutex`/`Condvar` sobre
//! futex, IPC e clientes OIDL chegam com o T-212.
//!
//! Só [`arch`] usa `unsafe` (a instrução `syscall` e o `_start`), como a
//! seção 17.1 permite ao "ostd baixo nível"; o resto da crate o proíbe.

#![no_std]
#![deny(unsafe_code)]

pub mod arch;
pub mod rt;
pub mod sys;

/// Versão da biblioteca, exposta para diagnóstico.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ABI do kernel (syscalls, erros, direitos, handles), a mesma usada pelo `okernel`.
pub use kabi;

/// Depuração.
pub mod debug {
    /// Manda `text` ao registro do kernel pela syscall de depuração
    /// provisória (`kabi::DEBUG_PRINT`), em pedaços de até
    /// `kabi::DEBUG_PRINT_MAX` bytes cortados em fronteira de caractere
    /// (cada pedaço vira uma linha).
    pub fn print(text: &str) {
        let mut rest = text;
        while !rest.is_empty() {
            let mut cut = rest.len().min(kabi::DEBUG_PRINT_MAX);
            while !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            let (part, tail) = rest.split_at(cut);
            let _ = crate::sys::call(
                kabi::DEBUG_PRINT,
                [part.as_ptr() as u64, part.len() as u64, 0, 0, 0, 0],
            );
            rest = tail;
        }
    }
}

/// Threads.
pub mod thread {
    use kabi::Syscall;

    /// Termina a thread atual (`thread_exit`).
    pub fn exit() -> ! {
        let _ = crate::sys::syscall(Syscall::ThreadExit, [0; 6]);
        // O kernel nunca volta de `thread_exit`.
        loop {
            core::hint::spin_loop();
        }
    }

    /// Cede a CPU (`yield`).
    pub fn yield_now() {
        let _ = crate::sys::syscall(Syscall::Yield, [0; 6]);
    }
}

/// Tempo.
pub mod time {
    /// Relógio monotônico em ns (`clock_get`).
    #[must_use]
    pub fn now_ns() -> u64 {
        crate::sys::syscall(kabi::Syscall::ClockGet, [0; 6]).map_or(0, |v| v[0])
    }
}
