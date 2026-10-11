//! `ostd`: biblioteca base dos processos de usuário do Optimus (SDD v1.0,
//! seção 7.1).
//!
//! Por ora (T-211, T-212), o mínimo para um serviço rodar e criar outro:
//! a entrada do processo ([`entry!`] e [`rt`]), as syscalls cruas
//! ([`sys`]), invólucros seguros para depuração, tempo, capabilities
//! ([`cap`]), memória ([`vm`]), threads ([`thread`]) e o IPC síncrono com
//! o buffer de IPC ([`ipc`], T-208), e o carregador de executáveis do
//! bootfs ([`process`], ADR 0029). Alocador, `Mutex`/`Condvar` sobre
//! futex e clientes OIDL ficam para depois.
//!
//! Só [`arch`] usa `unsafe` (a instrução `syscall`, o `_start` e o acesso
//! à memória que o processo mapeou), como a seção 17.1 permite ao "ostd
//! baixo nível"; o resto da crate o proíbe.

#![no_std]
#![deny(unsafe_code)]

pub mod arch;
pub mod cap;
pub mod ipc;
pub mod process;
pub mod rt;
pub mod sys;
pub mod thread;
pub mod vm;

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

    /// Linha formatada sem alocar, até `kabi::DEBUG_PRINT_MAX` bytes (o
    /// que passar é cortado).
    struct Line {
        buf: [u8; kabi::DEBUG_PRINT_MAX],
        len: usize,
    }

    impl core::fmt::Write for Line {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for c in s.chars() {
                let mut tmp = [0; 4];
                let bytes = c.encode_utf8(&mut tmp).as_bytes();
                let Some(dst) = self.buf.get_mut(self.len..self.len + bytes.len()) else {
                    return Err(core::fmt::Error);
                };
                dst.copy_from_slice(bytes);
                self.len += bytes.len();
            }
            Ok(())
        }
    }

    /// Como [`print`], com formatação (`format_args!`), numa linha só.
    pub fn print_fmt(args: core::fmt::Arguments<'_>) {
        let mut line = Line {
            buf: [0; kabi::DEBUG_PRINT_MAX],
            len: 0,
        };
        let _ = core::fmt::write(&mut line, args);
        // `write_str` só copia caracteres inteiros.
        if let Ok(text) = core::str::from_utf8(&line.buf[..line.len]) {
            print(text);
        }
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
