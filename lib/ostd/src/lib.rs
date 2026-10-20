//! `ostd`: biblioteca base dos processos de usuário do Optimus (SDD v1.0,
//! seção 7.1).
//!
//! Por ora (T-211, T-212), o mínimo para um serviço rodar e criar outro:
//! a entrada do processo ([`entry!`] e [`rt`]), as syscalls cruas
//! ([`sys`]), invólucros seguros para depuração, tempo, capabilities
//! ([`cap`]), memória ([`vm`]), threads ([`thread`]) e o IPC síncrono com
//! o buffer de IPC ([`ipc`], T-208), o bloco da thread com `thread_local!` ([`tls`], T-335), e o carregador de executáveis do
//! bootfs ([`process`], ADR 0029) e o alocador global ([`alloc`], T-334).
//! `Mutex`/`Condvar`/`Once`/`RwLock` sobre futex ([`sync`], T-336); a entropia do kernel ([`rand`], T-337); clientes OIDL ficam para depois.
//!
//! Só [`arch`] (a instrução `syscall`, o `_start` e o acesso à memória que o
//! processo mapeou), [`alloc`] (a cola do `GlobalAlloc`), [`tls`] (o bloco da
//! thread) e [`sync`] (as guardas das travas) usam `unsafe`,
//! como a seção 17.1 permite ao "ostd baixo nível" e a ADR 0039 detalha; o
//! resto da crate o proíbe. A lista de módulos com `unsafe` e o teto de
//! blocos de cada um estão em `unsafe-allowlist.toml`, e o `cargo xtask
//! check` os confere.

#![no_std]
#![deny(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

extern crate alloc as alloc_crate;

pub mod alloc;
pub mod arch;
pub mod cap;
pub mod ipc;
pub mod process;
pub mod rand;
pub mod rt;
pub mod sync;
pub mod sys;
pub mod thread;
pub mod tls;
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
