//! Protocolo entre o `hello` e o `root` (T-212), compartilhado pelos dois
//! binários (o `root` inclui este arquivo).
//!
//! O `hello` só chama (`ipc_call`) e o `root` só responde:
//!
//! - [`HELLO`]: saudação em UTF-8 nas palavras do buffer de IPC, com o
//!   tamanho em bytes na palavra 0; a resposta é [`HELLO`] sem palavras.
//! - [`PING`]: na volta `i` (de 0), seis palavras [`word`]`(i, k)`; a
//!   resposta é [`PONG`] com cada palavra somada de 1.
//! - [`BYE`]: palavra 0 com as voltas feitas e palavra 1 com os erros que o
//!   `hello` viu; a resposta é [`BYE`] sem palavras.
//!
//! Entrada do `hello` (`thread_start`): `rdi` com o endpoint (32 bits
//! baixos) e a própria thread (altos), `rsi` com o próprio espaço e a cota
//! dele, `rdx` com o número de voltas.

#![allow(dead_code, reason = "cada binário usa uma parte do protocolo")]

/// Saudação.
pub const HELLO: u64 = 0x4845_4c4c_4f00_0001;
/// Ida de uma volta.
pub const PING: u64 = 0x4845_4c4c_4f00_0002;
/// Volta de uma volta.
pub const PONG: u64 = 0x4845_4c4c_4f00_0003;
/// Fim.
pub const BYE: u64 = 0x4845_4c4c_4f00_0004;

/// Badge do endpoint do `hello` visto pelo `root`.
pub const BADGE: u64 = 0x4845;
/// Badge do mesmo endpoint como endpoint de exceções do `hello`.
pub const EXCEPTION_BADGE: u64 = 0xE0;

/// Palavra `k` (0 a 5) da volta `i`.
#[must_use]
pub const fn word(i: u64, k: u64) -> u64 {
    i.wrapping_mul(8).wrapping_add(k) ^ 0x5a5a_0000_0000_0000
}
