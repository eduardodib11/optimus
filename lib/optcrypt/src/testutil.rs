//! Auxiliares dos testes.

use core::fmt::Write;

/// Bytes em hexadecimal minúsculo.
pub fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        write!(s, "{x:02x}").unwrap();
        s
    })
}
