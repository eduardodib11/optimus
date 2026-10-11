//! Syscalls cruas com a convenção da seção 14.1: número em `rax`,
//! argumentos em `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`; status em `rax` e
//! valores em `rdx`, `r10`, `r8`.

use kabi::{Error, STATUS_OK, Syscall};

/// Valores devolvidos em `rdx`, `r10` e `r8`.
pub type Values = [u64; 3];

/// Faz a syscall de número cru `nr`; erro desconhecido vira
/// [`Error::NotSupported`].
///
/// # Errors
///
/// O `kabi::Error` devolvido pelo kernel.
pub fn call(nr: u64, args: [u64; 6]) -> Result<Values, Error> {
    let (status, values) = crate::arch::syscall(nr, args);
    if status == STATUS_OK {
        Ok(values)
    } else {
        Err(Error::try_from(status).unwrap_or(Error::NotSupported))
    }
}

/// Faz a syscall `nr` da ABI v1.
///
/// # Errors
///
/// O `kabi::Error` devolvido pelo kernel.
pub fn syscall(nr: Syscall, args: [u64; 6]) -> Result<Values, Error> {
    call(nr.to_raw(), args)
}
