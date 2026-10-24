//! Código de máquina do `ostd`: a instrução `syscall`, a entrada `_start`
//! e o acesso à memória que o processo mapeou. Único lugar da crate com
//! assembly (seção 17.1); o outro módulo com `unsafe` é [`crate::alloc`].
//!
//! # Unsafe
//!
//! O teto de usos está em `unsafe-allowlist.toml`. As invariantes:
//!
//! - **`syscall`:** a instrução entra no kernel, que só lê os argumentos,
//!   pode ler ou gravar a memória de usuário que eles apontam e preserva
//!   todos os registradores exceto `rax`, `rdx`, `r10`, `r8`, `rcx` e `r11`
//!   (declarados no `asm!`).
//! - **`_start` e `entry`:** o script `user.ld` põe em `__ostd_entry`
//!   exatamente um `Entry` válido e só de leitura (confere o tamanho na
//!   ligação).
//! - **`thread_pointer`:** lê `fs:[0]`; só se chama com o `FS_BASE` já posto
//!   num bloco de thread mapeado (a flag `tls::current` confere).
//! - **`mem`:** o acesso à memória mapeada parte de um [`Mapping`]
//!   (`crate::vm`), que mapeou a faixa no `new` e só desmapeia no `Drop`; o
//!   empréstimo do `Mapping` impede um acesso mutável concorrente.

#![allow(unsafe_code)]

pub(crate) mod mem;
mod x86_64;

pub use x86_64::{entry, ipc, syscall, thread_pointer};
