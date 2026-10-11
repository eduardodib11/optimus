//! Código de máquina do `ostd`: a instrução `syscall`, a entrada `_start`
//! e o acesso à memória que o processo mapeou. Único lugar da crate com
//! `unsafe` e assembly (seção 17.1).

#![allow(unsafe_code)]

pub(crate) mod mem;
mod x86_64;

pub use x86_64::{entry, ipc, syscall};
