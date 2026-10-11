//! Código de máquina do `ostd`: a instrução `syscall` e a entrada `_start`.
//! Único lugar da crate com `unsafe` e assembly (seção 17.1).

#![allow(unsafe_code)]

mod x86_64;

pub use x86_64::{entry, syscall};
