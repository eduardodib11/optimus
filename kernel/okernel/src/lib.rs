//! Lógica portável do Optimus Kernel (`okernel`).
//!
//! Tudo o que não depende do hardware fica nesta biblioteca, que compila para o
//! alvo do kernel (`no_std`) e roda os testes no host (`cargo xtask test unit`).
//! A entrada e o código de arquitetura ficam no binário (`main.rs`).

#![cfg_attr(not(test), no_std)]

pub mod mm;
