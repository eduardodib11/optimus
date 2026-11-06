//! Lógica portável do `svcmgr` (ADR 0034), testada no host. O binário
//! (`main.rs`) faz as syscalls; aqui fica o que decide.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod broker;
pub mod plan;
pub mod supervisor;
// O `ostd` traz o `panic_impl` do alvo e não convive com o `std` dos testes.
#[cfg(not(test))]
pub mod kernel;
