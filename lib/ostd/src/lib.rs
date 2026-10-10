//! `ostd`: biblioteca base dos processos de usuário do Optimus.
//!
//! Esqueleto do M0: só garante que a crate compila para o alvo de usuário.
//! Alocador, threads, IPC e clientes OIDL chegam a partir do M2 (T-212).

#![no_std]
#![forbid(unsafe_code)]

/// Versão da biblioteca, exposta para diagnóstico.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
