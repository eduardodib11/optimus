//! `oidlc`: compilador do OIDL (ADR 0012, ADR 0033).
//!
//! Esta fatia traz o léxico, o parser e o AST (T-341). A análise semântica
//! e a compatibilidade entre versões ficam em [`sema`] e [`compat`] (T-342).
//! O layout de fio é a T-343.

#![forbid(unsafe_code)]

pub mod ast;
pub mod compat;
pub mod lexer;
pub mod parser;
pub mod sema;

pub use compat::check_compat;
pub use parser::parse;
pub use sema::analyze;
