//! `oidlc`: compilador do OIDL (ADR 0012, ADR 0033).
//!
//! Esta fatia traz o léxico, o parser e o AST (T-341). A análise semântica
//! é a T-342; o layout de fio, a T-343.

#![forbid(unsafe_code)]

pub mod ast;
pub mod lexer;
pub mod parser;

pub use parser::parse;
