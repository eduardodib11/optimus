//! `onet`: os protocolos da pilha IP do `netd` (ADR 0017, 0068 e 0069).
//!
//! Tudo aqui é puro: recebe bytes e devolve bytes ou decisões, sem alocar
//! além do que o chamador entrega, sem relógio próprio (o tempo entra como
//! parâmetro) e sem `unsafe`. Todo parser trata a entrada como hostil: nunca
//! entra em pânico e devolve `None` ou um erro para quadro curto, truncado ou
//! inconsistente (ADR 0069, item 6). Assim os testes rodam no host e o
//! fuzzing (T-641) alcança cada parser direto.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod arp;
pub mod eth;
pub mod stack;

#[cfg(test)]
mod tests;
