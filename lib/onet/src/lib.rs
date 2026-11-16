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
#![allow(
    clippy::many_single_char_names,
    reason = "protocolo: h, p, s e e são o cabeçalho, o pacote, o estado e o eco, como nas RFCs"
)]
#![allow(
    clippy::doc_markdown,
    reason = "ICMPv6, IPv6 e DHCPv4 são nomes de protocolo, não identificadores"
)]

extern crate alloc;

pub mod arp;
pub mod dhcp;
pub mod eth;
pub mod frag;
pub mod icmp;
pub mod icmp6;
pub mod ip4;
pub mod ip6;
pub mod nd;
pub mod policy;
pub mod ports;
pub mod slaac;
pub mod sock;
pub mod stack;
pub mod tcp;
pub mod udp;

#[cfg(test)]
mod tests;
