//! Objetos do kernel e capabilities (SDD v1.0, seções 6.1 e 6.2).
//!
//! Lógica portável e 100% safe: cotas de memória ([`quota`]), criação de
//! objetos ([`object`]) e a tabela de capabilities de cada processo
//! ([`space`]). Os objetos vivem no heap do kernel (slab) atrás de
//! `Arc`; a contagem de referências é a das capabilities que apontam para
//! eles, e o objeto morre, devolvendo os bytes à cota, quando a última some.

#![forbid(unsafe_code)]

pub mod object;
pub mod quota;
pub mod space;
pub mod xcdt;

pub use object::{Object, SharedCapSpace, default_rights, obj_create};
pub use quota::{Charge, MemoryQuota};
pub use space::{Cap, CapInfo, CapSpace};
