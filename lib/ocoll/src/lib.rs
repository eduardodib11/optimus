//! `ocoll`: coleções, utilitários UTF-8 e geradores pseudoaleatórios do
//! Optimus (SDD v1.0, seção 7.1; ADR 0039, itens 4 e 6; T-337).
//!
//! `no_std` (usa `alloc`), sem `unsafe` e sem syscalls, então tudo roda e é
//! testado no host; o `ostd` reexporta isto como `ostd::collections`,
//! `ostd::utf8` e fornece a semente (`ostd::rand`).
//!
//! - [`HashMap`] e [`HashSet`]: endereçamento aberto com *Robin Hood* e
//!   remoção por deslocamento (sem lápides), sobre [`BuildHasher`]. O padrão
//!   é [`RandomState`], com SipHash-1-3 ([`SipHasher13`]) e chave de 128 bits
//!   diferente por mapa, sorteada de uma semente do processo
//!   ([`seed_random_state`]).
//! - [`Ring`]: anel de capacidade fixa (produtor/consumidor, com a variante
//!   que sobrescreve o mais antigo). A fila sem limite é a
//!   [`VecDeque`](alloc::collections::VecDeque) do `alloc`, reexportada
//!   como [`Queue`].
//! - [`utf8`]: validação estrita e decodificação incremental de UTF-8 e
//!   cortes em fronteira de caractere.
//! - [`prng`]: `SplitMix64` e `xoshiro256++` (não criptográficos).
//!
//! [`BuildHasher`]: core::hash::BuildHasher

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod hashmap;
pub mod prng;
mod ring;
mod siphash;
pub mod utf8;

#[cfg(test)]
mod tests;

pub use hashmap::{HashMap, HashSet, RandomState, is_seeded, seed_random_state};
pub use ring::Ring;
pub use siphash::SipHasher13;

/// Fila FIFO sem limite de tamanho (a do `alloc`).
pub use alloc::collections::VecDeque as Queue;
