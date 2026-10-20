//! Coleções (T-337; ADR 0039, item 6).
//!
//! [`HashMap`] e [`HashSet`] são do `ocoll` (endereçamento aberto, SipHash-1-3
//! com chave de 128 bits por mapa, derivada da semente aleatória do
//! processo que [`crate::rt::init`] dá em [`crate::rand`]); [`Ring`] é o
//! anel de capacidade fixa e [`Queue`] a fila sem limite (a `VecDeque` do
//! `alloc`). O resto reexporta o `alloc`.
//!
//! Se o kernel não tem entropia, a semente vem da mistura de reserva e
//! [`crate::rand::is_degraded`] fica `true`: o mapa continua funcionando,
//! sem a defesa contra colisões forjadas.

pub use alloc_crate::collections::{
    BTreeMap, BTreeSet, BinaryHeap, LinkedList, VecDeque, btree_map, btree_set,
};
pub use ocoll::{HashMap, HashSet, Queue, RandomState, Ring, SipHasher13};
