//! `optcrypt`: criptografia do Optimus OS (SDD v1.0, seção 13.3).
//!
//! **Provisória.** A ADR 0004 quer a criptografia do sistema vinda de código
//! verificado formalmente. Até essa crate existir, aqui fica só uma
//! implementação própria do BLAKE3 ([`blake3`]), portável, sem `unsafe`
//! e sem alocação, que segue a implementação de referência da
//! especificação (sem SIMD nem paralelismo) e é conferida com os vetores
//! oficiais. Ela serve ao bootfs (T-211) e sai quando a ADR 0004 for
//! cumprida; a API (`blake3::hash`, `blake3::Hasher`) deve ser mantida
//! pela substituta.
//!
//! Para o armazenamento (ADR 0053), a crate também tem SHA-256, HMAC e
//! HKDF ([`sha256`], [`hmac`], [`hkdf`]) e os tipos de segredo ([`secret`]).
//! São escritos à mão e conferidos com vetores NIST e RFC; a adaptação de
//! código verificado (P9 da ADR 0053) continua pendente, como a do BLAKE3.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod blake3;
pub mod hkdf;
pub mod hmac;
pub mod secret;
pub mod sha256;

#[cfg(test)]
mod testutil;
