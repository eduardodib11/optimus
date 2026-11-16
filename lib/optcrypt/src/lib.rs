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
//!
//! Para a rede (M6, ADR 0070): SHA-384 e SHA-512 ([`sha512`]), com HMAC
//! e HKDF sobre os dois, X25519 ([`x25519`]) sobre o corpo de `f25519`,
//! SHA-3 e SHAKE ([`sha3`]) e ML-KEM-768 ([`mlkem768`]).
//! Os vetores oficiais dos testes ficam em `vetores/` (CAVP do NIST e
//! Wycheproof convertido por `vetores/wycheproof.py`).

#![cfg_attr(not(test), no_std)]
// `unsafe` só em `arch` (AES-NI), pelo orçamento de `unsafe-allowlist.toml`.
#![deny(unsafe_code)]

pub mod aead;
pub mod aes_gcm;
pub mod arch;
pub mod argon2;
pub mod blake2b;
pub mod blake3;
pub mod block;
pub mod chacha20;
pub mod drbg;
mod f25519;
pub mod hkdf;
pub mod hmac;
pub mod keyring;
pub mod mlkem768;
pub mod poly1305;
pub mod secret;
pub mod sha256;
pub mod sha3;
pub mod sha512;
pub mod x25519;

#[cfg(test)]
mod testutil;
