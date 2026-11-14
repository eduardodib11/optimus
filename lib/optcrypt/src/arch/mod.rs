//! Código dependente de CPU da `optcrypt`: AES-256-GCM com AES-NI e
//! PCLMULQDQ (ADR 0053, item 1; T-534). Único lugar da crate com `unsafe`.
//!
//! # Unsafe
//!
//! O teto de usos está em `unsafe-allowlist.toml`. As invariantes:
//!
//! - As funções com `#[target_feature(enable = "aes,pclmulqdq,sse2,ssse3")]`
//!   só são chamadas pelas envoltórias seguras deste módulo, depois de
//!   [`x86_64::supported`] confirmar as quatro extensões por CPUID. Sem isso
//!   as envoltórias recusam a chamada e nenhuma instrução é executada.
//! - Nenhum ponteiro bruto: os dados entram e saem por `transmute` entre
//!   `[u8; 16]` e `__m128i`, que têm o mesmo tamanho e aceitam todo padrão de
//!   bits.
//! - Tempo constante: só instruções sem ramos nos dados (`aesenc`,
//!   `pclmulqdq`, xor, deslocamentos).
//!
//! # Alvos sem SSE
//!
//! Os alvos da imagem (`x86_64-unknown-none` e `x86_64-unknown-uefi`) são
//! soft-float (ADR 0025); neles o módulo `x86_64` nem é compilado (os tipos
//! vetoriais derrubam o LLVM) e `AesGcm` não existe, então o volume usa
//! ChaCha20-Poly1305. Ligar o AES-NI na imagem depende de liberar SSE para
//! processos de usuário, o que pede ADR própria (pendência da ADR 0025).
#![allow(unsafe_code)]

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
pub mod x86_64;
