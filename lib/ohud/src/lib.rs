//! `ohud`: primeiro passo do HUD do Optimus (ADR 0040, M-HUD1): a moldura de
//! vidro.
//!
//! `no_std` (usa `alloc`), sem `unsafe` e sem syscalls, então tudo roda e é
//! testado no host. O processo `hud` (ainda não existe) entregará a
//! [`Tela`] ao driver gráfico; aqui só se desenha em memória.
//!
//! - [`desenha_moldura`]: painel de vidro reto com reflexo diagonal.
//! - [`tema`]: paleta de funções (ciano, cobre, vermelho, verde) do ADR 0040.
//!
//! O núcleo em anéis entra no próximo PR, sobre este.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Coordenadas de tela usam `as` em faixas dentro do tipo de destino (até
// 1920x1080).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

extern crate alloc;

mod moldura;
mod tela;
pub mod tema;

pub use moldura::desenha_moldura;
pub use tela::{Cor, Tela, cor};

#[cfg(test)]
mod tests;
