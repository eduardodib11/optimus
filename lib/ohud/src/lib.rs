//! `ohud`: primeiro passo do HUD do Optimus (ADR 0040, M-HUD1): a moldura de
//! vidro e o núcleo estilo JARVIS.
//!
//! `no_std` (usa `alloc`), sem `unsafe` e sem syscalls, então tudo roda e é
//! testado no host. O processo `hud` (ainda não existe) entregará a
//! [`Tela`] ao driver gráfico; aqui só se desenha em memória.
//!
//! - [`desenha_moldura`]: painel de vidro reto com reflexo diagonal.
//! - [`Nucleo`]: anéis de aço e cobre em degraus, régua de marcações,
//!   triângulo e reator. Os raios são proporcionais ao raio externo pedido.
//! - [`tema`]: paleta de funções (ciano, cobre, vermelho, verde) do ADR 0040.
//!
//! O brilho usa uma opacidade aproximada e o núcleo não tem desfoque nem
//! sombra; ADR 0040 prevê isso na meta de custo (medida em M-HUD2/3).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Coordenadas de tela e a tabela trigonométrica usam `as` em faixas sempre
// dentro do tipo de destino (tela até 1920x1080, tabela de 1440 passos).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

extern crate alloc;

mod moldura;
mod nucleo;
mod pincel;
mod tela;
pub mod tema;
mod trig;

pub use moldura::desenha_moldura;
pub use nucleo::Nucleo;
pub use tela::{Cor, Tela, cor};

#[cfg(test)]
mod tests;
