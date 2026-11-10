//! Lógica pura dos drivers legados (T-406; ADR 0042, itens 3 e 4).
//!
//! O driver de RTC e o de PS/2 rodam em processos isolados com só um
//! `IoPortRange` cada. O que decide algo (ler o CMOS de forma consistente,
//! decodificar bytes do `i8042`) mora aqui, sem acesso a hardware, para ser
//! testado no host. O processo do driver liga isto às portas e à IRQ.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod ps2;
pub mod rtc;

#[cfg(test)]
mod tests;
