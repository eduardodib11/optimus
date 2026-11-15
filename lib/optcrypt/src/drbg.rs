//! Gerador de bytes do `keyd` (ADR 0054, item 4): `ChaCha20` com apagamento
//! rápido de chave. A cada saída os primeiros 32 bytes do fluxo viram a
//! chave seguinte e só o resto sai, então um estado vazado depois não
//! revela saídas anteriores.
//!
//! A semente mistura as fontes por `HKDF-Extract` com o sal
//! `optimus/keyd/semente/v1` sobre `kernel ‖ virtio ‖ chave atual`: o
//! dispositivo soma à entropia do kernel e nunca a substitui. A fonte do
//! kernel continua obrigatória; a decisão de recusar criar chave sem ela
//! é do `keyd`.

use crate::chacha20::{self, KEY_LEN};
use crate::hkdf;
use crate::secret::{Secret, wipe};

/// Sal da mistura de sementes.
pub const SEED_SALT: &[u8] = b"optimus/keyd/semente/v1";

/// Gerador com apagamento rápido de chave.
pub struct Drbg {
    key: Secret<KEY_LEN>,
    /// Foi semeado ao menos uma vez com entrada não vazia do kernel.
    seeded: bool,
}

impl Default for Drbg {
    fn default() -> Self {
        Self::new()
    }
}

impl Drbg {
    /// Gerador sem semente: [`Drbg::fill`] recusa até o primeiro
    /// [`Drbg::reseed`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            key: Secret::zeroed(),
            seeded: false,
        }
    }

    /// Foi semeado?
    #[must_use]
    pub const fn is_seeded(&self) -> bool {
        self.seeded
    }

    /// Mistura `kernel` (obrigatório, não vazio) e `virtio` (pode ser
    /// vazio) à chave atual. Sem bytes do kernel não semeia.
    ///
    /// # Errors
    /// [`Error::NoKernelEntropy`] se `kernel` é vazio.
    pub fn reseed(&mut self, kernel: &[u8], virtio: &[u8]) -> Result<(), Error> {
        if kernel.is_empty() {
            return Err(Error::NoKernelEntropy);
        }
        // IKM = kernel ‖ virtio ‖ chave atual, num buffer que é zerado.
        let mut ikm = [0u8; 256];
        let total = kernel.len() + virtio.len() + KEY_LEN;
        if total > ikm.len() {
            return Err(Error::InputTooLong);
        }
        let (a, rest) = ikm.split_at_mut(kernel.len());
        a.copy_from_slice(kernel);
        let (b, rest) = rest.split_at_mut(virtio.len());
        b.copy_from_slice(virtio);
        rest[..KEY_LEN].copy_from_slice(self.key.expose());
        let prk = hkdf::extract(SEED_SALT, &ikm[..total]);
        wipe(&mut ikm);
        self.key = prk;
        self.seeded = true;
        Ok(())
    }

    /// Enche `out` com bytes pseudoaleatórios.
    ///
    /// # Errors
    /// [`Error::NotSeeded`] antes da primeira semente.
    pub fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if !self.seeded {
            return Err(Error::NotSeeded);
        }
        // Fluxo: [nova chave (32) ‖ saída]. O nonce é fixo porque a chave
        // muda a cada chamada.
        let nonce = [0u8; chacha20::NONCE_LEN];
        let mut next = Secret::<KEY_LEN>::zeroed();
        let mut first = chacha20::block(self.key.expose(), 0, &nonce);
        next.expose_mut().copy_from_slice(&first[..KEY_LEN]);
        let head = out.len().min(chacha20::BLOCK_LEN - KEY_LEN);
        out[..head].copy_from_slice(&first[KEY_LEN..KEY_LEN + head]);
        wipe(&mut first);
        if out.len() > head {
            let rest = &mut out[head..];
            rest.fill(0);
            chacha20::apply(self.key.expose(), 1, &nonce, rest);
        }
        self.key = next;
        Ok(())
    }
}

/// Erros do gerador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Pediu-se saída antes de semear.
    NotSeeded,
    /// Sem bytes do kernel, que são obrigatórios (ADR 0054, item 1).
    NoKernelEntropy,
    /// As fontes somam mais de 224 bytes (kernel ‖ virtio).
    InputTooLong,
}

#[cfg(test)]
mod tests;
