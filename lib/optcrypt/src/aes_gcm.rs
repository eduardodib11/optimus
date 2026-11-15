//! AES-256-GCM (NIST SP 800-38D) com nonce de 96 bits, por AES-NI e
//! PCLMULQDQ (ADR 0053, item 1). Sem AES em software: se a CPU não tem as
//! extensões, [`AesGcm::new`] devolve `None` e o volume usa ChaCha20-Poly1305.
//! A tag é conferida em tempo constante antes de decifrar (P6).

pub use crate::aead::AuthError;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
use crate::arch::x86_64 as cpu;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
use crate::poly1305::TAG_LEN;
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
use crate::secret::{Secret, ct_eq, wipe};

/// Bytes da chave.
pub const KEY_LEN: usize = 32;
/// Bytes do nonce.
pub const NONCE_LEN: usize = 12;

/// Chave AES-256 expandida.
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
pub struct AesGcm(cpu::Keys);

/// Esta CPU tem AES-NI e PCLMULQDQ?
#[must_use]
pub fn available() -> bool {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    {
        cpu::supported()
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "sse2")))]
    {
        false
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
impl AesGcm {
    /// Expande `key`; `None` sem AES-NI ou PCLMULQDQ.
    #[must_use]
    pub fn new(key: &Secret<KEY_LEN>) -> Option<Self> {
        cpu::expand(key.expose()).map(Self)
    }

    /// Cifra `buf` no lugar e devolve a tag. O chamador garante que
    /// `(chave, nonce)` não se repete (a API de bloco faz isso).
    #[must_use]
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> [u8; TAG_LEN] {
        cpu::ctr(&self.0, nonce, buf);
        cpu::tag(&self.0, nonce, aad, buf)
    }

    /// Confere `tag` e decifra `buf` no lugar; com tag errada `buf` fica zerado.
    ///
    /// # Errors
    /// [`AuthError`] se a tag não confere.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AuthError> {
        let mut esperada = cpu::tag(&self.0, nonce, aad, buf);
        let ok = ct_eq(&esperada, tag);
        wipe(&mut esperada);
        if !ok {
            wipe(buf);
            return Err(AuthError);
        }
        cpu::ctr(&self.0, nonce, buf);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
