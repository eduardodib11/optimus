//! HMAC-SHA-256 (RFC 2104, RFC 4231).

use crate::secret::{ct_eq, wipe};
use crate::sha256::{self, BLOCK_LEN, OUT_LEN, Sha256};

/// HMAC-SHA-256 incremental.
pub struct HmacSha256 {
    inner: Sha256,
    opad: [u8; BLOCK_LEN],
}

impl HmacSha256 {
    /// Começa um HMAC com `key` de qualquer tamanho.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            k[..OUT_LEN].copy_from_slice(&sha256::hash(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK_LEN];
        let mut opad = [0x5cu8; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        wipe(&mut k);
        wipe(&mut ipad);
        Self { inner, opad }
    }

    /// Alimenta a mensagem.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Termina e devolve a tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; OUT_LEN] {
        let inner = core::mem::take(&mut self.inner).finalize();
        let mut outer = Sha256::new();
        outer.update(&self.opad);
        outer.update(&inner);
        outer.finalize()
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        wipe(&mut self.opad);
    }
}

/// HMAC-SHA-256 de `data` com `key`.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; OUT_LEN] {
    let mut h = HmacSha256::new(key);
    h.update(data);
    h.finalize()
}

/// Confere `tag` contra o HMAC de `data` em tempo constante.
#[must_use]
pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut expected = hmac_sha256(key, data);
    let ok = ct_eq(&expected, tag);
    wipe(&mut expected);
    ok
}

#[cfg(test)]
mod tests;
