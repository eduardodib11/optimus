//! HKDF-SHA-256 (RFC 5869).

use crate::hmac::{HmacSha256, hmac_sha256};
use crate::secret::Secret;
use crate::sha256::OUT_LEN;

/// Maior saída do `expand`: 255 blocos do hash.
pub const MAX_OUT: usize = 255 * OUT_LEN;

/// Erro do `expand`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Pediu-se mais de [`MAX_OUT`] bytes.
    TooLong,
}

/// HKDF-Extract: PRK = HMAC(`salt`, `ikm`). Sal vazio vale 32 zeros.
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> Secret<OUT_LEN> {
    let zeros = [0u8; OUT_LEN];
    let salt = if salt.is_empty() { &zeros[..] } else { salt };
    let mut prk = hmac_sha256(salt, ikm);
    Secret::take(&mut prk)
}

/// HKDF-Expand: enche `out` a partir de `prk` e `info`.
///
/// # Errors
/// [`Error::TooLong`] se `out` passar de [`MAX_OUT`] bytes.
pub fn expand(prk: &Secret<OUT_LEN>, info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    if out.len() > MAX_OUT {
        return Err(Error::TooLong);
    }
    let mut prev = Secret::<OUT_LEN>::zeroed();
    let mut contador = 0u8;
    for (i, chunk) in out.chunks_mut(OUT_LEN).enumerate() {
        // No máximo 255 blocos, pela checagem de tamanho acima.
        contador = contador.wrapping_add(1);
        let mut h = HmacSha256::new(prk.expose());
        if i > 0 {
            h.update(prev.expose());
        }
        h.update(info);
        h.update(&[contador]);
        let mut block = h.finalize();
        chunk.copy_from_slice(&block[..chunk.len()]);
        prev = Secret::take(&mut block);
    }
    Ok(())
}

/// Atalho: `expand` que devolve um [`Secret`] de `N` bytes (`N <= 8160`).
///
/// # Errors
/// [`Error::TooLong`] se `N` passar de [`MAX_OUT`].
pub fn expand_secret<const N: usize>(
    prk: &Secret<OUT_LEN>,
    info: &[u8],
) -> Result<Secret<N>, Error> {
    let mut s = Secret::<N>::zeroed();
    expand(prk, info, s.expose_mut())?;
    Ok(s)
}

#[cfg(test)]
mod tests;
