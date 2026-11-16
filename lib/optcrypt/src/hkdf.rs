//! HKDF (RFC 5869) sobre SHA-256, SHA-384 e SHA-512.
//!
//! As funções da raiz do módulo são as do SHA-256; [`sha384`] e [`sha512`]
//! têm a mesma API com o hash respectivo (o TLS 1.3 usa as três).

/// Erro do `expand`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Pediu-se mais de `MAX_OUT` bytes.
    TooLong,
}

macro_rules! hkdf {
    ($modulo:ident, $hmac:ident, $hmac_fn:ident, $saida:path, $doc:literal) => {
        #[doc = concat!("HKDF-", $doc, ".")]
        pub mod $modulo {
            use super::Error;
            use crate::hmac::{$hmac, $hmac_fn};
            use crate::secret::Secret;

            /// Bytes do PRK (a saída do hash).
            pub const OUT_LEN: usize = $saida;
            /// Maior saída do `expand`: 255 blocos do hash.
            pub const MAX_OUT: usize = 255 * OUT_LEN;

            /// HKDF-Extract: PRK = HMAC(`salt`, `ikm`). Sal vazio vale
            /// `OUT_LEN` zeros.
            #[must_use]
            pub fn extract(salt: &[u8], ikm: &[u8]) -> Secret<OUT_LEN> {
                let zeros = [0u8; OUT_LEN];
                let salt = if salt.is_empty() { &zeros[..] } else { salt };
                let mut prk = $hmac_fn(salt, ikm);
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
                    let mut h = $hmac::new(prk.expose());
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

            /// Atalho: `expand` que devolve um [`Secret`] de `N` bytes.
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
        }
    };
}

hkdf!(
    sha256,
    HmacSha256,
    hmac_sha256,
    crate::sha256::OUT_LEN,
    "SHA-256"
);
hkdf!(
    sha384,
    HmacSha384,
    hmac_sha384,
    crate::sha512::OUT_LEN_384,
    "SHA-384"
);
hkdf!(
    sha512,
    HmacSha512,
    hmac_sha512,
    crate::sha512::OUT_LEN,
    "SHA-512"
);

pub use self::sha256::{MAX_OUT, expand, expand_secret, extract};

#[cfg(test)]
mod tests;
