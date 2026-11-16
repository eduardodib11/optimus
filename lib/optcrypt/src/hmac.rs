//! HMAC (RFC 2104) sobre SHA-256, SHA-384 e SHA-512 (RFC 4231).
//!
//! Os três tipos saem da mesma macro; só mudam o hash, o bloco e a saída.

use crate::secret::{ct_eq, wipe};
use crate::sha256::{self, Sha256};
use crate::sha512::{self, Sha384, Sha512};

macro_rules! hmac {
    ($nome:ident, $hash:ty, $hash_fn:path, $bloco:expr, $saida:expr, $fn:ident, $verify:ident, $doc:literal) => {
        #[doc = concat!("HMAC-", $doc, " incremental.")]
        pub struct $nome {
            inner: $hash,
            opad: [u8; $bloco],
        }

        impl $nome {
            /// Começa um HMAC com `key` de qualquer tamanho.
            #[must_use]
            pub fn new(key: &[u8]) -> Self {
                let mut k = [0u8; $bloco];
                if key.len() > $bloco {
                    let mut hk = $hash_fn(key);
                    k[..$saida].copy_from_slice(&hk);
                    wipe(&mut hk);
                } else {
                    k[..key.len()].copy_from_slice(key);
                }
                let mut ipad = [0x36u8; $bloco];
                let mut opad = [0x5cu8; $bloco];
                for i in 0..$bloco {
                    ipad[i] ^= k[i];
                    opad[i] ^= k[i];
                }
                let mut inner = <$hash>::new();
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
            pub fn finalize(mut self) -> [u8; $saida] {
                let mut inner = core::mem::take(&mut self.inner).finalize();
                let mut outer = <$hash>::new();
                outer.update(&self.opad);
                outer.update(&inner);
                wipe(&mut inner);
                outer.finalize()
            }
        }

        impl Drop for $nome {
            fn drop(&mut self) {
                wipe(&mut self.opad);
            }
        }

        #[doc = concat!("HMAC-", $doc, " de `data` com `key`.")]
        #[must_use]
        pub fn $fn(key: &[u8], data: &[u8]) -> [u8; $saida] {
            let mut h = $nome::new(key);
            h.update(data);
            h.finalize()
        }

        #[doc = concat!("Confere `tag` contra o HMAC-", $doc, " de `data` em tempo constante.")]
        #[must_use]
        pub fn $verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
            let mut expected = $fn(key, data);
            let ok = ct_eq(&expected, tag);
            wipe(&mut expected);
            ok
        }
    };
}

hmac!(
    HmacSha256,
    Sha256,
    sha256::hash,
    sha256::BLOCK_LEN,
    sha256::OUT_LEN,
    hmac_sha256,
    verify,
    "SHA-256"
);
hmac!(
    HmacSha384,
    Sha384,
    sha512::hash384,
    sha512::BLOCK_LEN,
    sha512::OUT_LEN_384,
    hmac_sha384,
    verify_sha384,
    "SHA-384"
);
hmac!(
    HmacSha512,
    Sha512,
    sha512::hash,
    sha512::BLOCK_LEN,
    sha512::OUT_LEN,
    hmac_sha512,
    verify_sha512,
    "SHA-512"
);

#[cfg(test)]
mod tests;
