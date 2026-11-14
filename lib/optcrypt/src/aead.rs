//! ChaCha20-Poly1305 (RFC 8439, seção 2.8). A tag é conferida em tempo
//! constante *antes* de decifrar; se falha, o buffer fica zerado (P6).

use crate::chacha20::{self, KEY_LEN, NONCE_LEN};
use crate::poly1305::{self, Poly1305, TAG_LEN};
use crate::secret::{Secret, ct_eq, wipe};

/// A tag não confere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthError;

fn mac(key: &Secret<KEY_LEN>, nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut otk = chacha20::block(key.expose(), 0, nonce);
    let mut k = [0u8; poly1305::KEY_LEN];
    k.copy_from_slice(&otk[..poly1305::KEY_LEN]);
    wipe(&mut otk);
    let mut p = Poly1305::new(&k);
    wipe(&mut k);
    let zeros = [0u8; 16];
    p.update(aad);
    p.update(&zeros[..aad.len().wrapping_neg() % 16]);
    p.update(ct);
    p.update(&zeros[..ct.len().wrapping_neg() % 16]);
    p.update(&(aad.len() as u64).to_le_bytes());
    p.update(&(ct.len() as u64).to_le_bytes());
    p.finalize()
}

/// Cifra `buf` no lugar e devolve a tag.
///
/// O chamador precisa garantir que `(key, nonce)` nunca se repete; a API de
/// bloco ([`crate::block`]) faz isso por construção.
#[must_use]
pub fn seal(
    key: &Secret<KEY_LEN>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; TAG_LEN] {
    chacha20::apply(key.expose(), 1, nonce, buf);
    mac(key, nonce, aad, buf)
}

/// Confere `tag` e decifra `buf` no lugar. Se a tag falha, `buf` é zerado.
///
/// # Errors
/// [`AuthError`] se a tag não confere.
pub fn open(
    key: &Secret<KEY_LEN>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), AuthError> {
    let mut esperada = mac(key, nonce, aad, buf);
    let ok = ct_eq(&esperada, tag);
    wipe(&mut esperada);
    if !ok {
        wipe(buf);
        return Err(AuthError);
    }
    chacha20::apply(key.expose(), 1, nonce, buf);
    Ok(())
}

#[cfg(test)]
mod tests;
