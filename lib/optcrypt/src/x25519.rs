//! X25519 (RFC 7748): troca de chaves Diffie-Hellman sobre a Curve25519.
//!
//! A escada de Montgomery percorre os 255 bits do escalar com troca
//! condicional por máscara: o número de operações e os endereços acessados
//! não dependem do segredo.

use crate::f25519::Fe;
use crate::secret::{Secret, ct_eq};

/// Bytes de escalares, coordenadas e segredos.
pub const LEN: usize = 32;

/// Coordenada u do ponto base (9).
pub const BASEPOINT: [u8; LEN] = {
    let mut b = [0u8; LEN];
    b[0] = 9;
    b
};

/// Erro do [`diffie_hellman`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// O ponto do par é de ordem pequena e o segredo deu zero (RFC 7748,
    /// seção 6.1; o TLS 1.3 manda abortar).
    LowOrder,
}

#[allow(clippy::many_single_char_names, reason = "nomes da RFC 7748")]
/// Função X25519 crua: `k` (ajustado como manda a RFC) vezes o ponto `u`.
#[must_use]
pub fn x25519(k: &[u8; LEN], u: &[u8; LEN]) -> [u8; LEN] {
    let mut e = *k;
    e[0] &= 0xf8;
    e[31] &= 0x7f;
    e[31] |= 0x40;
    let x1 = Fe::from_bytes(u);
    let (mut x2, mut z2, mut x3, mut z3) = (Fe::ONE, Fe::ZERO, x1, Fe::ONE);
    let mut swap = 0u64;
    for t in (0..255).rev() {
        // O índice depende só do contador, não do segredo.
        let bit = u64::from((e[t >> 3] >> (t & 7)) & 1);
        swap ^= bit;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let ee = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = ee.mul(&aa.add(&ee.mul_small(121_665)));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    crate::secret::wipe(&mut e);
    x2.mul(&z2.invert()).to_bytes()
}

/// Chave pública de `secret`: `secret` vezes o ponto base.
#[must_use]
pub fn public_key(secret: &Secret<LEN>) -> [u8; LEN] {
    x25519(secret.expose(), &BASEPOINT)
}

/// Segredo compartilhado com o par de chave pública `peer`.
///
/// # Errors
/// [`Error::LowOrder`] se o resultado for zero (ponto de ordem pequena).
pub fn diffie_hellman(secret: &Secret<LEN>, peer: &[u8; LEN]) -> Result<Secret<LEN>, Error> {
    let mut s = x25519(secret.expose(), peer);
    let zero = ct_eq(&s, &[0u8; LEN]);
    let out = Secret::take(&mut s);
    if zero { Err(Error::LowOrder) } else { Ok(out) }
}

#[cfg(test)]
mod tests;
