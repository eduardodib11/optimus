//! RSA, **só verificação** (RFC 8017, ADR 0071): RSASSA-PKCS1-v1_5 e
//! RSASSA-PSS com MGF1, módulos de 2048 a 4096 bits, SHA-256/384/512.
//!
//! Dados públicos, sem exigência de tempo constante. O PKCS#1 v1.5 é
//! conferido montando a codificação esperada e comparando byte a byte
//! (nada de interpretar o ASN.1 de dentro da assinatura).

use crate::bignum::{Modulus, Uint};
use crate::sha256::Sha256;
use crate::sha512::{Sha384, Sha512};

/// Menor módulo aceito, em bits.
pub const MIN_BITS: usize = 2048;
/// Maior módulo aceito, em bits.
pub const MAX_BITS: usize = 4096;
const MAX_LEN: usize = MAX_BITS / 8;
const LIMBS: usize = MAX_BITS / 64;

/// Hash da assinatura (e do MGF1, no PSS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Hash {
    /// Bytes do resumo.
    #[must_use]
    pub const fn out_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Resumo da concatenação de `partes`; os `out_len()` primeiros bytes valem.
    #[must_use]
    pub fn digest(self, partes: &[&[u8]]) -> [u8; 64] {
        let mut out = [0u8; 64];
        match self {
            Self::Sha256 => {
                let mut h = Sha256::new();
                for p in partes {
                    h.update(p);
                }
                out[..32].copy_from_slice(&h.finalize());
            }
            Self::Sha384 => {
                let mut h = Sha384::new();
                for p in partes {
                    h.update(p);
                }
                out[..48].copy_from_slice(&h.finalize());
            }
            Self::Sha512 => {
                let mut h = Sha512::new();
                for p in partes {
                    h.update(p);
                }
                out.copy_from_slice(&h.finalize());
            }
        }
        out
    }

    /// `DigestInfo` DER (RFC 8017, seção 9.2, nota 1) sem o resumo.
    const fn digest_info(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }
}

/// Erro ao montar a chave pública.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Módulo fora de 2048 a 4096 bits, ou par.
    Modulus,
    /// Expoente par, menor que 3 ou não menor que o módulo.
    Exponent,
}

/// Chave pública RSA `(n, e)`.
pub struct PublicKey {
    n: Modulus<LIMBS>,
    e: Uint<LIMBS>,
    /// Bytes do módulo (`k` da RFC).
    k: usize,
    bits: usize,
}

impl PublicKey {
    /// Monta a chave a partir de `n` e `e` big-endian (zeros à esquerda
    /// são aceitos, como vêm do DER).
    ///
    /// # Errors
    /// [`Error::Modulus`] ou [`Error::Exponent`] fora dos limites.
    pub fn new(n: &[u8], e: &[u8]) -> Result<Self, Error> {
        let n = Uint::<LIMBS>::from_be(n).ok_or(Error::Modulus)?;
        let bits = n.bits();
        if !(MIN_BITS..=MAX_BITS).contains(&bits) {
            return Err(Error::Modulus);
        }
        let n = Modulus::new(n).ok_or(Error::Modulus)?;
        let e = Uint::<LIMBS>::from_be(e).ok_or(Error::Exponent)?;
        if e.0[0] & 1 == 0 || e.bits() < 2 || e.cmp(&n.m).is_ge() {
            return Err(Error::Exponent);
        }
        Ok(Self {
            n,
            e,
            k: bits.div_ceil(8),
            bits,
        })
    }

    /// RSAVP1: `s^e mod n` em `k` bytes; `None` se `sig` não tiver `k`
    /// bytes ou não for menor que `n`.
    fn open(&self, sig: &[u8]) -> Option<[u8; MAX_LEN]> {
        if sig.len() != self.k {
            return None;
        }
        let s = Uint::from_be(sig)?;
        if s.cmp(&self.n.m).is_ge() {
            return None;
        }
        let m = self.n.leave_mont(&self.n.pow(&self.n.to_mont(&s), &self.e));
        let mut em = [0u8; MAX_LEN];
        m.write_be(&mut em[..self.k]);
        Some(em)
    }

    /// RSASSA-PKCS1-v1_5 sobre o resumo `hash` (já calculado com `alg`).
    #[must_use]
    pub fn verify_pkcs1v15(&self, alg: Hash, hash: &[u8], sig: &[u8]) -> bool {
        let Some(em) = self.open(sig) else {
            return false;
        };
        let info = alg.digest_info();
        let t_len = info.len() + alg.out_len();
        if hash.len() != alg.out_len() || self.k < t_len + 11 {
            return false;
        }
        // 00 01 FF..FF 00 ‖ DigestInfo ‖ resumo
        let mut esperado = [0xffu8; MAX_LEN];
        esperado[0] = 0;
        esperado[1] = 1;
        esperado[self.k - t_len - 1] = 0;
        esperado[self.k - t_len..self.k - alg.out_len()].copy_from_slice(info);
        esperado[self.k - alg.out_len()..self.k].copy_from_slice(hash);
        em[..self.k] == esperado[..self.k]
    }

    /// RSASSA-PSS (EMSA-PSS-VERIFY, RFC 8017 seção 9.1.2) com MGF1 sobre o
    /// mesmo hash e sal de `salt_len` bytes.
    #[must_use]
    pub fn verify_pss(&self, alg: Hash, hash: &[u8], sig: &[u8], salt_len: usize) -> bool {
        let Some(em_k) = self.open(sig) else {
            return false;
        };
        let h_len = alg.out_len();
        let em_bits = self.bits - 1;
        let em_len = em_bits.div_ceil(8);
        // I2OSP(m, emLen): com emLen = k - 1 o byte de cima precisa ser 0.
        if em_len < self.k && em_k[0] != 0 {
            return false;
        }
        let em = &em_k[self.k - em_len..self.k];
        if hash.len() != h_len || em_len < h_len + salt_len + 2 || em[em_len - 1] != 0xbc {
            return false;
        }
        let db_len = em_len - h_len - 1;
        let (masked, h) = (&em[..db_len], &em[db_len..em_len - 1]);
        let sobra = 8 * em_len - em_bits;
        let topo = 0xffu8 >> sobra;
        if masked[0] & !topo != 0 {
            return false;
        }
        let mut db = [0u8; MAX_LEN];
        let db = &mut db[..db_len];
        db.copy_from_slice(masked);
        mgf1_xor(alg, h, db);
        db[0] &= topo;
        let ps = db_len - salt_len - 1;
        if db[..ps].iter().any(|&b| b != 0) || db[ps] != 0x01 {
            return false;
        }
        let h2 = alg.digest(&[&[0u8; 8], hash, &db[ps + 1..]]);
        h2[..h_len] == *h
    }
}

/// `out ^= MGF1(seed, out.len())`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "contador de 32 bits da RFC"
)]
fn mgf1_xor(alg: Hash, seed: &[u8], out: &mut [u8]) {
    for (i, bloco) in out.chunks_mut(alg.out_len()).enumerate() {
        let c = (i as u32).to_be_bytes();
        let d = alg.digest(&[seed, &c]);
        for (o, x) in bloco.iter_mut().zip(d) {
            *o ^= x;
        }
    }
}

#[cfg(test)]
mod tests;
