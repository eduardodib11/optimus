//! Corpo primo GF(2^255 - 19), base do X25519 e do Ed25519.
//!
//! Cinco membros de 51 bits, produtos em `u128`. Nenhuma operação tem ramo
//! ou índice que dependa dos valores: a redução final e a troca condicional
//! são feitas com máscaras.

// Os `as` para u8 e u64 truncam de propósito: só os bits baixos interessam.
#![allow(clippy::cast_possible_truncation, reason = "truncagens intencionais")]

/// 2^51 - 1.
const MASK: u64 = (1 << 51) - 1;

/// Elemento do corpo. Os membros ficam abaixo de 2^52 depois de cada
/// operação; só `to_bytes` dá a forma canônica.
#[derive(Clone, Copy)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

#[inline]
fn m(a: u64, b: u64) -> u128 {
    u128::from(a) * u128::from(b)
}

impl Fe {
    pub(crate) const ZERO: Self = Self([0; 5]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// Lê 32 bytes little-endian, ignorando o bit 255 (RFC 7748, seção 5).
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Self {
        let load = |i: usize| {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i..i + 8]);
            u64::from_le_bytes(w)
        };
        Self([
            load(0) & MASK,
            (load(6) >> 3) & MASK,
            (load(12) >> 6) & MASK,
            (load(19) >> 1) & MASK,
            (load(24) >> 12) & MASK,
        ])
    }

    /// Forma canônica (menor que p), 32 bytes little-endian.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        // Duas passadas: depois delas todos os membros ficam abaixo de 2^51.
        let mut l = self.carry().carry().0;
        // q = 1 se l >= p: somar 19 e ver se passa de 2^255.
        let mut q = (l[0] + 19) >> 51;
        for x in &l[1..] {
            q = (x + q) >> 51;
        }
        l[0] += 19 * q;
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK;
        }
        l[4] &= MASK;
        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut bits = 0;
        let mut j = 0;
        for x in l {
            acc |= u128::from(x) << bits;
            bits += 51;
            while bits >= 8 && j < 32 {
                out[j] = acc as u8;
                acc >>= 8;
                bits -= 8;
                j += 1;
            }
        }
        if j < 32 {
            out[j] = acc as u8;
        }
        out
    }

    /// Propaga os vai-uns: membros abaixo de 2^51 + 2^13·19.
    fn carry(self) -> Self {
        let mut l = self.0;
        let c4 = l[4] >> 51;
        l[4] &= MASK;
        l[0] += 19 * c4;
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK;
        }
        Self(l)
    }

    pub(crate) fn add(&self, o: &Self) -> Self {
        let mut l = self.0;
        for (x, y) in l.iter_mut().zip(o.0) {
            *x += y;
        }
        Self(l).carry()
    }

    /// `self - o`, somando 16p antes para não ficar negativo.
    pub(crate) fn sub(&self, o: &Self) -> Self {
        const P16_0: u64 = 16 * ((1 << 51) - 19);
        const P16_N: u64 = 16 * ((1 << 51) - 1);
        let a = self.0;
        Self([
            a[0] + P16_0 - o.0[0],
            a[1] + P16_N - o.0[1],
            a[2] + P16_N - o.0[2],
            a[3] + P16_N - o.0[3],
            a[4] + P16_N - o.0[4],
        ])
        .carry()
    }

    #[allow(clippy::many_single_char_names, reason = "notação usual")]
    pub(crate) fn mul(&self, o: &Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = o.0;
        let (b1t, b2t, b3t, b4t) = (b1 * 19, b2 * 19, b3 * 19, b4 * 19);
        let c = [
            m(a0, b0) + m(a4, b1t) + m(a3, b2t) + m(a2, b3t) + m(a1, b4t),
            m(a1, b0) + m(a0, b1) + m(a4, b2t) + m(a3, b3t) + m(a2, b4t),
            m(a2, b0) + m(a1, b1) + m(a0, b2) + m(a4, b3t) + m(a3, b4t),
            m(a3, b0) + m(a2, b1) + m(a1, b2) + m(a0, b3) + m(a4, b4t),
            m(a4, b0) + m(a3, b1) + m(a2, b2) + m(a1, b3) + m(a0, b4),
        ];
        Self::reduce_wide(c)
    }

    pub(crate) fn square(&self) -> Self {
        self.mul(self)
    }

    /// Produto por uma constante pequena (o `a24` da escada).
    pub(crate) fn mul_small(&self, k: u32) -> Self {
        let mut c = [0u128; 5];
        for (ci, x) in c.iter_mut().zip(self.0) {
            *ci = m(x, u64::from(k));
        }
        Self::reduce_wide(c)
    }

    /// Reduz cinco acumuladores de 128 bits para membros de 51 bits.
    fn reduce_wide(mut c: [u128; 5]) -> Self {
        for i in 0..4 {
            c[i + 1] += c[i] >> 51;
            c[i] &= u128::from(MASK);
        }
        // c4 >> 51 pode passar de 2^64 / 19: a conta fica em u128.
        c[0] += (c[4] >> 51) * 19;
        c[4] &= u128::from(MASK);
        c[1] += c[0] >> 51;
        c[0] &= u128::from(MASK);
        Self(c.map(|x| x as u64))
    }

    /// `self` elevado a 2^k.
    pub(crate) fn pow2k(&self, k: u32) -> Self {
        let mut r = *self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    /// Inverso por Fermat, `self^(p-2)`; zero vai em zero.
    #[allow(clippy::similar_names, reason = "nomes da cadeia de adição")]
    pub(crate) fn invert(&self) -> Self {
        let z2 = self.square();
        let z9 = z2.pow2k(2).mul(self);
        let z11 = z9.mul(&z2);
        let z_5_0 = z11.square().mul(&z9);
        let z_10_0 = z_5_0.pow2k(5).mul(&z_5_0);
        let z_20_0 = z_10_0.pow2k(10).mul(&z_10_0);
        let z_40_0 = z_20_0.pow2k(20).mul(&z_20_0);
        let z_50_0 = z_40_0.pow2k(10).mul(&z_10_0);
        let z_100_0 = z_50_0.pow2k(50).mul(&z_50_0);
        let z_200_0 = z_100_0.pow2k(100).mul(&z_100_0);
        let z_250_0 = z_200_0.pow2k(50).mul(&z_50_0);
        // 2^255 - 32 + 11 = p - 2.
        z_250_0.pow2k(5).mul(&z11)
    }

    /// Troca `a` e `b` se `bit` for 1, sem ramo.
    pub(crate) fn cswap(a: &mut Self, b: &mut Self, bit: u64) {
        let mask = 0u64.wrapping_sub(bit);
        for (x, y) in a.0.iter_mut().zip(b.0.iter_mut()) {
            let t = mask & (*x ^ *y);
            *x ^= t;
            *y ^= t;
        }
    }
}
