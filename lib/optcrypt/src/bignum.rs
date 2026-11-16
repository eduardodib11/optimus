//! Inteiros grandes mínimos para a verificação de assinaturas (ECDSA P-256
//! e RSA): `N` palavras de 64 bits little-endian e aritmética de
//! Montgomery (CIOS) sobre um módulo ímpar.
//!
//! **Não é tempo constante.** Só serve a dados públicos (chaves públicas,
//! assinaturas, resumos); nada secreto passa por aqui.

#![allow(
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    reason = "metades de produtos de 128 bits; notação e laços usuais de bignum"
)]

use core::cmp::Ordering;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Uint<const N: usize>(pub(crate) [u64; N]);

impl<const N: usize> Uint<N> {
    pub(crate) const ZERO: Self = Self([0; N]);
    pub(crate) const ONE: Self = {
        let mut w = [0; N];
        w[0] = 1;
        Self(w)
    };

    /// Lê big-endian; `None` se não couber em `N` palavras.
    pub(crate) fn from_be(b: &[u8]) -> Option<Self> {
        let mut w = [0u64; N];
        for (i, &byte) in b.iter().rev().enumerate() {
            if i / 8 >= N {
                if byte != 0 {
                    return None;
                }
                continue;
            }
            w[i / 8] |= u64::from(byte) << (8 * (i % 8));
        }
        Some(Self(w))
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    pub(crate) fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    /// Número de bits significativos.
    pub(crate) fn bits(&self) -> usize {
        for i in (0..N).rev() {
            if self.0[i] != 0 {
                return 64 * i + 64 - self.0[i].leading_zeros() as usize;
            }
        }
        0
    }

    pub(crate) fn cmp(&self, o: &Self) -> Ordering {
        for i in (0..N).rev() {
            match self.0[i].cmp(&o.0[i]) {
                Ordering::Equal => {}
                r => return r,
            }
        }
        Ordering::Equal
    }

    fn add(&self, o: &Self) -> (Self, bool) {
        let mut r = [0u64; N];
        let mut c = false;
        for i in 0..N {
            let (s1, c1) = self.0[i].overflowing_add(o.0[i]);
            let (s2, c2) = s1.overflowing_add(u64::from(c));
            r[i] = s2;
            c = c1 | c2;
        }
        (Self(r), c)
    }

    pub(crate) fn sub(&self, o: &Self) -> (Self, bool) {
        let mut r = [0u64; N];
        let mut b = false;
        for i in 0..N {
            let (d1, b1) = self.0[i].overflowing_sub(o.0[i]);
            let (d2, b2) = d1.overflowing_sub(u64::from(b));
            r[i] = d2;
            b = b1 | b2;
        }
        (Self(r), b)
    }
}

/// Módulo ímpar com as constantes de Montgomery (R = 2^(64N)).
pub(crate) struct Modulus<const N: usize> {
    pub(crate) m: Uint<N>,
    /// -m⁻¹ mod 2^64.
    inv: u64,
    /// R² mod m.
    r2: Uint<N>,
}

impl<const N: usize> Modulus<N> {
    /// `None` se `m` for par ou menor que 3.
    pub(crate) fn new(m: Uint<N>) -> Option<Self> {
        if m.0[0] & 1 == 0 || m.bits() < 2 {
            return None;
        }
        // Newton: cada passo dobra os bits certos de m0⁻¹ (1 → 64).
        let mut x = 1u64;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(m.0[0].wrapping_mul(x)));
        }
        let mut md = Self {
            m,
            inv: x.wrapping_neg(),
            r2: Uint::ZERO,
        };
        // 1 dobrado 2·64·N vezes mod m dá R² mod m.
        let mut r = Uint::ONE;
        for _ in 0..128 * N {
            r = md.add(&r, &r);
        }
        md.r2 = r;
        Some(md)
    }

    /// `a + b mod m`, com `a, b < m`.
    pub(crate) fn add(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        let (s, c) = a.add(b);
        let (d, bw) = s.sub(&self.m);
        if c || !bw { d } else { s }
    }

    /// `a - b mod m`, com `a, b < m`.
    pub(crate) fn sub(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        let (d, bw) = a.sub(b);
        if bw { d.add(&self.m).0 } else { d }
    }

    /// Produto de Montgomery `a·b·R⁻¹ mod m` (CIOS), com `a, b < m`.
    pub(crate) fn mul(&self, a: &Uint<N>, b: &Uint<N>) -> Uint<N> {
        let m = &self.m.0;
        let mut t = [0u64; N];
        let (mut t_n, mut t_n1);
        t_n = 0u64;
        for i in 0..N {
            let mut c = 0u64;
            for j in 0..N {
                let x = u128::from(t[j]) + u128::from(a.0[j]) * u128::from(b.0[i]) + u128::from(c);
                t[j] = x as u64;
                c = (x >> 64) as u64;
            }
            let x = u128::from(t_n) + u128::from(c);
            t_n = x as u64;
            t_n1 = (x >> 64) as u64;
            let q = t[0].wrapping_mul(self.inv);
            let x = u128::from(t[0]) + u128::from(q) * u128::from(m[0]);
            let mut c = (x >> 64) as u64;
            for j in 1..N {
                let x = u128::from(t[j]) + u128::from(q) * u128::from(m[j]) + u128::from(c);
                t[j - 1] = x as u64;
                c = (x >> 64) as u64;
            }
            let x = u128::from(t_n) + u128::from(c);
            t[N - 1] = x as u64;
            t_n = t_n1 + (x >> 64) as u64;
        }
        let r = Uint(t);
        let (d, bw) = r.sub(&self.m);
        if t_n != 0 || !bw { d } else { r }
    }

    /// Para a forma de Montgomery; `a < m`.
    pub(crate) fn to_mont(&self, a: &Uint<N>) -> Uint<N> {
        self.mul(a, &self.r2)
    }

    /// Da forma de Montgomery para o valor.
    pub(crate) fn leave_mont(&self, a: &Uint<N>) -> Uint<N> {
        self.mul(a, &Uint::ONE)
    }

    /// `base^e` com `base` e o resultado na forma de Montgomery.
    pub(crate) fn pow<const K: usize>(&self, base: &Uint<N>, e: &Uint<K>) -> Uint<N> {
        let mut r = self.to_mont(&Uint::ONE);
        for i in (0..e.bits()).rev() {
            r = self.mul(&r, &r);
            if e.bit(i) {
                r = self.mul(&r, base);
            }
        }
        r
    }

    /// Inverso por Fermat (`m` primo), na forma de Montgomery.
    pub(crate) fn inv_prime(&self, a: &Uint<N>) -> Uint<N> {
        let two = Uint::ONE.add(&Uint::ONE).0;
        self.pow(a, &self.m.sub(&two).0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contra `u128` com um módulo de uma palavra e um de duas.
    #[test]
    fn confere_com_u128() {
        let m1 = Modulus::<1>::new(Uint([0xffff_ffff_ffff_ffc5])).unwrap();
        let m2 = Modulus::<2>::new(Uint([0xffff_ffff_ffff_ff61, 0x7fff])).unwrap();
        let mv2 = 0x7fff_u128 << 64 | 0xffff_ffff_ffff_ff61;
        let mut x = 0x1234_5678_9abc_def1u64;
        for _ in 0..200 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let (a, b) = (x % m1.m.0[0], x.rotate_left(17) % m1.m.0[0]);
            let p = m1.leave_mont(&m1.mul(&m1.to_mont(&Uint([a])), &m1.to_mont(&Uint([b]))));
            assert_eq!(
                u128::from(p.0[0]),
                u128::from(a) * u128::from(b) % u128::from(m1.m.0[0])
            );
            let (a2, b2) = (u128::from(x) << 40 | 7, u128::from(x.rotate_left(9)) << 30);
            let (a2, b2) = (a2 % mv2, b2 % mv2);
            let w = |v: u128| Uint([v as u64, (v >> 64) as u64]);
            let p = m2.leave_mont(&m2.mul(&m2.to_mont(&w(a2)), &m2.to_mont(&w(b2))));
            // a2·b2 mod m2 por somas e dobras (u128 não cabe o produto).
            let mut esp = 0u128;
            for i in (0..128).rev() {
                esp = (esp * 2) % mv2;
                if (b2 >> i) & 1 == 1 {
                    esp = (esp + a2) % mv2;
                }
            }
            assert_eq!(p, w(esp));
            assert_eq!(m2.add(&w(a2), &w(b2)), w((a2 + b2) % mv2));
            assert_eq!(m2.sub(&w(a2), &w(b2)), w((a2 + mv2 - b2) % mv2));
        }
        // 3^(p-2)·3 = 1 mod p.
        let tres = m1.to_mont(&Uint([3]));
        assert_eq!(
            m1.leave_mont(&m1.mul(&m1.inv_prime(&tres), &tres)),
            Uint::ONE
        );
    }

    #[test]
    fn bytes() {
        let u = Uint::<2>::from_be(&[0, 0, 1, 2, 3]).unwrap();
        assert_eq!(u.0, [0x01_0203, 0]);
        assert!(Uint::<1>::from_be(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).is_none());
        assert!(Uint::<1>::from_be(&[0, 0, 0, 0, 0, 0, 0, 0, 9]).is_some());
        assert_eq!(u.bits(), 17);
    }
}
