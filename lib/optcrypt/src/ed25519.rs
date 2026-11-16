//! Ed25519 (RFC 8032): assinatura e verificação (ADR 0071, item 2).
//!
//! Pontos em coordenadas estendidas com a fórmula de soma completa
//! (`add-2008-hwcd-3`, que também serve para dobrar), sobre o corpo de
//! `f25519`. A multiplicação por escalar é uma escada com troca
//! condicional: 256 passos fixos, sem ramo nem índice que dependa do
//! escalar. Escalares mod L são reduzidos bit a bit com subtração por
//! máscara.
//!
//! A verificação é a estrita da RFC: `S < L`, `A` com codificação
//! canônica, e `R` comparado byte a byte com a codificação de
//! `[S]B - [k]A` (sem o fator 8).

#![allow(clippy::many_single_char_names, reason = "notação da RFC 8032")]

use crate::f25519::Fe;
use crate::secret::{Secret, wipe};
use crate::sha512::Sha512;

/// Bytes da chave secreta (a semente).
pub const SECRET_LEN: usize = 32;
/// Bytes da chave pública.
pub const PUBLIC_LEN: usize = 32;
/// Bytes da assinatura.
pub const SIG_LEN: usize = 64;

/// d = -121665/121666.
const D2: Fe = Fe([
    0x6_9b94_26b2_f159,
    0x3_5050_762a_dd7a,
    0x3_cf44_c003_8052,
    0x6_738c_c740_7977,
    0x2_406d_9dc5_6dff,
]);
const D: Fe = Fe([
    0x3_4dca_1359_78a3,
    0x1_a828_3b15_6ebd,
    0x5_e7a2_6001_c029,
    0x7_39c6_63a0_3cbb,
    0x5_2036_cee2_b6ff,
]);
const SQRT_M1: Fe = Fe([
    0x6_1b27_4a0e_a0b0,
    0x0_d5a5_fc8f_189d,
    0x7_ef5e_9cbd_0c60,
    0x7_8595_a680_4c9e,
    0x2_b832_4804_fc1d,
]);
/// Ponto base B (y = 4/5, x par).
const B: Point = Point {
    x: Fe([
        0x6_2d60_8f25_d51a,
        0x4_12a4_b4f6_592a,
        0x7_5b71_71a4_b31d,
        0x1_ff60_5271_18fe,
        0x2_1693_6d3c_d6e5,
    ]),
    y: Fe([
        0x6_6666_6666_6658,
        0x4_cccc_cccc_cccc,
        0x1_9999_9999_9999,
        0x3_3333_3333_3333,
        0x6_6666_6666_6666,
    ]),
    z: Fe::ONE,
    t: Fe([
        0x6_8ab3_a5b7_dda3,
        0x0_0eea_2a5e_adbb,
        0x2_af8d_f483_c27e,
        0x3_32b3_7527_4732,
        0x6_7875_f0fd_78b7,
    ]),
};

/// L = 2^252 + 27742317777372353535851937790883648493, em palavras LE.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl Point {
    const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Soma completa (`add-2008-hwcd-3`, a = -1): vale para dobrar também.
    fn add(&self, o: &Self) -> Self {
        let a = self.y.sub(&self.x).mul(&o.y.sub(&o.x));
        let b = self.y.add(&self.x).mul(&o.y.add(&o.x));
        let c = self.t.mul(&D2).mul(&o.t);
        let d = self.z.add(&self.z).mul(&o.z);
        let (e, f, g, h) = (b.sub(&a), d.sub(&c), d.add(&c), b.add(&a));
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    fn neg(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    fn cswap(a: &mut Self, b: &mut Self, bit: u64) {
        Fe::cswap(&mut a.x, &mut b.x, bit);
        Fe::cswap(&mut a.y, &mut b.y, bit);
        Fe::cswap(&mut a.z, &mut b.z, bit);
        Fe::cswap(&mut a.t, &mut b.t, bit);
    }

    /// `[k]self` para `k` de 256 bits LE, em tempo constante.
    fn mul(&self, k: &[u8; 32]) -> Self {
        let (mut r0, mut r1) = (Self::IDENTITY, *self);
        for i in (0..256).rev() {
            let bit = u64::from((k[i >> 3] >> (i & 7)) & 1);
            Self::cswap(&mut r0, &mut r1, bit);
            r1 = r0.add(&r1);
            r0 = r0.add(&r0);
            Self::cswap(&mut r0, &mut r1, bit);
        }
        r0
    }

    fn encode(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let mut s = self.y.mul(&zi).to_bytes();
        s[31] |= self.x.mul(&zi).is_negative() << 7;
        s
    }

    /// Decodificação da RFC 8032, seção 5.1.3; `None` se `y >= p`, se não
    /// houver raiz ou se pedir `x = 0` negativo.
    fn decode(s: &[u8; 32]) -> Option<Self> {
        let sinal = s[31] >> 7;
        let mut yb = *s;
        yb[31] &= 0x7f;
        let y = Fe::from_bytes(&yb);
        if y.to_bytes() != yb {
            return None;
        }
        let y2 = y.square();
        let u = y2.sub(&Fe::ONE);
        let v = y2.mul(&D).add(&Fe::ONE);
        let v3 = v.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v3.square().mul(&v)).pow22523());
        let vx2 = v.mul(&x.square());
        if !vx2.ct_eq(&u) {
            if vx2.ct_eq(&u.neg()) {
                x = x.mul(&SQRT_M1);
            } else {
                return None;
            }
        }
        if x.is_negative() != sinal {
            if x.ct_eq(&Fe::ZERO) {
                return None;
            }
            x = x.neg();
        }
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }
}

// --- Escalares mod L ----------------------------------------------------

/// `x mod L` para `x` de 512 bits (palavras LE), bit a bit: `r < L` antes
/// de cada passo, `2r + 1 < 2L < 2^254` cabe em quatro palavras, e uma
/// subtração por máscara volta a `r < L`.
fn reduce512(x: &[u64; 8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in (0..512).rev() {
        let bit = (x[i / 64] >> (i % 64)) & 1;
        for j in (1..4).rev() {
            r[j] = (r[j] << 1) | (r[j - 1] >> 63);
        }
        r[0] = (r[0] << 1) | bit;
        let mut t = [0u64; 4];
        let mut borrow = 0u64;
        for j in 0..4 {
            let (d1, b1) = r[j].overflowing_sub(L[j]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            t[j] = d2;
            borrow = u64::from(b1 | b2);
        }
        // borrow = 1: r < L, fica r; borrow = 0: fica t.
        let mask = borrow.wrapping_sub(1);
        for j in 0..4 {
            r[j] = (t[j] & mask) | (r[j] & !mask);
        }
    }
    r
}

fn words(b: &[u8]) -> [u64; 8] {
    let mut w = [0u64; 8];
    for (wi, c) in w.iter_mut().zip(b.chunks(8)) {
        let mut x = [0u8; 8];
        x[..c.len()].copy_from_slice(c);
        *wi = u64::from_le_bytes(x);
    }
    w
}

fn to_bytes(s: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (c, w) in out.chunks_exact_mut(8).zip(s) {
        c.copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// `(k·a + r) mod L`, com `k`, `a` e `r` já menores que L.
#[allow(clippy::cast_possible_truncation, reason = "metade baixa do produto")]
fn mul_add(k: &[u64; 4], a: &[u64; 4], r: &[u64; 4]) -> [u64; 4] {
    let mut w = [0u64; 8];
    w[..4].copy_from_slice(r);
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = u128::from(k[i]) * u128::from(a[j]) + u128::from(w[i + j]) + carry;
            w[i + j] = t as u64;
            carry = t >> 64;
        }
        let mut idx = i + 4;
        while carry != 0 && idx < 8 {
            let t = u128::from(w[idx]) + carry;
            w[idx] = t as u64;
            carry = t >> 64;
            idx += 1;
        }
    }
    let out = reduce512(&w);
    w.fill(0);
    core::hint::black_box(&mut w);
    out
}

/// SHA-512 das partes, reduzido mod L.
fn hash_mod_l(partes: &[&[u8]]) -> [u64; 4] {
    let mut h = Sha512::new();
    for p in partes {
        h.update(p);
    }
    let mut d = h.finalize();
    let r = reduce512(&words(&d));
    wipe(&mut d);
    r
}

// --- API -----------------------------------------------------------------

/// Escalar ajustado `a` e o prefixo da semente (RFC 8032, seção 5.1.5).
fn expand(sk: &Secret<SECRET_LEN>) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha512::new();
    h.update(sk.expose());
    let mut d = h.finalize();
    let (mut a, mut prefixo) = ([0u8; 32], [0u8; 32]);
    a.copy_from_slice(&d[..32]);
    prefixo.copy_from_slice(&d[32..]);
    wipe(&mut d);
    a[0] &= 0xf8;
    a[31] &= 0x7f;
    a[31] |= 0x40;
    (a, prefixo)
}

/// Chave pública da semente `sk`.
#[must_use]
pub fn public_key(sk: &Secret<SECRET_LEN>) -> [u8; PUBLIC_LEN] {
    let (mut a, mut prefixo) = expand(sk);
    let pk = B.mul(&a).encode();
    wipe(&mut a);
    wipe(&mut prefixo);
    pk
}

/// Assina `msg` com a semente `sk` (determinística, RFC 8032 5.1.6).
#[must_use]
pub fn sign(sk: &Secret<SECRET_LEN>, msg: &[u8]) -> [u8; SIG_LEN] {
    let (mut a, mut prefixo) = expand(sk);
    let pk = B.mul(&a).encode();
    let mut r = hash_mod_l(&[&prefixo, msg]);
    let mut rb = to_bytes(&r);
    let big_r = B.mul(&rb).encode();
    let k = hash_mod_l(&[&big_r, &pk, msg]);
    let mut a_l = reduce512(&words(&a));
    let s = mul_add(&k, &a_l, &r);
    let mut sig = [0u8; SIG_LEN];
    sig[..32].copy_from_slice(&big_r);
    sig[32..].copy_from_slice(&to_bytes(&s));
    for x in [&mut a, &mut prefixo, &mut rb] {
        wipe(x);
    }
    r.fill(0);
    a_l.fill(0);
    core::hint::black_box((&mut r, &mut a_l));
    sig
}

/// Verifica a assinatura `sig` de `msg` pela chave `pk` (dados públicos;
/// a ordem das recusas não vaza nada).
#[must_use]
pub fn verify(pk: &[u8; PUBLIC_LEN], msg: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    let Some(a) = Point::decode(pk) else {
        return false;
    };
    let (rb, sb) = sig.split_at(32);
    let s = words(sb);
    // S < L, comparado da palavra mais alta para a mais baixa.
    let menor = (0..4)
        .rev()
        .find(|&i| s[i] != L[i])
        .is_some_and(|i| s[i] < L[i]);
    if !menor {
        return false;
    }
    let k = to_bytes(&hash_mod_l(&[rb, pk, msg]));
    let mut s_b = [0u8; 32];
    s_b.copy_from_slice(sb);
    let r2 = B.mul(&s_b).add(&a.neg().mul(&k));
    r2.encode()[..] == rb[..]
}

#[cfg(test)]
mod tests;
