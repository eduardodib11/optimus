//! ECDSA sobre a P-256 (FIPS 186-5, SEC 1), **só verificação** (ADR 0071):
//! certificados e o `CertificateVerify` do TLS 1.3.
//!
//! Tudo aqui é público (chave, assinatura, resumo), então não há exigência
//! de tempo constante e a aritmética usa o `bignum` genérico. Os pontos
//! ficam em coordenadas projetivas com a fórmula de soma completa de
//! Renes, Costello e Batina (2016, algoritmo 4, a = -3): sem casos
//! especiais para dobrar, para o infinito ou para `P = -Q`.

#![allow(clippy::many_single_char_names, reason = "notação da FIPS 186-5")]
#![allow(clippy::similar_names, reason = "nomes da fórmula de RCB")]

use crate::bignum::{Modulus, Uint};
use crate::sha256;

const P: Uint<4> = Uint([
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);
const N: Uint<4> = Uint([
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
]);
const B: Uint<4> = Uint([
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
]);
const GX: Uint<4> = Uint([
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
]);
const GY: Uint<4> = Uint([
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
]);

/// Bytes da chave pública não comprimida (`04 ‖ X ‖ Y`).
pub const PUBLIC_LEN: usize = 65;

type Fp = Uint<4>;

#[derive(Clone, Copy)]
struct Point {
    x: Fp,
    y: Fp,
    z: Fp,
}

/// Corpo mod p e o `b` da curva na forma de Montgomery.
struct Curve {
    fp: Modulus<4>,
    b: Fp,
}

impl Curve {
    fn new() -> Option<Self> {
        let fp = Modulus::new(P)?;
        let b = fp.to_mont(&B);
        Some(Self { fp, b })
    }

    /// Ponto afim `(x, y)` (valores, não Montgomery) se estiver na curva.
    fn point(&self, x: &Fp, y: &Fp) -> Option<Point> {
        if x.cmp(&P).is_ge() || y.cmp(&P).is_ge() {
            return None;
        }
        let f = &self.fp;
        let (x, y) = (f.to_mont(x), f.to_mont(y));
        // y² = x³ - 3x + b
        let x3 = f.mul(&f.mul(&x, &x), &x);
        let tres_x = f.add(&f.add(&x, &x), &x);
        let direita = f.add(&f.sub(&x3, &tres_x), &self.b);
        if f.mul(&y, &y) != direita {
            return None;
        }
        Some(Point {
            x,
            y,
            z: f.to_mont(&Uint::ONE),
        })
    }

    fn identity(&self) -> Point {
        Point {
            x: Uint::ZERO,
            y: self.fp.to_mont(&Uint::ONE),
            z: Uint::ZERO,
        }
    }

    /// Soma completa (RCB 2016, algoritmo 4).
    fn add(&self, p: &Point, q: &Point) -> Point {
        let f = &self.fp;
        let (add, sub, mul) = (
            |a: &Fp, b: &Fp| f.add(a, b),
            |a: &Fp, b: &Fp| f.sub(a, b),
            |a: &Fp, b: &Fp| f.mul(a, b),
        );
        let triplo = |a: &Fp| add(&add(a, a), a);
        let xx = mul(&p.x, &q.x);
        let yy = mul(&p.y, &q.y);
        let zz = mul(&p.z, &q.z);
        let xy = sub(&mul(&add(&p.x, &p.y), &add(&q.x, &q.y)), &add(&xx, &yy));
        let yz = sub(&mul(&add(&p.y, &p.z), &add(&q.y, &q.z)), &add(&yy, &zz));
        let xz = sub(&mul(&add(&p.x, &p.z), &add(&q.x, &q.z)), &add(&xx, &zz));
        let bzz3 = triplo(&sub(&xz, &mul(&self.b, &zz)));
        let yy_m = sub(&yy, &bzz3);
        let yy_p = add(&yy, &bzz3);
        let zz3 = triplo(&zz);
        let bxz3 = triplo(&sub(&mul(&self.b, &xz), &add(&zz3, &xx)));
        let xx3_m = sub(&triplo(&xx), &zz3);
        Point {
            x: sub(&mul(&yy_p, &xy), &mul(&yz, &bxz3)),
            y: add(&mul(&yy_p, &yy_m), &mul(&xx3_m, &bxz3)),
            z: add(&mul(&yy_m, &yz), &mul(&xy, &xx3_m)),
        }
    }

    /// `[u1]G + [u2]Q` (truque de Shamir) e a coordenada x afim do
    /// resultado; `None` no infinito.
    fn mul2_x(&self, u1: &Fp, g: &Point, u2: &Fp, q: &Point) -> Option<Fp> {
        let gq = self.add(g, q);
        let mut r = self.identity();
        for i in (0..256).rev() {
            r = self.add(&r, &r);
            match (u1.bit(i), u2.bit(i)) {
                (true, false) => r = self.add(&r, g),
                (false, true) => r = self.add(&r, q),
                (true, true) => r = self.add(&r, &gq),
                (false, false) => {}
            }
        }
        if r.z.is_zero() {
            return None;
        }
        let f = &self.fp;
        Some(f.leave_mont(&f.mul(&r.x, &f.inv_prime(&r.z))))
    }
}

/// `v mod n` para `v < 2n` (resumos e coordenadas, todos `< 2^256 < 2n`).
fn mod_n(v: &Uint<4>) -> Uint<4> {
    let (d, bw) = v.sub(&N);
    if bw { *v } else { d }
}

/// Verifica `(r, s)` sobre o resumo `hash` (de qualquer tamanho; só os 256
/// bits da esquerda contam, como manda a FIPS 186-5) com a chave pública
/// `pk` não comprimida.
#[must_use]
pub fn verify_prehashed(pk: &[u8], hash: &[u8], r: &[u8; 32], s: &[u8; 32]) -> bool {
    let (Some(r), Some(s)) = (Uint::from_be(r), Uint::from_be(s)) else {
        return false;
    };
    if r.is_zero() || s.is_zero() || r.cmp(&N).is_ge() || s.cmp(&N).is_ge() {
        return false;
    }
    let (Some(c), Some(fnn)) = (Curve::new(), Modulus::new(N)) else {
        return false;
    };
    let Some((&0x04, xy)) = pk.split_first() else {
        return false;
    };
    if xy.len() != 64 {
        return false;
    }
    let (Some(qx), Some(qy)) = (Uint::from_be(&xy[..32]), Uint::from_be(&xy[32..])) else {
        return false;
    };
    let (Some(q), Some(g)) = (c.point(&qx, &qy), c.point(&GX, &GY)) else {
        return false;
    };
    let Some(e) = Uint::from_be(&hash[..hash.len().min(32)]) else {
        return false;
    };
    let w = fnn.inv_prime(&fnn.to_mont(&s));
    // mul(valor, Montgomery) dá o produto como valor.
    let u1 = fnn.mul(&mod_n(&e), &w);
    let u2 = fnn.mul(&r, &w);
    c.mul2_x(&u1, &g, &u2, &q).is_some_and(|x| mod_n(&x) == r)
}

/// Um INTEGER DER positivo de até 32 bytes, em codificação mínima.
fn der_int(b: &[u8]) -> Option<([u8; 32], &[u8])> {
    let (&0x02, b) = b.split_first()? else {
        return None;
    };
    let (&len, b) = b.split_first()?;
    let len = usize::from(len);
    if len == 0 || len >= 0x80 || b.len() < len {
        return None;
    }
    let (v, resto) = b.split_at(len);
    if v[0] & 0x80 != 0 || (len > 1 && v[0] == 0 && v[1] & 0x80 == 0) {
        return None;
    }
    let v = if v[0] == 0 { &v[1..] } else { v };
    if v.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Some((out, resto))
}

/// Assinatura DER `SEQUENCE { INTEGER r, INTEGER s }`, estrita: forma
/// curta de tamanho, nada sobrando.
fn der_sig(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let (&0x30, b) = sig.split_first()? else {
        return None;
    };
    let (&len, b) = b.split_first()?;
    if len >= 0x80 || usize::from(len) != b.len() {
        return None;
    }
    let (r, b) = der_int(b)?;
    let (s, b) = der_int(b)?;
    b.is_empty().then_some((r, s))
}

/// Verifica a assinatura DER `sig` sobre o resumo `hash`.
#[must_use]
pub fn verify_der(pk: &[u8], hash: &[u8], sig: &[u8]) -> bool {
    der_sig(sig).is_some_and(|(r, s)| verify_prehashed(pk, hash, &r, &s))
}

/// `ecdsa_secp256r1_sha256` do TLS 1.3: SHA-256 de `msg` e assinatura DER.
#[must_use]
pub fn verify_sha256(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_der(pk, &sha256::hash(msg), sig)
}

#[cfg(test)]
mod tests;
