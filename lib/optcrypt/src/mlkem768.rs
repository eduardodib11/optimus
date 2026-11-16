//! ML-KEM-768 (FIPS 203): encapsulamento de chave por reticulados, a
//! metade pós-quântica do grupo híbrido `X25519MLKEM768` do TLS (ADR 0070).
//!
//! Tempo constante no que toca segredos: a aritmética mod q usa redução de
//! Barrett com máscaras (sem `%` nem `/`, que podem virar `div`), a
//! amostragem binomial só soma bits e a rejeição implícita escolhe a chave
//! por máscara. Só a amostragem da matriz (pública, vinda de ρ) e a
//! checagem da chave de encapsulamento (pública) têm ramos.
//!
//! As funções `*_internal` recebem a aleatoriedade de fora (FIPS 203,
//! seção 6), como pedem os vetores; quem usa sorteia `d`, `z` e `m` no
//! `drbg`.

#![allow(clippy::many_single_char_names, reason = "notação da FIPS 203")]

use crate::secret::{Secret, ct_eq, wipe};
use crate::sha3::{Shake128, Shake256, sha3_256, sha3_512};

const N: usize = 256;
const Q: u32 = 3329;
const K: usize = 3;
const DU: u32 = 10;
const DV: u32 = 4;
/// Bytes de um polinômio com 12 bits por coeficiente.
const POLY12: usize = 384;
/// Bytes de `u` comprimido (`c1`).
const C1_LEN: usize = 32 * DU as usize * K;
const PKE_DK_LEN: usize = POLY12 * K;

/// Bytes da chave de encapsulamento (pública).
pub const EK_LEN: usize = POLY12 * K + 32;
/// Bytes da chave de desencapsulamento (secreta).
pub const DK_LEN: usize = 2 * POLY12 * K + 96;
/// Bytes do texto cifrado.
pub const CT_LEN: usize = C1_LEN + 32 * DV as usize;
/// Bytes do segredo compartilhado.
pub const SS_LEN: usize = 32;

type Poly = [u16; N];

/// Erros das checagens de entrada (FIPS 203, seção 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Chave de encapsulamento com coeficiente fora de `[0, q)`, ou chave
    /// de desencapsulamento cujo hash de `ek` não confere.
    InvalidKey,
}

// --- Aritmética mod q ---------------------------------------------------

/// `r mod q` para `r < 2q`, sem ramo.
#[allow(clippy::cast_possible_truncation, reason = "resultado < q")]
fn csub(r: u32) -> u16 {
    let t = r.wrapping_sub(Q);
    t.wrapping_add(Q & 0u32.wrapping_sub(t >> 31)) as u16
}

/// Barrett: `floor(x / q)` exato para qualquer `x` de 32 bits, sem ramo.
#[allow(clippy::cast_possible_truncation, reason = "quociente < 2^32")]
fn div_q(x: u32) -> u32 {
    let t = ((u64::from(x) * 1_290_167) >> 32) as u32;
    let r = x - t * Q;
    t + ((Q - 1).wrapping_sub(r) >> 31)
}

#[allow(clippy::cast_possible_truncation, reason = "resto < q")]
fn reduce(x: u32) -> u16 {
    (x - div_q(x) * Q) as u16
}

fn add(a: u16, b: u16) -> u16 {
    csub(u32::from(a) + u32::from(b))
}

fn sub(a: u16, b: u16) -> u16 {
    csub(u32::from(a) + Q - u32::from(b))
}

fn mul(a: u16, b: u16) -> u16 {
    reduce(u32::from(a) * u32::from(b))
}

// --- NTT ----------------------------------------------------------------

const fn bitrev7(i: usize) -> usize {
    let mut r = 0;
    let mut k = 0;
    while k < 7 {
        r |= ((i >> k) & 1) << (6 - k);
        k += 1;
    }
    r
}

#[allow(clippy::cast_possible_truncation, reason = "resultado < q")]
const fn pow17(e: usize) -> u16 {
    let mut r = 1u32;
    let mut k = 0;
    while k < e {
        r = r * 17 % Q;
        k += 1;
    }
    r as u16
}

/// `ζ^BitRev7(i)` com ζ = 17 (passos da NTT).
const ZETAS: [u16; 128] = {
    let mut z = [0; 128];
    let mut i = 0;
    while i < 128 {
        z[i] = pow17(bitrev7(i));
        i += 1;
    }
    z
};

/// `ζ^(2·BitRev7(i) + 1)` (produto das bases de grau 1).
const GAMMAS: [u16; 128] = {
    let mut z = [0; 128];
    let mut i = 0;
    while i < 128 {
        z[i] = pow17(2 * bitrev7(i) + 1);
        i += 1;
    }
    z
};

/// Algoritmo 9.
fn ntt(f: &mut Poly) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        for start in (0..N).step_by(2 * len) {
            let z = ZETAS[i];
            i += 1;
            for j in start..start + len {
                let t = mul(z, f[j + len]);
                f[j + len] = sub(f[j], t);
                f[j] = add(f[j], t);
            }
        }
        len /= 2;
    }
}

/// Algoritmo 10 (inclui o fator 128⁻¹ = 3303).
fn ntt_inv(f: &mut Poly) {
    let mut i = 127;
    let mut len = 2;
    while len <= 128 {
        for start in (0..N).step_by(2 * len) {
            let z = ZETAS[i];
            i -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = add(t, f[j + len]);
                f[j + len] = mul(z, sub(f[j + len], t));
            }
        }
        len *= 2;
    }
    for x in f.iter_mut() {
        *x = mul(*x, 3303);
    }
}

/// `acc += f ∘ g` no domínio da NTT (algoritmos 11 e 12).
fn mul_acc(acc: &mut Poly, f: &Poly, g: &Poly) {
    for i in 0..128 {
        let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);
        let c0 = add(mul(a0, b0), mul(mul(a1, b1), GAMMAS[i]));
        let c1 = add(mul(a0, b1), mul(a1, b0));
        acc[2 * i] = add(acc[2 * i], c0);
        acc[2 * i + 1] = add(acc[2 * i + 1], c1);
    }
}

fn add_poly(f: &mut Poly, g: &Poly) {
    for (x, y) in f.iter_mut().zip(g) {
        *x = add(*x, *y);
    }
}

fn wipe_polys(p: &mut [Poly]) {
    for f in p.iter_mut() {
        f.fill(0);
    }
    core::hint::black_box(p);
}

fn wipe_poly(p: &mut Poly) {
    wipe_polys(core::slice::from_mut(p));
}

// --- Codificação e compressão (algoritmos 5 e 6, seção 4.2.1) ------------

#[allow(clippy::cast_possible_truncation, reason = "byte baixo do acumulador")]
fn encode(f: &Poly, d: u32, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 32 * d as usize);
    let (mut acc, mut bits, mut j) = (0u32, 0u32, 0);
    for &x in f {
        acc |= u32::from(x) << bits;
        bits += d;
        while bits >= 8 {
            out[j] = acc as u8;
            acc >>= 8;
            bits -= 8;
            j += 1;
        }
    }
}

/// Valores crus de `d` bits; quem usa reduz mod q quando `d = 12`.
#[allow(clippy::cast_possible_truncation, reason = "valores de até 12 bits")]
fn decode(b: &[u8], d: u32) -> Poly {
    let mut f = [0u16; N];
    let (mut acc, mut bits, mut i) = (0u32, 0u32, 0);
    for &byte in b {
        acc |= u32::from(byte) << bits;
        bits += 8;
        while bits >= d && i < N {
            f[i] = (acc & ((1 << d) - 1)) as u16;
            acc >>= d;
            bits -= d;
            i += 1;
        }
    }
    f
}

fn decode12(b: &[u8]) -> Poly {
    // 12 bits dão no máximo 4095 < 2q: um `csub` reduz.
    decode(b, 12).map(|x| csub(u32::from(x)))
}

#[allow(clippy::cast_possible_truncation, reason = "d ≤ 11 bits")]
fn compress(f: &mut Poly, d: u32) {
    for x in f.iter_mut() {
        *x = (div_q((u32::from(*x) << d) + Q / 2) & ((1 << d) - 1)) as u16;
    }
}

#[allow(clippy::cast_possible_truncation, reason = "resultado < q")]
fn decompress(f: &mut Poly, d: u32) {
    for x in f.iter_mut() {
        *x = ((u32::from(*x) * Q + (1 << (d - 1))) >> d) as u16;
    }
}

// --- Amostragem (algoritmos 7 e 8) ---------------------------------------

/// Coeficiente da matriz Â a partir de `ρ ‖ a ‖ b`. Rejeição sobre dados
/// públicos.
fn sample_ntt(rho: &[u8], a: u8, b: u8) -> Poly {
    let mut x = Shake128::new();
    x.update(rho);
    x.update(&[a, b]);
    let mut f = [0u16; N];
    let mut j = 0;
    let mut buf = [0u8; 168];
    while j < N {
        x.squeeze(&mut buf);
        for c in buf.chunks_exact(3) {
            let d1 = u16::from(c[0]) | (u16::from(c[1] & 0xf) << 8);
            let d2 = u16::from(c[1] >> 4) | (u16::from(c[2]) << 4);
            for d in [d1, d2] {
                if u32::from(d) < Q && j < N {
                    f[j] = d;
                    j += 1;
                }
            }
        }
    }
    f
}

/// `SamplePolyCBD_2(PRF_2(s, n))`: cada coeficiente é a diferença de duas
/// somas de dois bits.
fn cbd2(s: &[u8], n: u8) -> Poly {
    let mut b = [0u8; 128];
    shake256_into(&[s, &[n]], &mut b);
    let mut f = [0u16; N];
    for (i, &byte) in b.iter().enumerate() {
        for h in 0..2 {
            let v = byte >> (4 * h);
            let x = (v & 1) + ((v >> 1) & 1);
            let y = ((v >> 2) & 1) + ((v >> 3) & 1);
            f[2 * i + h] = csub(u32::from(x) + Q - u32::from(y));
        }
    }
    wipe(&mut b);
    f
}

fn shake256_into(data: &[&[u8]], out: &mut [u8]) {
    let mut x = Shake256::new();
    for d in data {
        x.update(d);
    }
    x.squeeze(out);
}

// --- K-PKE (algoritmos 13 a 15) ------------------------------------------

#[allow(clippy::cast_possible_truncation, reason = "índices < K")]
fn pke_keygen(d: &[u8; 32], ek: &mut [u8; EK_LEN], dk: &mut [u8]) {
    let mut gin = [0u8; 33];
    gin[..32].copy_from_slice(d);
    gin[32] = K as u8;
    let mut g = sha3_512(&gin);
    wipe(&mut gin);
    let (rho, sigma) = g.split_at(32);
    let mut s = [[0u16; N]; K];
    let mut e = [[0u16; N]; K];
    for i in 0..K {
        s[i] = cbd2(sigma, i as u8);
        e[i] = cbd2(sigma, (K + i) as u8);
        ntt(&mut s[i]);
        ntt(&mut e[i]);
    }
    for i in 0..K {
        let mut t = e[i];
        for (j, sj) in s.iter().enumerate() {
            mul_acc(&mut t, &sample_ntt(rho, j as u8, i as u8), sj);
        }
        encode(&t, 12, &mut ek[POLY12 * i..POLY12 * (i + 1)]);
        encode(&s[i], 12, &mut dk[POLY12 * i..POLY12 * (i + 1)]);
    }
    ek[POLY12 * K..].copy_from_slice(rho);
    wipe_polys(&mut s);
    wipe_polys(&mut e);
    wipe(&mut g);
}

#[allow(clippy::cast_possible_truncation, reason = "índices < K")]
fn pke_encrypt(ek: &[u8; EK_LEN], m: &[u8; 32], r: &[u8], c: &mut [u8; CT_LEN]) {
    let rho = &ek[POLY12 * K..];
    let mut y = [[0u16; N]; K];
    for (i, yi) in y.iter_mut().enumerate() {
        *yi = cbd2(r, i as u8);
        ntt(yi);
    }
    for i in 0..K {
        let mut u = [0u16; N];
        for (j, yj) in y.iter().enumerate() {
            mul_acc(&mut u, &sample_ntt(rho, i as u8, j as u8), yj);
        }
        ntt_inv(&mut u);
        add_poly(&mut u, &cbd2(r, (K + i) as u8));
        compress(&mut u, DU);
        encode(&u, DU, &mut c[320 * i..320 * (i + 1)]);
    }
    let mut v = [0u16; N];
    for (i, yi) in y.iter().enumerate() {
        mul_acc(&mut v, &decode12(&ek[POLY12 * i..POLY12 * (i + 1)]), yi);
    }
    ntt_inv(&mut v);
    let mut mu = decode(m, 1);
    decompress(&mut mu, 1);
    let mut e2 = cbd2(r, 2 * K as u8);
    add_poly(&mut v, &e2);
    add_poly(&mut v, &mu);
    compress(&mut v, DV);
    encode(&v, DV, &mut c[C1_LEN..]);
    wipe_polys(&mut y);
    wipe_poly(&mut v);
    wipe_poly(&mut mu);
    wipe_poly(&mut e2);
}

fn pke_decrypt(dk: &[u8], c: &[u8; CT_LEN]) -> [u8; 32] {
    let mut w = [0u16; N];
    for i in 0..K {
        let mut u = decode(&c[320 * i..320 * (i + 1)], DU);
        decompress(&mut u, DU);
        ntt(&mut u);
        let mut s = decode12(&dk[POLY12 * i..POLY12 * (i + 1)]);
        mul_acc(&mut w, &s, &u);
        wipe_poly(&mut s);
    }
    ntt_inv(&mut w);
    let mut v = decode(&c[C1_LEN..], DV);
    decompress(&mut v, DV);
    for (x, y) in v.iter_mut().zip(&w) {
        *x = sub(*x, *y);
    }
    compress(&mut v, 1);
    let mut m = [0u8; 32];
    encode(&v, 1, &mut m);
    wipe_poly(&mut v);
    wipe_poly(&mut w);
    m
}

// --- ML-KEM (algoritmos 16 a 18) -----------------------------------------

/// Gera o par a partir das sementes `d` e `z` (algoritmo 16). Devolve
/// `(ek, dk)`.
#[must_use]
pub fn keygen_internal(d: &[u8; 32], z: &[u8; 32]) -> ([u8; EK_LEN], Secret<DK_LEN>) {
    let mut ek = [0u8; EK_LEN];
    let mut dk = Secret::<DK_LEN>::zeroed();
    let b = dk.expose_mut();
    pke_keygen(d, &mut ek, &mut b[..PKE_DK_LEN]);
    b[PKE_DK_LEN..PKE_DK_LEN + EK_LEN].copy_from_slice(&ek);
    b[DK_LEN - 64..DK_LEN - 32].copy_from_slice(&sha3_256(&ek));
    b[DK_LEN - 32..].copy_from_slice(z);
    (ek, dk)
}

/// Gera o par com 64 bytes aleatórios (`d ‖ z`) do chamador.
#[must_use]
pub fn keygen(seed: &Secret<64>) -> ([u8; EK_LEN], Secret<DK_LEN>) {
    let (d, z) = seed.expose().split_at(32);
    let (Ok(d), Ok(z)) = (d.try_into(), z.try_into()) else {
        unreachable!("64 = 32 + 32")
    };
    keygen_internal(d, z)
}

/// Checagem de módulo da chave de encapsulamento (seção 7.2): todo
/// coeficiente de 12 bits precisa estar em `[0, q)`.
fn check_ek(ek: &[u8; EK_LEN]) -> Result<(), Error> {
    for i in 0..K {
        let t = decode(&ek[POLY12 * i..POLY12 * (i + 1)], 12);
        if t.iter().any(|&x| u32::from(x) >= Q) {
            return Err(Error::InvalidKey);
        }
    }
    Ok(())
}

/// Encapsula com a mensagem `m` (algoritmo 17). Devolve `(c, K)`.
///
/// # Errors
/// [`Error::InvalidKey`] se `ek` falhar na checagem de módulo.
pub fn encaps_internal(
    ek: &[u8; EK_LEN],
    m: &[u8; 32],
) -> Result<([u8; CT_LEN], Secret<SS_LEN>), Error> {
    check_ek(ek)?;
    let mut gin = [0u8; 64];
    gin[..32].copy_from_slice(m);
    gin[32..].copy_from_slice(&sha3_256(ek));
    let mut g = sha3_512(&gin);
    wipe(&mut gin);
    let mut c = [0u8; CT_LEN];
    pke_encrypt(ek, m, &g[32..], &mut c);
    let mut k = [0u8; SS_LEN];
    k.copy_from_slice(&g[..32]);
    wipe(&mut g);
    Ok((c, Secret::take(&mut k)))
}

/// Encapsula com 32 bytes aleatórios `m` do chamador.
///
/// # Errors
/// [`Error::InvalidKey`] se `ek` falhar na checagem de módulo.
pub fn encaps(ek: &[u8; EK_LEN], m: &Secret<32>) -> Result<([u8; CT_LEN], Secret<SS_LEN>), Error> {
    encaps_internal(ek, m.expose())
}

/// Desencapsula (algoritmo 18) com rejeição implícita: um texto cifrado
/// adulterado dá uma chave pseudoaleatória `J(z ‖ c)`, sem erro.
///
/// # Errors
/// [`Error::InvalidKey`] se o hash de `ek` guardado em `dk` não conferir
/// (checagem da seção 7.3).
pub fn decaps(dk: &Secret<DK_LEN>, c: &[u8; CT_LEN]) -> Result<Secret<SS_LEN>, Error> {
    let dk = dk.expose();
    let ek: &[u8; EK_LEN] = dk[PKE_DK_LEN..PKE_DK_LEN + EK_LEN]
        .try_into()
        .map_err(|_| Error::InvalidKey)?;
    let h = &dk[DK_LEN - 64..DK_LEN - 32];
    let z = &dk[DK_LEN - 32..];
    if !ct_eq(&sha3_256(ek), h) {
        return Err(Error::InvalidKey);
    }
    let mut m = pke_decrypt(&dk[..PKE_DK_LEN], c);
    let mut gin = [0u8; 64];
    gin[..32].copy_from_slice(&m);
    gin[32..].copy_from_slice(h);
    let mut g = sha3_512(&gin);
    let mut rejeita = [0u8; SS_LEN];
    shake256_into(&[z, c], &mut rejeita);
    let mut c2 = [0u8; CT_LEN];
    pke_encrypt(ek, &m, &g[32..], &mut c2);
    let mask = 0u8.wrapping_sub(u8::from(ct_eq(c, &c2)));
    let mut k = [0u8; SS_LEN];
    for (i, x) in k.iter_mut().enumerate() {
        *x = (g[i] & mask) | (rejeita[i] & !mask);
    }
    wipe(&mut m);
    wipe(&mut gin);
    wipe(&mut g);
    wipe(&mut rejeita);
    wipe(&mut c2);
    Ok(Secret::take(&mut k))
}

#[cfg(test)]
mod tests;
