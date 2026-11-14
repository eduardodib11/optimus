//! BLAKE2b (RFC 7693) sem chave, com saída de 1 a 64 bytes. É a base do
//! Argon2id (RFC 9106). Só soma, rotação e xor.

#![allow(
    clippy::doc_markdown,
    reason = "BLAKE2b e H' são nomes de especificação"
)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "alvo x86_64: usize tem 64 bits"
)]
use crate::secret::wipe;

/// Maior saída.
pub const MAX_OUT: usize = 64;
const BLOCK: usize = 128;

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// BLAKE2b incremental.
pub struct Blake2b {
    h: [u64; 8],
    buf: [u8; BLOCK],
    buf_len: usize,
    t: u64,
    out_len: usize,
}

impl Blake2b {
    /// Começa um hash de `out_len` bytes (1 a 64; fora disso vira 64).
    #[must_use]
    pub fn new(out_len: usize) -> Self {
        let out_len = if (1..=MAX_OUT).contains(&out_len) {
            out_len
        } else {
            MAX_OUT
        };
        let mut h = IV;
        // Parâmetros: tamanho da saída, sem chave, fanout 1, profundidade 1.
        h[0] ^= 0x0101_0000 ^ out_len as u64;
        Self {
            h,
            buf: [0; BLOCK],
            buf_len: 0,
            t: 0,
            out_len,
        }
    }

    /// Alimenta com `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // O último bloco só é comprimido no `finalize`.
            if self.buf_len == BLOCK {
                self.t = self.t.wrapping_add(BLOCK as u64);
                let b = self.buf;
                compress(&mut self.h, &b, self.t, false);
                self.buf_len = 0;
            }
            let take = (BLOCK - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
        }
    }

    /// Termina; `out` deve ter o tamanho dado em `new`.
    pub fn finalize(mut self, out: &mut [u8]) {
        self.t = self.t.wrapping_add(self.buf_len as u64);
        self.buf[self.buf_len..].fill(0);
        let b = self.buf;
        compress(&mut self.h, &b, self.t, true);
        let mut full = [0u8; MAX_OUT];
        for (c, w) in full.chunks_exact_mut(8).zip(self.h) {
            c.copy_from_slice(&w.to_le_bytes());
        }
        let n = self.out_len.min(out.len());
        out[..n].copy_from_slice(&full[..n]);
        wipe(&mut full);
    }
}

impl Drop for Blake2b {
    fn drop(&mut self) {
        wipe(&mut self.buf);
        self.h.fill(0);
        core::hint::black_box(&mut self.h);
    }
}

/// BLAKE2b de `data` com saída de `out.len()` bytes (1 a 64).
pub fn hash(data: &[u8], out: &mut [u8]) {
    let mut h = Blake2b::new(out.len());
    h.update(data);
    h.finalize(out);
}

#[allow(clippy::many_single_char_names, reason = "nomes da RFC 7693")]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[allow(clippy::many_single_char_names, reason = "nomes da RFC 7693")]
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK], t: u64, last: bool) {
    let mut m = [0u64; 16];
    for (w, c) in m.iter_mut().zip(block.chunks_exact(8)) {
        *w = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t;
    if last {
        v[14] = !v[14];
    }
    for s in SIGMA.iter().cycle().take(12) {
        let w = |i: usize| m[usize::from(s[i])];
        g(&mut v, 0, 4, 8, 12, w(0), w(1));
        g(&mut v, 1, 5, 9, 13, w(2), w(3));
        g(&mut v, 2, 6, 10, 14, w(4), w(5));
        g(&mut v, 3, 7, 11, 15, w(6), w(7));
        g(&mut v, 0, 5, 10, 15, w(8), w(9));
        g(&mut v, 1, 6, 11, 12, w(10), w(11));
        g(&mut v, 2, 7, 8, 13, w(12), w(13));
        g(&mut v, 3, 4, 9, 14, w(14), w(15));
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
    m.fill(0);
    v.fill(0);
    core::hint::black_box((&mut m, &mut v));
}

#[cfg(test)]
mod tests;
