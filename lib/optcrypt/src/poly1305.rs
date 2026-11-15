//! Poly1305 (RFC 8439, seção 2.5) com cinco membros de 26 bits, na forma
//! do poly1305-donna de 32 bits. Sem ramos nem índices que dependam dos
//! dados. A chave é de uso único.

use crate::secret::wipe;

/// Bytes da chave de uso único.
pub const KEY_LEN: usize = 32;
/// Bytes da tag.
pub const TAG_LEN: usize = 16;
const BLOCK: usize = 16;
const MASK: u32 = 0x03ff_ffff;

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Estado incremental do Poly1305.
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; BLOCK],
    buf_len: usize,
}

impl Poly1305 {
    /// Começa com a chave de uso único `key` (`r` com máscara, depois `s`).
    #[must_use]
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        let r = [
            le32(&key[0..]) & 0x03ff_ffff,
            (le32(&key[3..]) >> 2) & 0x03ff_ff03,
            (le32(&key[6..]) >> 4) & 0x03ff_c0ff,
            (le32(&key[9..]) >> 6) & 0x03f0_3fff,
            (le32(&key[12..]) >> 8) & 0x000f_ffff,
        ];
        let pad = [
            le32(&key[16..]),
            le32(&key[20..]),
            le32(&key[24..]),
            le32(&key[28..]),
        ];
        Self {
            r,
            h: [0; 5],
            pad,
            buf: [0; BLOCK],
            buf_len: 0,
        }
    }

    fn block(&mut self, m: &[u8], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let [s1, s2, s3, s4] = [r1 * 5, r2 * 5, r3 * 5, r4 * 5];
        let h = &mut self.h;
        h[0] += le32(&m[0..]) & MASK;
        h[1] += (le32(&m[3..]) >> 2) & MASK;
        h[2] += (le32(&m[6..]) >> 4) & MASK;
        h[3] += (le32(&m[9..]) >> 6) & MASK;
        h[4] += (le32(&m[12..]) >> 8) | hibit;
        let [h0, h1, h2, h3, h4] = h.map(u64::from);
        let mut d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        let m26 = u64::from(MASK);
        let mut c = d0 >> 26;
        d1 += c;
        c = d1 >> 26;
        d2 += c;
        c = d2 >> 26;
        d3 += c;
        c = d3 >> 26;
        d4 += c;
        c = d4 >> 26;
        // Os `as u32` abaixo só guardam valores já mascarados em 26 bits.
        #[allow(clippy::cast_possible_truncation)]
        {
            h[0] = (d0 & m26) as u32;
            h[1] = (d1 & m26) as u32;
            h[2] = (d2 & m26) as u32;
            h[3] = (d3 & m26) as u32;
            h[4] = (d4 & m26) as u32;
        }
        d0 = u64::from(h[0]) + c * 5;
        #[allow(clippy::cast_possible_truncation)]
        {
            h[0] = (d0 & m26) as u32;
            h[1] += (d0 >> 26) as u32;
        }
    }

    /// Alimenta a mensagem.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (BLOCK - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < BLOCK {
                return;
            }
            let b = self.buf;
            self.block(&b, 1 << 24);
            self.buf_len = 0;
        }
        while let Some((b, rest)) = data.split_first_chunk::<BLOCK>() {
            self.block(b, 1 << 24);
            data = rest;
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buf_len = data.len();
    }

    /// Termina e devolve a tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; TAG_LEN] {
        if self.buf_len > 0 {
            let mut b = [0u8; BLOCK];
            b[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            b[self.buf_len] = 1;
            self.block(&b, 0);
        }
        let h = &mut self.h;
        let mut c = h[1] >> 26;
        h[1] &= MASK;
        for x in &mut h[2..] {
            *x += c;
            c = *x >> 26;
            *x &= MASK;
        }
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= MASK;
        h[1] += c;
        // g = h + 5 - 2^130; escolhe g se não houve empréstimo.
        let mut g = [0u32; 5];
        g[0] = h[0] + 5;
        c = g[0] >> 26;
        g[0] &= MASK;
        for (gi, hi) in g.iter_mut().zip(*h).skip(1) {
            *gi = hi + c;
            c = *gi >> 26;
            *gi &= MASK;
        }
        // `c` é 1 quando h + 5 >= 2^130, ou seja, quando h >= p.
        let mask_g = 0u32.wrapping_sub(c); // todos 1 se h >= p
        let mask_h = !mask_g;
        for (hi, gi) in h.iter_mut().zip(g) {
            *hi = (*hi & mask_h) | (gi & mask_g);
        }
        let w0 = h[0] | (h[1] << 26);
        let w1 = (h[1] >> 6) | (h[2] << 20);
        let w2 = (h[2] >> 12) | (h[3] << 14);
        let w3 = (h[3] >> 18) | (h[4] << 8);
        let mut out = [0u8; TAG_LEN];
        let mut carry = 0u64;
        for (i, w) in [w0, w1, w2, w3].into_iter().enumerate() {
            let f = u64::from(w) + u64::from(self.pad[i]) + carry;
            out[4 * i..4 * i + 4].copy_from_slice(&f.to_le_bytes()[..4]);
            carry = f >> 32;
        }
        out
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.fill(0);
        self.h.fill(0);
        self.pad.fill(0);
        core::hint::black_box((&mut self.r, &mut self.h, &mut self.pad));
        wipe(&mut self.buf);
    }
}

/// Tag Poly1305 de `data` de uma vez.
#[must_use]
pub fn tag(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; TAG_LEN] {
    let mut p = Poly1305::new(key);
    p.update(data);
    p.finalize()
}

#[cfg(test)]
mod tests;
