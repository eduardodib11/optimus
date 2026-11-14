//! SHA-256 (FIPS 180-4), sem `unsafe` e sem alocação. Sem ramos nem
//! índices que dependam dos dados: só soma, rotação e operações bit a bit.

use crate::secret::wipe;

/// Bytes do resumo.
pub const OUT_LEN: usize = 32;
/// Bytes do bloco de compressão.
pub const BLOCK_LEN: usize = 64;

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Estado incremental do SHA-256.
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Estado inicial.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            h: H0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            total: 0,
        }
    }

    /// Alimenta o hash com `data`.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < BLOCK_LEN {
                return;
            }
            let block = self.buf;
            compress(&mut self.h, &block);
            self.buf_len = 0;
        }
        while let Some((block, rest)) = data.split_first_chunk::<BLOCK_LEN>() {
            compress(&mut self.h, block);
            data = rest;
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buf_len = data.len();
    }

    /// Termina e devolve o resumo.
    #[must_use]
    pub fn finalize(mut self) -> [u8; OUT_LEN] {
        let bits = self.total.wrapping_mul(8);
        let mut pad = [0u8; BLOCK_LEN * 2];
        pad[0] = 0x80;
        // Zeros até faltarem 8 bytes para fechar um bloco.
        let zeros = (BLOCK_LEN * 2 - 8 - self.buf_len - 1) % BLOCK_LEN;
        let n = 1 + zeros;
        pad[n..n + 8].copy_from_slice(&bits.to_be_bytes());
        let total = self.total;
        self.update(&pad[..n + 8]);
        self.total = total;
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; OUT_LEN];
        for (chunk, w) in out.chunks_exact_mut(4).zip(self.h) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // O estado pode derivar de uma chave (HMAC).
        wipe(&mut self.buf);
        for w in &mut self.h {
            *w = 0;
        }
        core::hint::black_box(&mut self.h);
    }
}

/// SHA-256 de `data` de uma vez.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

#[allow(clippy::many_single_char_names, reason = "nomes da FIPS 180-4")]
fn compress(h: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u32; 64];
    for (i, c) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(y);
    }
    // O escalonamento de mensagem pode ter derivado de uma chave.
    w.fill(0);
    core::hint::black_box(&mut w);
}

#[cfg(test)]
mod tests;
