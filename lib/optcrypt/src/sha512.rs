//! SHA-512 e SHA-384 (FIPS 180-4), sem `unsafe` e sem alocação. Como no
//! SHA-256, não há ramos nem índices que dependam dos dados.
//!
//! O SHA-384 é o SHA-512 com outro vetor inicial e saída truncada em 48
//! bytes; os dois dividem o mesmo núcleo ([`Core`]).

use crate::secret::wipe;

/// Bytes do bloco de compressão (os dois algoritmos).
pub const BLOCK_LEN: usize = 128;
/// Bytes do resumo do SHA-512.
pub const OUT_LEN: usize = 64;
/// Bytes do resumo do SHA-384.
pub const OUT_LEN_384: usize = 48;

#[rustfmt::skip]
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22, 0x7137_4491_23ef_65cd, 0xb5c0_fbcf_ec4d_3b2f, 0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538, 0x59f1_11f1_b605_d019, 0x923f_82a4_af19_4f9b, 0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242, 0x1283_5b01_4570_6fbe, 0x2431_85be_4ee4_b28c, 0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f, 0x80de_b1fe_3b16_96b1, 0x9bdc_06a7_25c7_1235, 0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2, 0xefbe_4786_384f_25e3, 0x0fc1_9dc6_8b8c_d5b5, 0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275, 0x4a74_84aa_6ea6_e483, 0x5cb0_a9dc_bd41_fbd4, 0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab, 0xa831_c66d_2db4_3210, 0xb003_27c8_98fb_213f, 0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2, 0xd5a7_9147_930a_a725, 0x06ca_6351_e003_826f, 0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc, 0x2e1b_2138_5c26_c926, 0x4d2c_6dfc_5ac4_2aed, 0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de, 0x766a_0abb_3c77_b2a8, 0x81c2_c92e_47ed_aee6, 0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364, 0xa81a_664b_bc42_3001, 0xc24b_8b70_d0f8_9791, 0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218, 0xd699_0624_5565_a910, 0xf40e_3585_5771_202a, 0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8, 0x1e37_6c08_5141_ab53, 0x2748_774c_df8e_eb99, 0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63, 0x4ed8_aa4a_e341_8acb, 0x5b9c_ca4f_7763_e373, 0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc, 0x78a5_636f_4317_2f60, 0x84c8_7814_a1f0_ab72, 0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28, 0xa450_6ceb_de82_bde9, 0xbef9_a3f7_b2c6_7915, 0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c, 0xd186_b8c7_21c0_c207, 0xeada_7dd6_cde0_eb1e, 0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba, 0x0a63_7dc5_a2c8_98a6, 0x113f_9804_bef9_0dae, 0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84, 0x32ca_ab7b_40c7_2493, 0x3c9e_be0a_15c9_bebc, 0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6, 0x597f_299c_fc65_7e2a, 0x5fcb_6fab_3ad6_faec, 0x6c44_198c_4a47_5817,
];

#[rustfmt::skip]
const H512: [u64; 8] = [
    0x6a09_e667_f3bc_c908, 0xbb67_ae85_84ca_a73b, 0x3c6e_f372_fe94_f82b, 0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1, 0x9b05_688c_2b3e_6c1f, 0x1f83_d9ab_fb41_bd6b, 0x5be0_cd19_137e_2179,
];

#[rustfmt::skip]
const H384: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8, 0x629a_292a_367c_d507, 0x9159_015a_3070_dd17, 0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31, 0x8eb4_4a87_6858_1511, 0xdb0c_2e0d_64f9_8fa7, 0x47b5_481d_befa_4fa4,
];

/// Núcleo comum: estado de 8 palavras de 64 bits e contador de 128 bits.
struct Core {
    h: [u64; 8],
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    total: u128,
}

impl Core {
    const fn new(iv: [u64; 8]) -> Self {
        Self {
            h: iv,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            total: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u128);
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

    /// Preenchimento e resumo completo de 64 bytes.
    fn finalize(&mut self) -> [u8; OUT_LEN] {
        let bits = self.total.wrapping_mul(8);
        let mut pad = [0u8; BLOCK_LEN * 2];
        pad[0] = 0x80;
        // Zeros até faltarem 16 bytes para fechar um bloco.
        let zeros = (BLOCK_LEN * 2 - 16 - self.buf_len - 1) % BLOCK_LEN;
        let n = 1 + zeros;
        pad[n..n + 16].copy_from_slice(&bits.to_be_bytes());
        let total = self.total;
        self.update(&pad[..n + 16]);
        self.total = total;
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; OUT_LEN];
        for (chunk, w) in out.chunks_exact_mut(8).zip(self.h) {
            chunk.copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        // O estado pode derivar de uma chave (HMAC, Ed25519).
        wipe(&mut self.buf);
        for w in &mut self.h {
            *w = 0;
        }
        core::hint::black_box(&mut self.h);
    }
}

/// Estado incremental do SHA-512.
pub struct Sha512(Core);

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Estado inicial.
    #[must_use]
    pub const fn new() -> Self {
        Self(Core::new(H512))
    }

    /// Alimenta o hash com `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Termina e devolve o resumo.
    #[must_use]
    pub fn finalize(mut self) -> [u8; OUT_LEN] {
        self.0.finalize()
    }
}

/// Estado incremental do SHA-384.
pub struct Sha384(Core);

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384 {
    /// Estado inicial.
    #[must_use]
    pub const fn new() -> Self {
        Self(Core::new(H384))
    }

    /// Alimenta o hash com `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Termina e devolve o resumo (os 48 primeiros bytes do núcleo).
    #[must_use]
    pub fn finalize(mut self) -> [u8; OUT_LEN_384] {
        let mut full = self.0.finalize();
        let mut out = [0u8; OUT_LEN_384];
        out.copy_from_slice(&full[..OUT_LEN_384]);
        // Os 16 bytes cortados são estado interno e não podem vazar.
        wipe(&mut full);
        out
    }
}

/// SHA-512 de `data` de uma vez.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

/// SHA-384 de `data` de uma vez.
#[must_use]
pub fn hash384(data: &[u8]) -> [u8; OUT_LEN_384] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize()
}

#[allow(clippy::many_single_char_names, reason = "nomes da FIPS 180-4")]
fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u64; 80];
    for (i, c) in block.chunks_exact(8).enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(c);
        w[i] = u64::from_be_bytes(b);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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
