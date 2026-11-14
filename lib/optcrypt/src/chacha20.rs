//! `ChaCha20` (RFC 8439, seção 2.3 e 2.4): cifra de fluxo de 256 bits com
//! nonce de 96 bits e contador de 32 bits. Só soma, rotação e xor.

use crate::secret::wipe;

/// Bytes da chave.
pub const KEY_LEN: usize = 32;
/// Bytes do nonce.
pub const NONCE_LEN: usize = 12;
/// Bytes de um bloco de fluxo.
pub const BLOCK_LEN: usize = 64;

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[allow(clippy::many_single_char_names, reason = "nomes da RFC 8439")]
fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Bloco de fluxo para `counter`.
#[must_use]
pub fn block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; BLOCK_LEN] {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&SIGMA);
    for (w, c) in init[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    init[12] = counter;
    for (w, c) in init[13..].iter_mut().zip(nonce.chunks_exact(4)) {
        *w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    let mut s = init;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; BLOCK_LEN];
    for ((o, a), b) in out.chunks_exact_mut(4).zip(s).zip(init) {
        o.copy_from_slice(&a.wrapping_add(b).to_le_bytes());
    }
    wipe_words(&mut s);
    wipe_words(&mut init);
    out
}

fn wipe_words(w: &mut [u32; 16]) {
    w.fill(0);
    core::hint::black_box(&mut *w);
}

/// Aplica o fluxo em `data` (cifra e decifra são a mesma operação),
/// começando no bloco `counter`.
pub fn apply(key: &[u8; KEY_LEN], mut counter: u32, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    for chunk in data.chunks_mut(BLOCK_LEN) {
        let mut ks = block(key, counter, nonce);
        for (d, k) in chunk.iter_mut().zip(&ks) {
            *d ^= k;
        }
        wipe(&mut ks);
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests;
