//! AES-256 e GHASH por instruções da CPU. Veja as invariantes em
//! [`super`].

use core::arch::x86_64::{
    __cpuid, __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128,
    _mm_bslli_si128, _mm_bsrli_si128, _mm_clmulepi64_si128, _mm_or_si128, _mm_set_epi8,
    _mm_setzero_si128, _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_slli_epi32, _mm_srli_epi32,
    _mm_xor_si128,
};

use crate::secret::wipe;

/// Chaves expandidas (15 de 16 bytes) e subchave do GHASH.
pub struct Keys {
    rk: [[u8; 16]; 15],
    h: [u8; 16],
}

impl Drop for Keys {
    fn drop(&mut self) {
        for k in &mut self.rk {
            wipe(k);
        }
        wipe(&mut self.h);
    }
}

/// A CPU tem AES-NI, PCLMULQDQ, SSE2 e SSSE3 (CPUID, folha 1)?
#[must_use]
pub fn supported() -> bool {
    // CPUID existe em todo x86_64; a folha 1 também.
    let r = __cpuid(1);
    let ecx = r.ecx;
    (ecx >> 25) & 1 == 1 && (ecx >> 1) & 1 == 1 && (ecx >> 9) & 1 == 1 && (r.edx >> 26) & 1 == 1
}

#[inline]
#[target_feature(enable = "sse2")]
fn ld(b: &[u8; 16]) -> __m128i {
    // SAFETY: `[u8; 16]` e `__m128i` têm 16 bytes e todo padrão é válido.
    unsafe { core::mem::transmute::<[u8; 16], __m128i>(*b) }
}

#[inline]
#[target_feature(enable = "sse2")]
fn st(x: __m128i) -> [u8; 16] {
    // SAFETY: idem, no sentido contrário.
    unsafe { core::mem::transmute::<__m128i, [u8; 16]>(x) }
}

#[inline]
#[target_feature(enable = "sse2,ssse3")]
fn bswap(x: __m128i) -> __m128i {
    let m = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    _mm_shuffle_epi8(x, m)
}

#[target_feature(enable = "aes,sse2")]
fn assist1(a: __m128i, b: __m128i) -> __m128i {
    // Palavra 3 do assist replicada, xor em cascata (RFC/Intel).
    let b = _mm_shuffle_epi32::<0xff>(b);
    let mut a = a;
    let mut t = _mm_bslli_si128::<4>(a);
    a = _mm_xor_si128(a, t);
    t = _mm_bslli_si128::<4>(t);
    a = _mm_xor_si128(a, t);
    t = _mm_bslli_si128::<4>(t);
    a = _mm_xor_si128(a, t);
    _mm_xor_si128(a, b)
}

#[target_feature(enable = "aes,sse2")]
fn assist2(a: __m128i, c: __m128i) -> __m128i {
    // `c` vem de aeskeygenassist(a, 0): a palavra 2 vale SubWord(w3).
    let c = _mm_shuffle_epi32::<0xaa>(c);
    let mut b = a;
    let mut t = _mm_bslli_si128::<4>(b);
    b = _mm_xor_si128(b, t);
    t = _mm_bslli_si128::<4>(t);
    b = _mm_xor_si128(b, t);
    t = _mm_bslli_si128::<4>(t);
    b = _mm_xor_si128(b, t);
    _mm_xor_si128(b, c)
}

#[target_feature(enable = "aes,pclmulqdq,sse2,ssse3")]
fn expand_inner(key: &[u8; 32]) -> Keys {
    let mut k = [_mm_setzero_si128(); 15];
    let (lo, hi) = key.split_at(16);
    k[0] = ld(lo.try_into().unwrap_or(&[0; 16]));
    k[1] = ld(hi.try_into().unwrap_or(&[0; 16]));
    macro_rules! even {
        ($i:expr, $rcon:expr) => {
            k[$i] = assist1(k[$i - 2], _mm_aeskeygenassist_si128::<$rcon>(k[$i - 1]));
        };
    }
    macro_rules! odd {
        ($i:expr) => {
            k[$i] = assist2(k[$i - 2], _mm_aeskeygenassist_si128::<0>(k[$i - 1]));
        };
    }
    even!(2, 0x01);
    odd!(3);
    even!(4, 0x02);
    odd!(5);
    even!(6, 0x04);
    odd!(7);
    even!(8, 0x08);
    odd!(9);
    even!(10, 0x10);
    odd!(11);
    even!(12, 0x20);
    odd!(13);
    even!(14, 0x40);
    let mut rk = [[0u8; 16]; 15];
    for (o, x) in rk.iter_mut().zip(k) {
        *o = st(x);
    }
    let h = st(enc_block(&rk, _mm_setzero_si128()));
    Keys { rk, h }
}

#[inline]
#[target_feature(enable = "aes,sse2")]
fn enc_block(rk: &[[u8; 16]; 15], x: __m128i) -> __m128i {
    let mut s = _mm_xor_si128(x, ld(&rk[0]));
    for k in &rk[1..14] {
        s = _mm_aesenc_si128(s, ld(k));
    }
    _mm_aesenclast_si128(s, ld(&rk[14]))
}

/// Multiplicação em GF(2^128) do GCM (algoritmo da nota técnica da Intel,
/// com entradas em ordem de bytes invertida).
#[inline]
#[target_feature(enable = "pclmulqdq,sse2")]
fn gfmul(a: __m128i, b: __m128i) -> __m128i {
    let mut t3 = _mm_clmulepi64_si128::<0x00>(a, b);
    let mut t4 = _mm_clmulepi64_si128::<0x10>(a, b);
    let t5 = _mm_clmulepi64_si128::<0x01>(a, b);
    let mut t6 = _mm_clmulepi64_si128::<0x11>(a, b);
    t4 = _mm_xor_si128(t4, t5);
    let t5 = _mm_bslli_si128::<8>(t4);
    t4 = _mm_bsrli_si128::<8>(t4);
    t3 = _mm_xor_si128(t3, t5);
    t6 = _mm_xor_si128(t6, t4);
    let mut t7 = _mm_srli_epi32::<31>(t3);
    let mut t8 = _mm_srli_epi32::<31>(t6);
    t3 = _mm_slli_epi32::<1>(t3);
    t6 = _mm_slli_epi32::<1>(t6);
    let t9 = _mm_bsrli_si128::<12>(t7);
    t8 = _mm_bslli_si128::<4>(t8);
    t7 = _mm_bslli_si128::<4>(t7);
    t3 = _mm_or_si128(t3, t7);
    t6 = _mm_or_si128(t6, t8);
    t6 = _mm_or_si128(t6, t9);
    t7 = _mm_slli_epi32::<31>(t3);
    t8 = _mm_slli_epi32::<30>(t3);
    let t9 = _mm_slli_epi32::<25>(t3);
    t7 = _mm_xor_si128(t7, t8);
    t7 = _mm_xor_si128(t7, t9);
    t8 = _mm_bsrli_si128::<4>(t7);
    t7 = _mm_bslli_si128::<12>(t7);
    t3 = _mm_xor_si128(t3, t7);
    let mut t2 = _mm_srli_epi32::<1>(t3);
    let t4 = _mm_srli_epi32::<2>(t3);
    let t5 = _mm_srli_epi32::<7>(t3);
    t2 = _mm_xor_si128(t2, t4);
    t2 = _mm_xor_si128(t2, t5);
    t2 = _mm_xor_si128(t2, t8);
    t3 = _mm_xor_si128(t3, t2);
    _mm_xor_si128(t6, t3)
}

fn ctr_block(nonce: &[u8; 12], ctr: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..12].copy_from_slice(nonce);
    b[12..].copy_from_slice(&ctr.to_be_bytes());
    b
}

#[target_feature(enable = "aes,pclmulqdq,sse2,ssse3")]
fn tag_inner(keys: &Keys, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let h = bswap(ld(&keys.h));
    let mut x = _mm_setzero_si128();
    for part in [aad, ct] {
        for chunk in part.chunks(16) {
            let mut b = [0u8; 16];
            b[..chunk.len()].copy_from_slice(chunk);
            x = gfmul(_mm_xor_si128(x, bswap(ld(&b))), h);
        }
    }
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lens[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    x = gfmul(_mm_xor_si128(x, bswap(ld(&lens))), h);
    let ek = enc_block(&keys.rk, ld(&ctr_block(nonce, 1)));
    st(_mm_xor_si128(bswap(x), ek))
}

#[target_feature(enable = "aes,sse2")]
fn ctr_inner(keys: &Keys, nonce: &[u8; 12], buf: &mut [u8]) {
    let mut ctr = 2u32;
    for chunk in buf.chunks_mut(16) {
        let mut ks = st(enc_block(&keys.rk, ld(&ctr_block(nonce, ctr))));
        for (d, k) in chunk.iter_mut().zip(&ks) {
            *d ^= k;
        }
        wipe(&mut ks);
        ctr = ctr.wrapping_add(1);
    }
}

/// Expande a chave de 256 bits. `None` se a CPU não tem as extensões.
#[must_use]
pub fn expand(key: &[u8; 32]) -> Option<Keys> {
    if !supported() {
        return None;
    }
    // SAFETY: `supported()` confirmou aes, pclmulqdq, sse2 e ssse3.
    Some(unsafe { expand_inner(key) })
}

/// Tag GCM sobre `ct`.
#[must_use]
pub fn tag(keys: &Keys, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    // SAFETY: `Keys` só existe depois de `expand`, que exige as extensões.
    unsafe { tag_inner(keys, nonce, aad, ct) }
}

/// Xor do fluxo CTR (contador 2 em diante) em `buf`.
pub fn ctr(keys: &Keys, nonce: &[u8; 12], buf: &mut [u8]) {
    // SAFETY: idem.
    unsafe { ctr_inner(keys, nonce, buf) }
}
