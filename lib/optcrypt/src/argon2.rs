//! Argon2id v1.3 (RFC 9106), composto à mão sobre o [`crate::blake2b`]
//! (ADR 0004 e ADR 0053, P9). Sem alocação: o chamador dá a memória de
//! trabalho como fatias de [`Block`], que o Argon2 zera ao terminar.
//!
//! As duas primeiras fatias da primeira passada indexam sem depender da
//! senha (modo "i"); o resto usa o modo "d", como manda o Argon2id.

#![allow(
    clippy::doc_markdown,
    reason = "BLAKE2b e H' são nomes de especificação"
)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "alvo x86_64: usize tem 64 bits"
)]
use crate::blake2b::{self, Blake2b};
use crate::secret::wipe;

/// Bloco de 1 KiB (128 palavras de 64 bits).
pub type Block = [u64; 128];

/// Erros de parâmetro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Sal com menos de 8 bytes.
    SaltTooShort,
    /// Saída com menos de 4 ou mais de 2^32-1 bytes.
    BadOutputLen,
    /// `t` zero, `p` zero ou `m` menor que `8p`.
    BadParams,
    /// A memória de trabalho tem menos blocos que `m'`.
    WorkTooSmall,
}

/// Parâmetros de custo.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Passadas (`t`).
    pub t: u32,
    /// Memória em KiB (`m`).
    pub m_kib: u32,
    /// Faixas (`p`).
    pub p: u32,
}

impl Params {
    /// Blocos que a memória de trabalho precisa ter (`m'`), ou `None` se os
    /// parâmetros são inválidos.
    #[must_use]
    pub fn work_blocks(&self) -> Option<usize> {
        if self.t == 0 || self.p == 0 || self.m_kib < 8 * self.p {
            return None;
        }
        Some((self.m_kib / (4 * self.p) * (4 * self.p)) as usize)
    }
}

fn h0(pwd: &[u8], salt: &[u8], secret: &[u8], ad: &[u8], pr: Params, out_len: u32) -> [u8; 64] {
    let mut h = Blake2b::new(64);
    for w in [pr.p, out_len, pr.m_kib, pr.t, 0x13, 2] {
        h.update(&w.to_le_bytes());
    }
    for part in [pwd, salt, secret, ad] {
        h.update(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_le_bytes());
        h.update(part);
    }
    let mut out = [0u8; 64];
    h.finalize(&mut out);
    out
}

/// `H'`: BLAKE2b de saída variável (RFC 9106, seção 3.3).
fn h_prime(input: &[&[u8]], out: &mut [u8]) {
    let len = u32::try_from(out.len()).unwrap_or(u32::MAX).to_le_bytes();
    if out.len() <= 64 {
        let mut h = Blake2b::new(out.len());
        h.update(&len);
        for i in input {
            h.update(i);
        }
        h.finalize(out);
        return;
    }
    let mut v = [0u8; 64];
    let mut h = Blake2b::new(64);
    h.update(&len);
    for i in input {
        h.update(i);
    }
    h.finalize(&mut v);
    let mut pos = 0;
    while out.len() - pos > 64 {
        out[pos..pos + 32].copy_from_slice(&v[..32]);
        pos += 32;
        let prev = v;
        if out.len() - pos > 64 {
            blake2b::hash(&prev, &mut v);
        } else {
            let mut last = [0u8; 64];
            blake2b::hash(&prev, &mut last[..out.len() - pos]);
            v = last;
        }
    }
    let n = out.len() - pos;
    out[pos..].copy_from_slice(&v[..n]);
    wipe(&mut v);
}

#[allow(clippy::many_single_char_names, reason = "nomes da RFC 9106")]
fn gb(v: &mut [u64; 128], a: usize, b: usize, c: usize, d: usize) {
    let mul = |x: u64, y: u64| {
        (x & 0xffff_ffff)
            .wrapping_mul(y & 0xffff_ffff)
            .wrapping_mul(2)
    };
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mul(v[a], v[b]));
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(mul(v[c], v[d]));
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mul(v[a], v[b]));
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(mul(v[c], v[d]));
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// Permutação `P` sobre 16 palavras de `z` dadas por `ix`.
fn perm(z: &mut Block, ix: [usize; 16]) {
    gb(z, ix[0], ix[4], ix[8], ix[12]);
    gb(z, ix[1], ix[5], ix[9], ix[13]);
    gb(z, ix[2], ix[6], ix[10], ix[14]);
    gb(z, ix[3], ix[7], ix[11], ix[15]);
    gb(z, ix[0], ix[5], ix[10], ix[15]);
    gb(z, ix[1], ix[6], ix[11], ix[12]);
    gb(z, ix[2], ix[7], ix[8], ix[13]);
    gb(z, ix[3], ix[4], ix[9], ix[14]);
}

/// Função de compressão `G(x, y)`.
fn compress(x: &Block, y: &Block) -> Block {
    let mut r = [0u64; 128];
    for ((o, a), b) in r.iter_mut().zip(x).zip(y) {
        *o = a ^ b;
    }
    let mut z = r;
    for row in 0..8 {
        perm(&mut z, core::array::from_fn(|i| 16 * row + i));
    }
    for col in 0..8 {
        perm(
            &mut z,
            core::array::from_fn(|i| 2 * col + 16 * (i / 2) + i % 2),
        );
    }
    for (a, b) in z.iter_mut().zip(r) {
        *a ^= b;
    }
    r.fill(0);
    z
}

fn put_le(block: &mut Block, bytes: &[u8; 1024]) {
    for (w, c) in block.iter_mut().zip(bytes.chunks_exact(8)) {
        *w = u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    }
}

/// Argon2id: `out` recebe a tag (`out.len()` de 4 em diante).
///
/// `secret` e `ad` são os campos opcionais da RFC (use `&[]` se não houver).
/// `work` precisa ter pelo menos `params.work_blocks()` blocos; só esse
/// prefixo é usado e depois zerado.
///
/// # Errors
/// [`Error`] por parâmetro inválido.
#[allow(clippy::too_many_arguments, reason = "assinatura da RFC 9106")]
pub fn argon2id(
    pwd: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    params: Params,
    work: &mut [Block],
    out: &mut [u8],
) -> Result<(), Error> {
    if salt.len() < 8 {
        return Err(Error::SaltTooShort);
    }
    if out.len() < 4 || u32::try_from(out.len()).is_err() {
        return Err(Error::BadOutputLen);
    }
    let mp = params.work_blocks().ok_or(Error::BadParams)?;
    if work.len() < mp {
        return Err(Error::WorkTooSmall);
    }
    let mem = &mut work[..mp];
    let lanes = params.p as usize;
    let q = mp / lanes;
    let seg = q / 4;
    let mut h = h0(
        pwd,
        salt,
        secret,
        ad,
        params,
        u32::try_from(out.len()).unwrap_or(0),
    );
    for lane in 0..lanes {
        for col in 0..2u32 {
            let mut raw = [0u8; 1024];
            let li = u32::try_from(lane).unwrap_or(0).to_le_bytes();
            h_prime(&[&h, &col.to_le_bytes(), &li], &mut raw);
            put_le(&mut mem[lane * q + col as usize], &raw);
            wipe(&mut raw);
        }
    }
    wipe(&mut h);
    for pass in 0..params.t {
        for slice in 0..4usize {
            for lane in 0..lanes {
                segment(mem, params, (pass, slice, lane), (q, seg, mp));
            }
        }
    }
    let mut c = mem[q - 1];
    for lane in 1..lanes {
        for (a, b) in c.iter_mut().zip(mem[lane * q + q - 1]) {
            *a ^= b;
        }
    }
    let mut bytes = [0u8; 1024];
    for (ch, w) in bytes.chunks_exact_mut(8).zip(c) {
        ch.copy_from_slice(&w.to_le_bytes());
    }
    h_prime(&[&bytes], out);
    wipe(&mut bytes);
    c.fill(0);
    core::hint::black_box(&mut c);
    for b in mem.iter_mut() {
        b.fill(0);
    }
    core::hint::black_box(&mut *mem);
    Ok(())
}

fn segment(
    mem: &mut [Block],
    pr: Params,
    (pass, slice, lane): (u32, usize, usize),
    (q, seg, mp): (usize, usize, usize),
) {
    let lanes = pr.p as usize;
    let independent = pass == 0 && slice < 2;
    let mut addr = [0u64; 128];
    let start = if pass == 0 && slice == 0 { 2 } else { 0 };
    for idx in start..seg {
        if independent && (idx == start || idx % 128 == 0) {
            let mut z = [0u64; 128];
            z[0] = u64::from(pass);
            z[1] = lane as u64;
            z[2] = slice as u64;
            z[3] = mp as u64;
            z[4] = u64::from(pr.t);
            z[5] = 2;
            z[6] = (idx / 128 + 1) as u64;
            let zero = [0u64; 128];
            addr = compress(&zero, &compress(&zero, &z));
        }
        let col = slice * seg + idx;
        let prev = lane * q + if col == 0 { q - 1 } else { col - 1 };
        let rnd = if independent {
            addr[idx % 128]
        } else {
            mem[prev][0]
        };
        let (j1, j2) = (rnd & 0xffff_ffff, rnd >> 32);
        let rlane = if pass == 0 && slice == 0 {
            lane
        } else {
            (j2 % u64::from(pr.p)) as usize
        };
        let same = rlane == lane;
        let area = if pass == 0 {
            if slice == 0 {
                idx - 1
            } else if same {
                slice * seg + idx - 1
            } else {
                (slice * seg).saturating_sub(usize::from(idx == 0))
            }
        } else if same {
            q - seg + idx - 1
        } else {
            q - seg - usize::from(idx == 0)
        } as u64;
        let x = (j1 * j1) >> 32;
        let rel = area - 1 - ((area * x) >> 32);
        let base = if pass == 0 || slice == 3 {
            0
        } else {
            (slice + 1) * seg
        };
        let refcol = (base as u64 + rel) as usize % q;
        let mut new = compress(&mem[prev], &mem[rlane * q + refcol]);
        let cur = &mut mem[lane * q + col];
        if pass == 0 {
            *cur = new;
        } else {
            for (a, b) in cur.iter_mut().zip(new) {
                *a ^= b;
            }
        }
        new.fill(0);
        core::hint::black_box(&mut new);
    }
    let _ = lanes;
}

#[cfg(test)]
mod tests;
