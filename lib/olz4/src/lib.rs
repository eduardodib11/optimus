//! `olz4`: compressão LZ4 em formato de bloco, sem alocação e sem `unsafe`.
//!
//! Implementa o formato de bloco do LZ4 (sem cabeçalho de quadro): sequências
//! de `token`, literais, `offset` de 2 bytes e comprimento extra. [`compress`]
//! é guloso, com tabela de dispersão de 1024 entradas na pilha. [`decompress`]
//! valida cada campo antes de copiar, então entrada maliciosa vira [`Error`],
//! nunca pânico nem leitura fora dos limites.
//!
//! O buffer de saída de [`compress`] deve ter [`max_compressed_len`] bytes; com
//! isso a compressão não precisa checar espaço a cada byte.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Os casts truncam de propósito: são extrações de bytes e offsets já validados.
#![allow(clippy::cast_possible_truncation)]

use core::fmt;

/// Menor casamento que vale a pena codificar (exigência do formato).
pub const MIN_MATCH: usize = 4;
/// Os últimos bytes de um bloco são sempre literais (exigência do formato).
pub const LAST_LITERALS: usize = 5;
/// Um casamento não pode começar nos últimos `MFLIMIT` bytes do bloco.
pub const MFLIMIT: usize = 12;
/// Distância máxima de um casamento (offset de 16 bits).
pub const MAX_OFFSET: usize = 65_535;

const HASH_LOG: u32 = 10;

/// Erros de [`compress`] e [`decompress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// O buffer de saída é menor que o necessário.
    OutputTooSmall,
    /// A entrada acaba no meio de uma sequência.
    Truncated,
    /// Um offset é zero ou aponta antes do início da saída.
    BadOffset,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OutputTooSmall => "olz4: buffer de saída pequeno",
            Self::Truncated => "olz4: entrada truncada",
            Self::BadOffset => "olz4: offset inválido",
        })
    }
}

/// Tamanho do pior caso de [`compress`] para uma entrada de `n` bytes.
#[must_use]
pub const fn max_compressed_len(n: usize) -> usize {
    n + n / 255 + 16
}

fn read_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn hash(v: u32) -> usize {
    (v.wrapping_mul(2_654_435_761) >> (32 - HASH_LOG)) as usize
}

/// Escreve uma sequência: literais e, se houver, um casamento `(offset, len)`.
/// Pressupõe espaço (garantido por [`max_compressed_len`]).
fn emit(out: &mut [u8], op: &mut usize, lits: &[u8], matched: Option<(usize, usize)>) {
    let ml = matched.map_or(0, |(_, len)| len - MIN_MATCH);
    let lit_nib = lits.len().min(15);
    let ml_nib = ml.min(15);
    out[*op] = ((lit_nib << 4) | ml_nib) as u8;
    *op += 1;
    if lits.len() >= 15 {
        put_extra(out, op, lits.len() - 15);
    }
    out[*op..*op + lits.len()].copy_from_slice(lits);
    *op += lits.len();
    if let Some((offset, _)) = matched {
        out[*op] = offset as u8;
        out[*op + 1] = (offset >> 8) as u8;
        *op += 2;
        if ml >= 15 {
            put_extra(out, op, ml - 15);
        }
    }
}

fn put_extra(out: &mut [u8], op: &mut usize, mut rest: usize) {
    while rest >= 255 {
        out[*op] = 255;
        *op += 1;
        rest -= 255;
    }
    out[*op] = rest as u8;
    *op += 1;
}

/// Comprime `input` em `out` e devolve o número de bytes escritos.
///
/// # Errors
///
/// [`Error::OutputTooSmall`] se `out` tem menos de [`max_compressed_len`]
/// bytes para a entrada.
pub fn compress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let n = input.len();
    if out.len() < max_compressed_len(n) {
        return Err(Error::OutputTooSmall);
    }
    let mut op = 0;
    let mut anchor = 0;
    let mut table = [0u32; 1 << HASH_LOG];
    // Só casa se o início estiver a pelo menos MFLIMIT do fim.
    let mut ip = 0;
    while ip + MFLIMIT < n {
        let v = read_u32(input, ip);
        let h = hash(v);
        let prev = table[h];
        table[h] = (ip + 1) as u32;
        let cand = (prev as usize).wrapping_sub(1);
        let valid = prev != 0 && cand < ip && ip - cand <= MAX_OFFSET && read_u32(input, cand) == v;
        if !valid {
            ip += 1;
            continue;
        }
        // Estende o casamento sem passar dos últimos LAST_LITERALS bytes.
        let limit = n - LAST_LITERALS;
        let mut len = MIN_MATCH;
        while ip + len < limit && input[cand + len] == input[ip + len] {
            len += 1;
        }
        emit(out, &mut op, &input[anchor..ip], Some((ip - cand, len)));
        ip += len;
        anchor = ip;
    }
    emit(out, &mut op, &input[anchor..], None);
    Ok(op)
}

/// Descomprime `input` em `out` e devolve o número de bytes escritos.
///
/// # Errors
///
/// [`Error::Truncated`] se a entrada acaba no meio de uma sequência,
/// [`Error::BadOffset`] se um offset é inválido e [`Error::OutputTooSmall`]
/// se a saída não cabe em `out`.
pub fn decompress(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut ip = 0;
    let mut op = 0;
    loop {
        let token = *input.get(ip).ok_or(Error::Truncated)?;
        ip += 1;
        let lits = read_len(input, &mut ip, (token >> 4) as usize)?;
        let end = ip.checked_add(lits).ok_or(Error::Truncated)?;
        let src = input.get(ip..end).ok_or(Error::Truncated)?;
        let dst = out.get_mut(op..op + lits).ok_or(Error::OutputTooSmall)?;
        dst.copy_from_slice(src);
        op += lits;
        ip = end;
        if ip == input.len() {
            return Ok(op);
        }
        let off_bytes = input.get(ip..ip + 2).ok_or(Error::Truncated)?;
        let offset = usize::from(u16::from_le_bytes([off_bytes[0], off_bytes[1]]));
        ip += 2;
        if offset == 0 || offset > op {
            return Err(Error::BadOffset);
        }
        let len = read_len(input, &mut ip, (token & 15) as usize)? + MIN_MATCH;
        if out.len() - op < len {
            return Err(Error::OutputTooSmall);
        }
        // Cópia byte a byte: o casamento pode sobrepor a própria saída.
        for _ in 0..len {
            out[op] = out[op - offset];
            op += 1;
        }
    }
}

/// Lê o comprimento extra quando o nibble vale 15.
fn read_len(input: &[u8], ip: &mut usize, nib: usize) -> Result<usize, Error> {
    let mut len = nib;
    if nib == 15 {
        loop {
            let b = *input.get(*ip).ok_or(Error::Truncated)?;
            *ip += 1;
            len += usize::from(b);
            if b != 255 {
                break;
            }
        }
    }
    Ok(len)
}

#[cfg(test)]
mod tests;
