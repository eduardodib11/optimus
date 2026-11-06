//! Registro de log (`kind` 1) da ADR 0036, item 2: decodificação da carga
//! útil, que vem de um produtor não confiável.
//!
//! ```text
//!  0 ts_ns u64 | 8 level u8 | 9 nfields u8 | 10 tid u16 | 12 msg_len u16
//! 14 _ u16 | 16 mensagem | campos
//! ```
//!
//! Os campos estruturados são conferidos e ignorados por enquanto: a
//! consulta da v1 só devolve o texto.

use crate::Level;

/// `kind` do registro de log no anel.
pub const KIND_LOG: u16 = 1;
/// Maior carga útil de um registro de log.
pub const MAX_PAYLOAD: usize = 1024;
/// Maior mensagem.
pub const MAX_MSG: usize = 512;
/// Maior número de campos.
pub const MAX_FIELDS: u8 = 8;
/// `tid` das linhas do kernel.
pub const KERNEL_TID: u16 = 0xFFFF;
const HEAD: usize = 16;

/// Um registro decodificado; `msg` aponta para dentro da carga útil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRecord<'a> {
    /// Hora monotônica do produtor.
    pub ts_ns: u64,
    /// Nível.
    pub level: Level,
    /// Thread lógica do produtor.
    pub tid: u16,
    /// Mensagem, UTF-8.
    pub msg: &'a str,
}

/// Por que um registro foi recusado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Curto demais, longo demais ou com tamanhos que não fecham.
    Malformed,
    /// Nível fora de 1..=5.
    BadLevel,
    /// Mensagem que não é UTF-8.
    NotUtf8,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// Codifica um registro sem campos (o que o kernel e o `ostd` escrevem).
/// Devolve os bytes usados, ou `None` se `out` não comporta.
#[must_use]
pub fn encode(ts_ns: u64, level: Level, tid: u16, msg: &str, out: &mut [u8]) -> Option<usize> {
    let mut end = msg.len().min(MAX_MSG);
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    let msg = &msg.as_bytes()[..end];
    let n = HEAD + msg.len();
    let out = out.get_mut(..n)?;
    out[..8].copy_from_slice(&ts_ns.to_le_bytes());
    out[8] = level as u8 + 1;
    out[9] = 0;
    out[10..12].copy_from_slice(&tid.to_le_bytes());
    out[12..14].copy_from_slice(&u16::try_from(msg.len()).ok()?.to_le_bytes());
    out[14..16].fill(0);
    out[HEAD..].copy_from_slice(msg);
    Some(n)
}

/// Decodifica a carga útil de um registro de log.
///
/// # Errors
/// [`DecodeError`] para qualquer carga que não siga o formato.
pub fn decode(p: &[u8]) -> Result<LogRecord<'_>, DecodeError> {
    if p.len() < HEAD || p.len() > MAX_PAYLOAD {
        return Err(DecodeError::Malformed);
    }
    let ts_ns = u64::from_le_bytes(p[..8].try_into().map_err(|_| DecodeError::Malformed)?);
    let level = p[8]
        .checked_sub(1)
        .and_then(Level::from_u8)
        .ok_or(DecodeError::BadLevel)?;
    let nfields = p[9];
    let tid = u16_at(p, 10).ok_or(DecodeError::Malformed)?;
    let len = usize::from(u16_at(p, 12).ok_or(DecodeError::Malformed)?);
    if nfields > MAX_FIELDS || len > MAX_MSG {
        return Err(DecodeError::Malformed);
    }
    let msg = p.get(HEAD..HEAD + len).ok_or(DecodeError::Malformed)?;
    let msg = core::str::from_utf8(msg).map_err(|_| DecodeError::NotUtf8)?;
    skip_fields(&p[HEAD + len..], nfields)?;
    Ok(LogRecord {
        ts_ns,
        level,
        tid,
        msg,
    })
}

fn skip_fields(mut b: &[u8], n: u8) -> Result<(), DecodeError> {
    let bad = DecodeError::Malformed;
    for _ in 0..n {
        let klen = usize::from(*b.first().ok_or(bad)?);
        if klen > 32 {
            return Err(bad);
        }
        let ty = *b.get(1 + klen).ok_or(bad)?;
        let rest = 2 + klen;
        let vlen = match ty {
            0 => 2 + usize::from(u16_at(b, rest).ok_or(bad)?),
            1 | 2 => 8,
            3 => 1,
            _ => return Err(bad),
        };
        b = b.get(rest + vlen..).ok_or(bad)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
