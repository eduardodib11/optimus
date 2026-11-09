//! `acpid`: tabelas ACPI e AML (T-405; ADR 0045, itens 2 a 4).
//!
//! Núcleo `no_std`, sem alocação e sem `unsafe`, testado no host. Recebe os
//! bytes das tabelas (no processo, um `MemoryObject` somente leitura) e
//! entrega cada `Device` do espaço de nomes com `_HID`, `_CID`, `_ADR`, `_STA`
//! e o `_CRS` decodificado. O AML vem do firmware, então toda leitura é
//! conferida e há limites duros ([`Limits`]): estourá-los aborta com
//! [`Error::Limit`], nunca com pânico.
//!
//! Subconjunto desta etapa: `Scope`, `Device`, `Name` com constantes, string
//! ou buffer, `Method`/`Field`/`OperationRegion` apenas saltados. A execução
//! de métodos (`_STA`, `_CRS` e `_PRT` dinâmicos) entra na etapa seguinte.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod crs;
pub use crs::{Resource, Resources};

/// Erros de leitura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Dados curtos demais.
    Truncated,
    /// Soma dos bytes da tabela diferente de zero.
    BadChecksum,
    /// Estrutura inválida.
    Malformed,
    /// Limite de profundidade ou de operações estourado.
    Limit,
}

/// Limites duros do interpretador (ADR 0045, item 2).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Aninhamento máximo de `Scope`/`Device` (até [`MAX_DEPTH`]).
    pub max_depth: usize,
    /// Operações lidas no total.
    pub max_ops: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: MAX_DEPTH,
            max_ops: 200_000,
        }
    }
}

/// Teto de profundidade do caminho.
pub const MAX_DEPTH: usize = 16;
/// Tamanho do cabeçalho de uma tabela SDT.
pub const HEADER_LEN: usize = 36;

/// Cabeçalho comum das tabelas SDT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Assinatura de 4 letras (`DSDT`, `SSDT`, ...).
    pub signature: [u8; 4],
    /// Tamanho total, com o cabeçalho.
    pub length: usize,
}

/// Confere o cabeçalho e a soma de verificação e devolve o corpo AML (tudo
/// depois dos 36 bytes) de uma tabela `DSDT` ou `SSDT`.
///
/// # Errors
/// [`Error::Truncated`], [`Error::Malformed`] ou [`Error::BadChecksum`].
pub fn table_body(table: &[u8]) -> Result<(Header, &[u8]), Error> {
    let raw = table.get(..HEADER_LEN).ok_or(Error::Truncated)?;
    let length = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    if length < HEADER_LEN {
        return Err(Error::Malformed);
    }
    let whole = table.get(..length).ok_or(Error::Truncated)?;
    if whole.iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0 {
        return Err(Error::BadChecksum);
    }
    let signature = [raw[0], raw[1], raw[2], raw[3]];
    Ok((Header { signature, length }, &whole[HEADER_LEN..]))
}

/// Um nome de 4 caracteres do espaço de nomes.
pub type NameSeg = [u8; 4];

/// Um `Device` encontrado.
#[derive(Clone, Copy, Debug)]
pub struct Device<'a> {
    /// Caminho absoluto (`path[..depth]`).
    pub path: [NameSeg; MAX_DEPTH],
    /// Quantos nomes de `path` valem.
    pub depth: usize,
    /// `_HID` (e `_CID` em `cid`), já no formato textual (`PNP0303`).
    pub hid: Option<Id>,
    /// Primeiro `_CID`.
    pub cid: Option<Id>,
    /// `_ADR`.
    pub adr: Option<u64>,
    /// `_STA` constante.
    pub sta: Option<u64>,
    /// Bytes do buffer `_CRS`; [`Device::resources`] decodifica.
    pub crs: Option<&'a [u8]>,
}

impl<'a> Device<'a> {
    /// Recursos de `_CRS`.
    #[must_use]
    pub fn resources(&self) -> Resources<'a> {
        Resources::new(self.crs.unwrap_or(&[]))
    }
}

/// Identificador de hardware em texto (até 8 bytes ASCII).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id {
    /// Bytes.
    pub bytes: [u8; 8],
    /// Quantos valem.
    pub len: usize,
}

impl Id {
    /// O texto.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn from_str(s: &[u8]) -> Self {
        let len = s.len().min(8);
        let mut bytes = [0; 8];
        bytes[..len].copy_from_slice(&s[..len]);
        Self { bytes, len }
    }

    /// `EISAID` comprimido de 32 bits (`PNP0303` etc.).
    fn from_eisa(v: u32) -> Self {
        let b = v.to_le_bytes();
        let hex = |n: u8| if n < 10 { b'0' + n } else { b'A' + n - 10 };
        let s = [
            ((b[0] >> 2) & 0x1F) + 0x40,
            (((b[0] & 3) << 3) | (b[1] >> 5)) + 0x40,
            (b[1] & 0x1F) + 0x40,
            hex(b[2] >> 4),
            hex(b[2] & 15),
            hex(b[3] >> 4),
            hex(b[3] & 15),
        ];
        Self::from_str(&s)
    }
}

/// Valor de um `Name`.
enum Value<'a> {
    Int(u64),
    Str(&'a [u8]),
    Buf(&'a [u8]),
    Other,
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn u8(&mut self) -> Result<u8, Error> {
        let v = *self.b.get(self.p).ok_or(Error::Truncated)?;
        self.p += 1;
        Ok(v)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.p.checked_add(n).ok_or(Error::Truncated)?;
        let s = self.b.get(self.p..end).ok_or(Error::Truncated)?;
        self.p = end;
        Ok(s)
    }

    fn le(&mut self, n: usize) -> Result<u64, Error> {
        Ok(self
            .take(n)?
            .iter()
            .rev()
            .fold(0, |a, b| (a << 8) | u64::from(*b)))
    }

    /// `PkgLength`; devolve o fim absoluto do pacote (que conta o próprio
    /// campo), já dentro de `limit`.
    fn pkg_end(&mut self, limit: usize) -> Result<usize, Error> {
        let start = self.p;
        let lead = self.u8()?;
        let extra = usize::from(lead >> 6);
        let mut len = if extra == 0 {
            usize::from(lead & 0x3F)
        } else {
            usize::from(lead & 0x0F)
        };
        for i in 0..extra {
            len |= usize::from(self.u8()?) << (4 + 8 * i);
        }
        let end = start.checked_add(len).ok_or(Error::Malformed)?;
        if end > limit || end < self.p {
            return Err(Error::Malformed);
        }
        Ok(end)
    }

    fn seg(&mut self) -> Result<NameSeg, Error> {
        let s = self.take(4)?;
        let ok = |c: u8| c.is_ascii_uppercase() || c == b'_' || c.is_ascii_digit();
        if !s.iter().copied().all(ok) || s[0].is_ascii_digit() {
            return Err(Error::Malformed);
        }
        Ok([s[0], s[1], s[2], s[3]])
    }

    /// `NameString`: (raiz, número de `^`, nomes e quantos).
    fn name(&mut self) -> Result<(bool, usize, [NameSeg; 8], usize), Error> {
        let mut root = false;
        let mut up = 0;
        loop {
            match *self.b.get(self.p).ok_or(Error::Truncated)? {
                b'\\' if !root && up == 0 => root = true,
                b'^' if !root => up += 1,
                _ => break,
            }
            self.p += 1;
        }
        let mut segs = [[0; 4]; 8];
        let n = match self.u8()? {
            0x00 => 0,
            0x2E => 2,
            0x2F => usize::from(self.u8()?),
            _ => {
                self.p -= 1;
                1
            }
        };
        if n > segs.len() {
            return Err(Error::Malformed);
        }
        for s in &mut segs[..n] {
            *s = self.seg()?;
        }
        Ok((root, up, segs, n))
    }

    fn value(&mut self, limit: usize) -> Result<Value<'a>, Error> {
        Ok(match self.u8()? {
            0x00 => Value::Int(0),
            0x01 => Value::Int(1),
            0xFF => Value::Int(u64::MAX),
            0x0A => Value::Int(self.le(1)?),
            0x0B => Value::Int(self.le(2)?),
            0x0C => Value::Int(self.le(4)?),
            0x0E => Value::Int(self.le(8)?),
            0x0D => {
                let rest = self.b.get(self.p..limit).ok_or(Error::Truncated)?;
                let n = rest.iter().position(|c| *c == 0).ok_or(Error::Truncated)?;
                self.p += n + 1;
                Value::Str(&rest[..n])
            }
            op @ (0x11 | 0x12) => {
                let end = self.pkg_end(limit)?;
                let v = if op == 0x11 {
                    // BufferSize é um inteiro; os dados vão até o fim.
                    let _ = self.value(end)?;
                    Value::Buf(self.b.get(self.p..end).ok_or(Error::Truncated)?)
                } else {
                    Value::Other
                };
                self.p = end;
                v
            }
            _ => return Err(Error::Malformed),
        })
    }
}

struct Walker<'a, F> {
    cur: Cur<'a>,
    limits: Limits,
    ops: u32,
    f: F,
}

#[derive(Clone, Copy)]
struct Scope {
    path: [NameSeg; MAX_DEPTH],
    depth: usize,
}

impl Scope {
    fn child(&self, root: bool, up: usize, segs: &[NameSeg]) -> Result<Self, Error> {
        let mut s = if root {
            Self { depth: 0, ..*self }
        } else {
            *self
        };
        s.depth = s.depth.checked_sub(up).ok_or(Error::Malformed)?;
        for seg in segs {
            *s.path.get_mut(s.depth).ok_or(Error::Limit)? = *seg;
            s.depth += 1;
        }
        Ok(s)
    }
}

impl<'a, F: FnMut(&Device<'a>)> Walker<'a, F> {
    /// Lê termos até `end`; devolve a informação do `Device` em curso.
    fn body(
        &mut self,
        end: usize,
        scope: Scope,
        dev: &mut Option<Device<'a>>,
    ) -> Result<(), Error> {
        while self.cur.p < end {
            self.ops += 1;
            if self.ops > self.limits.max_ops {
                return Err(Error::Limit);
            }
            match self.cur.u8()? {
                // Name(seg, valor)
                0x08 => {
                    let (_, _, segs, n) = self.cur.name()?;
                    let v = self.cur.value(end)?;
                    if let (Some(d), 1) = (dev.as_mut(), n) {
                        record(d, segs[0], &v);
                    }
                }
                // Scope(...) { ... } e Method(...) { ... } (este só saltado)
                op @ (0x10 | 0x14) => {
                    let pend = self.cur.pkg_end(end)?;
                    let (root, up, segs, n) = self.cur.name()?;
                    if op == 0x10 {
                        let sub = scope.child(root, up, &segs[..n])?;
                        self.nested(pend, sub, &mut None)?;
                    }
                    self.cur.p = pend;
                }
                0x5B => match self.cur.u8()? {
                    // Device(...) { ... }
                    0x82 => {
                        let pend = self.cur.pkg_end(end)?;
                        let (root, up, segs, n) = self.cur.name()?;
                        let sub = scope.child(root, up, &segs[..n])?;
                        let mut me = Some(Device {
                            path: sub.path,
                            depth: sub.depth,
                            hid: None,
                            cid: None,
                            adr: None,
                            sta: None,
                            crs: None,
                        });
                        self.nested(pend, sub, &mut me)?;
                        if let Some(d) = me {
                            (self.f)(&d);
                        }
                        self.cur.p = pend;
                    }
                    // Field e IndexField: só saltados.
                    0x81 | 0x86 => {
                        let pend = self.cur.pkg_end(end)?;
                        self.cur.p = pend;
                    }
                    // OperationRegion(nome, espaço, offset, tamanho)
                    0x80 => {
                        self.cur.name()?;
                        self.cur.u8()?;
                        self.cur.value(end)?;
                        self.cur.value(end)?;
                    }
                    _ => return Err(Error::Malformed),
                },
                _ => return Err(Error::Malformed),
            }
        }
        Ok(())
    }

    fn nested(
        &mut self,
        end: usize,
        scope: Scope,
        dev: &mut Option<Device<'a>>,
    ) -> Result<(), Error> {
        if scope.depth > self.limits.max_depth {
            return Err(Error::Limit);
        }
        self.body(end, scope, dev)
    }
}

fn record<'a>(d: &mut Device<'a>, seg: NameSeg, v: &Value<'a>) {
    let id = |v: &Value<'a>| match *v {
        Value::Int(n) => u32::try_from(n).ok().map(Id::from_eisa),
        Value::Str(s) => Some(Id::from_str(s)),
        _ => None,
    };
    match (&seg, v) {
        (b"_HID", _) => d.hid = id(v),
        (b"_CID", _) => d.cid = d.cid.or_else(|| id(v)),
        (b"_ADR", Value::Int(n)) => d.adr = Some(*n),
        (b"_STA", Value::Int(n)) => d.sta = Some(*n),
        (b"_CRS", Value::Buf(b)) => d.crs = Some(b),
        _ => {}
    }
}

/// Percorre o AML de uma tabela (`aml` é o corpo de [`table_body`]) e chama
/// `f` para cada `Device`, depois de seus filhos.
///
/// # Errors
/// Qualquer estrutura inválida ou limite estourado aborta com um [`Error`];
/// os dispositivos já entregues continuam válidos.
pub fn scan<'a>(aml: &'a [u8], limits: Limits, f: impl FnMut(&Device<'a>)) -> Result<(), Error> {
    let mut w = Walker {
        cur: Cur { b: aml, p: 0 },
        limits,
        ops: 0,
        f,
    };
    let root = Scope {
        path: [[0; 4]; MAX_DEPTH],
        depth: 0,
    };
    w.body(aml.len(), root, &mut None)
}

#[cfg(test)]
mod tests;
