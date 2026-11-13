//! `acpid`: tabelas ACPI e AML (T-405; ADR 0045, itens 2 a 4).
//!
//! Núcleo `no_std`, sem alocação e sem `unsafe`, testado no host. Recebe os
//! bytes das tabelas (no processo, um `MemoryObject` somente leitura) e
//! entrega cada `Device` do espaço de nomes com `_HID`, `_CID`, `_ADR`, `_STA`
//! e o `_CRS` decodificado. O AML vem do firmware, então toda leitura é
//! conferida e há limites duros ([`Limits`]): estourá-los aborta com
//! [`Error::Limit`], nunca com pânico.
//!
//! Subconjunto desta etapa: desce em `Scope`, `Device`, `Processor`,
//! `PowerResource` e `ThermalZone`, lê `Name` com constantes, string ou
//! buffer e salta todo o resto pela gramática dos opcodes (métodos, campos,
//! regiões, expressões). A execução de métodos (`_STA`, `_CRS` e `_PRT`
//! dinâmicos) entra na etapa seguinte.

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

    /// Valor de dados de um `Name`; qualquer outro termo é saltado e vira
    /// [`Value::Other`].
    fn value(&mut self, limit: usize, budget: &mut Budget) -> Result<Value<'a>, Error> {
        let start = self.p;
        Ok(match self.u8()? {
            0x00 => Value::Int(0),
            0x01 => Value::Int(1),
            0xFF => Value::Int(u64::MAX),
            0x0A => Value::Int(self.le(1)?),
            0x0B => Value::Int(self.le(2)?),
            0x0C => Value::Int(self.le(4)?),
            0x0E => Value::Int(self.le(8)?),
            0x0D => Value::Str(self.string(limit)?),
            0x11 => {
                let end = self.pkg_end(limit)?;
                // BufferSize é um termo; os dados vão até o fim.
                self.term(end, budget, 0)?;
                let data = self.b.get(self.p..end).ok_or(Error::Truncated)?;
                self.p = end;
                Value::Buf(data)
            }
            _ => {
                self.p = start;
                self.term(limit, budget, 0)?;
                Value::Other
            }
        })
    }

    fn string(&mut self, limit: usize) -> Result<&'a [u8], Error> {
        let rest = self.b.get(self.p..limit).ok_or(Error::Truncated)?;
        let n = rest.iter().position(|c| *c == 0).ok_or(Error::Truncated)?;
        self.p += n + 1;
        Ok(&rest[..n])
    }

    /// Salta um termo inteiro (objeto, expressão ou comando) pela gramática
    /// de [`grammar`], sem interpretar. Uma chamada de método aparece como
    /// um nome solto: os argumentos dela, se houver, são saltados como
    /// termos seguintes pelo chamador.
    fn term(&mut self, limit: usize, budget: &mut Budget, depth: usize) -> Result<(), Error> {
        budget.step(depth)?;
        if self.p >= limit {
            return Err(Error::Truncated);
        }
        let op = self.u8()?;
        if matches!(op, b'A'..=b'Z' | b'_' | b'\\' | b'^' | 0x2E | 0x2F) {
            self.p -= 1;
            return self.name().map(drop);
        }
        let op = if op == 0x5B {
            0x5B00 | u16::from(self.u8()?)
        } else {
            u16::from(op)
        };
        for arg in grammar(op).ok_or(Error::Malformed)?.bytes() {
            match arg {
                b'N' => drop(self.name()?),
                b'T' => self.term(limit, budget, depth + 1)?,
                b'B' => drop(self.take(1)?),
                b'W' => drop(self.take(2)?),
                b'D' => drop(self.take(4)?),
                b'Q' => drop(self.take(8)?),
                b'S' => drop(self.string(limit)?),
                _ => self.p = self.pkg_end(limit)?,
            }
        }
        if self.p > limit {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }
}

/// Argumentos de cada opcode (os de prefixo `5B` somam `0x5B00`): `N` nome,
/// `T` termo, `B`/`W`/`D`/`Q` inteiros, `S` string e `P` um pacote saltado
/// inteiro pelo `PkgLength`. `None` para opcode desconhecido.
fn grammar(op: u16) -> Option<&'static str> {
    Some(match op {
        // Constantes, locais, argumentos e comandos sem operando.
        0x00 | 0x01 | 0xFF | 0x60..=0x6E | 0x9F | 0xA3 | 0xA5 | 0xCC | 0x5B30 | 0x5B31 | 0x5B33 => {
            ""
        }
        0x0A => "B",
        0x0B => "W",
        0x0C => "D",
        0x0E => "Q",
        0x0D => "S",
        0x06 => "NN",
        0x08 | 0x5B20 => "NT",
        0x15 => "NBB",
        // Tudo que é delimitado por PkgLength: Scope, Buffer, Package,
        // Method, If, Else, While, Field, Device, Processor etc.
        0x10..=0x14 | 0xA0..=0xA2 | 0x5B81..=0x5B87 => "P",
        0x70
        | 0x80..=0x82
        | 0x86
        | 0x90
        | 0x91
        | 0x93..=0x99
        | 0x9D
        | 0x5B12
        | 0x5B25
        | 0x5B28
        | 0x5B29 => "TT",
        0x71 | 0x75 | 0x76 | 0x83 | 0x87 | 0x8E | 0x92 | 0xA4 | 0x5B21 | 0x5B22 | 0x5B24
        | 0x5B26 | 0x5B27 => "T",
        0x72..=0x74 | 0x77 | 0x79..=0x7F | 0x84 | 0x85 | 0x88 | 0x9C => "TTT",
        0x78 | 0x9E => "TTTT",
        0x89 => "TBTBTT",
        0x8A..=0x8D | 0x8F => "TTN",
        0x5B01 => "NB",
        0x5B02 => "N",
        0x5B13 => "TTTN",
        0x5B1F => "TTTTTT",
        0x5B23 => "TW",
        0x5B32 => "BDT",
        0x5B80 => "NBTT",
        0x5B88 => "NTTT",
        _ => return None,
    })
}

/// Contador dos limites duros.
struct Budget {
    limits: Limits,
    ops: u32,
}

impl Budget {
    fn step(&mut self, depth: usize) -> Result<(), Error> {
        self.ops += 1;
        if self.ops > self.limits.max_ops || depth > self.limits.max_depth {
            return Err(Error::Limit);
        }
        Ok(())
    }
}

struct Walker<'a, F> {
    cur: Cur<'a>,
    budget: Budget,
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
    /// Lê termos até `end`. Desce em `Scope`, `Device`, `Processor`,
    /// `PowerResource` e `ThermalZone`; guarda os `Name` do `Device` em
    /// curso; salta o resto.
    fn body(
        &mut self,
        end: usize,
        scope: Scope,
        dev: &mut Option<Device<'a>>,
    ) -> Result<(), Error> {
        while self.cur.p < end {
            self.budget.step(scope.depth)?;
            let start = self.cur.p;
            let op = self.cur.u8()?;
            let ext = if op == 0x5B { self.cur.u8()? } else { 0 };
            // Bytes fixos entre o nome e o corpo de cada contêiner.
            let skip = match (op, ext) {
                (0x10, _) | (0x5B, 0x82 | 0x85) => Some(0),
                (0x5B, 0x83) => Some(6),
                (0x5B, 0x84) => Some(3),
                _ => None,
            };
            if let Some(skip) = skip {
                let pend = self.cur.pkg_end(end)?;
                let (root, up, segs, n) = self.cur.name()?;
                self.cur.take(skip)?;
                if self.cur.p > pend {
                    return Err(Error::Malformed);
                }
                let sub = scope.child(root, up, &segs[..n])?;
                let mut me = (ext == 0x82).then_some(Device {
                    path: sub.path,
                    depth: sub.depth,
                    hid: None,
                    cid: None,
                    adr: None,
                    sta: None,
                    crs: None,
                });
                self.body(pend, sub, &mut me)?;
                if let Some(d) = me {
                    (self.f)(&d);
                }
                self.cur.p = pend;
            } else if op == 0x08 {
                let (_, _, segs, n) = self.cur.name()?;
                let v = self.cur.value(end, &mut self.budget)?;
                if let (Some(d), 1) = (dev.as_mut(), n) {
                    record(d, segs[0], &v);
                }
            } else {
                self.cur.p = start;
                self.cur.term(end, &mut self.budget, 0)?;
            }
        }
        Ok(())
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
    let budget = Budget { limits, ops: 0 };
    let mut w = Walker {
        cur: Cur { b: aml, p: 0 },
        budget,
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
