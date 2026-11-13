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
//! regiões, expressões). Os métodos `_STA` e `_CRS` ficam anotados no
//! `Device` e [`eval`] os executa (inteiros, locais, argumentos, controle de
//! fluxo, aritmética e chamadas). O `_PRT` (rotas de interrupção `INTx` do
//! PCI) sai por [`Device::routes`], depois de [`pic_mode`] escolher o modo
//! APIC. Campos de `OperationRegion` de `SystemMemory` e `SystemIO` são
//! lidos por [`Regions`], que só atende os intervalos entregues ao processo;
//! sem ela, ou fora deles, o método dá [`Error::Unsupported`].

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod crs;
mod eval;
mod prt;
pub use crs::{Resource, Resources};
pub use eval::{Method, State, eval, pic_mode};
pub use prt::{Route, Routes};

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
    /// Método usa algo fora do subconjunto (ADR 0045, item 3).
    Unsupported,
}

/// Acesso às regiões de operação (ADR 0045, item 3): quem implementa só
/// atende os intervalos que o processo recebeu.
pub trait Regions: Sync {
    /// Lê `bytes` (1, 2, 4 ou 8) em `addr` do espaço `space`
    /// ([`SPACE_MEMORY`] ou [`SPACE_IO`]); `None` fora dos intervalos
    /// entregues.
    fn read(&self, space: u8, addr: u64, bytes: u8) -> Option<u64>;
}

/// Espaço `SystemMemory` de uma `OperationRegion`.
pub const SPACE_MEMORY: u8 = 0;
/// Espaço `SystemIO`.
pub const SPACE_IO: u8 = 1;

/// Limites duros do interpretador (ADR 0045, item 2) e o acesso que ele
/// tem ao hardware.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Aninhamento máximo de `Scope`/`Device` (até [`MAX_DEPTH`]).
    pub max_depth: usize,
    /// Operações lidas no total.
    pub max_ops: u32,
    /// Leitura das regiões de operação; `None`: nenhum intervalo entregue.
    pub regions: Option<&'static dyn Regions>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: MAX_DEPTH,
            max_ops: 200_000,
            regions: None,
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
    /// Revisão da tabela; abaixo de 2, os inteiros do AML têm 32 bits.
    pub revision: u8,
}

impl Header {
    /// Os inteiros desta tabela têm 32 bits.
    #[must_use]
    pub fn width32(&self) -> bool {
        self.revision < 2
    }
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
    let header = Header {
        signature,
        length,
        revision: raw[8],
    };
    Ok((header, &whole[HEADER_LEN..]))
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
    /// `_STA` como método; [`Device::status`] o executa.
    pub sta_method: Option<Method>,
    /// `_CRS` como método; [`Device::current_resources`] o executa.
    pub crs_method: Option<Method>,
}

impl<'a> Device<'a> {
    /// Recursos de `_CRS`.
    #[must_use]
    pub fn resources(&self) -> Resources<'a> {
        Resources::new(self.crs.unwrap_or(&[]))
    }

    /// `_STA`: a constante, o resultado do método ou, sem nenhum dos dois,
    /// 0x0F (presente e funcionando, como manda a especificação).
    ///
    /// # Errors
    /// Os de [`eval`]; [`Error::Unsupported`] também se o método não
    /// devolver um inteiro.
    pub fn status(&self, aml: &'a [u8], width32: bool, limits: Limits) -> Result<u64, Error> {
        match (self.sta, self.sta_method) {
            (Some(v), _) => Ok(v),
            (None, None) => Ok(0x0F),
            (None, Some(m)) => match eval(aml, &self.path[..self.depth], m, width32, limits)? {
                Value::Int(v) => Ok(v),
                _ => Err(Error::Unsupported),
            },
        }
    }

    /// Recursos de `_CRS`, executando o método quando não é um buffer fixo.
    ///
    /// # Errors
    /// Os de [`eval`]; [`Error::Unsupported`] também se o método não
    /// devolver um buffer.
    pub fn current_resources(
        &self,
        aml: &'a [u8],
        width32: bool,
        limits: Limits,
    ) -> Result<Resources<'a>, Error> {
        match (self.crs, self.crs_method) {
            (None, Some(m)) => match eval(aml, &self.path[..self.depth], m, width32, limits)? {
                Value::Buf(b) => Ok(Resources::new(b)),
                _ => Err(Error::Unsupported),
            },
            _ => Ok(self.resources()),
        }
    }

    /// Rotas de `_PRT`; `None` se o dispositivo não tem `_PRT`. O objeto é
    /// procurado pelo caminho, porque o firmware pode declará-lo num `Scope`
    /// fora do `Device`. O método enxerga o que [`pic_mode`] gravou em
    /// `state`.
    ///
    /// # Errors
    /// Os de [`eval`]; [`Error::Unsupported`] também se o resultado não for
    /// um pacote.
    pub fn routes(
        &self,
        aml: &'a [u8],
        width32: bool,
        limits: Limits,
        state: &mut State,
    ) -> Result<Option<Routes<'a>>, Error> {
        let path = &self.path[..self.depth];
        let mut found = None;
        walk(aml, limits, |e| {
            if let Event::Object(at, item) = e
                && found.is_none()
                && at.depth == path.len() + 1
                && at.path[..path.len()] == *path
                && at.path[path.len()] == *b"_PRT"
            {
                found = Some(item);
            }
        })?;
        let v = match found {
            Some(Item::Name(v)) => v,
            Some(Item::Method(m)) => eval::run(aml, path, m, &[], width32, limits, state)?,
            Some(Item::Region(..) | Item::Field(_)) => return Err(Error::Unsupported),
            None => return Ok(None),
        };
        match v {
            Value::Pkg { data, .. } => Ok(Some(Routes::new(data))),
            _ => Err(Error::Unsupported),
        }
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

/// Valor de um `Name` ou resultado de um método.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// Inteiro.
    Int(u64),
    /// String (sem o zero final).
    Str(&'a [u8]),
    /// Dados de um buffer.
    Buf(&'a [u8]),
    /// Pacote: número de elementos e os bytes deles, ainda em AML.
    Pkg {
        /// Elementos declarados.
        count: u8,
        /// Os elementos codificados.
        data: &'a [u8],
    },
    /// Outro tipo de objeto, ou nenhum valor.
    Other,
}

/// O que a varredura encontra.
enum Event<'a> {
    /// Um `Device` completo, depois dos filhos.
    Device(Device<'a>),
    /// Um `Name` ou um `Method`, com o caminho absoluto dele.
    Object(Scope, Item<'a>),
}

/// Objeto com nome que [`eval`] sabe usar.
#[derive(Clone, Copy)]
enum Item<'a> {
    Name(Value<'a>),
    Method(Method),
    /// `OperationRegion`: espaço, base e tamanho em bytes (`None` quando
    /// não são constantes).
    Region(u8, Option<(u64, u64)>),
    Field(Field),
}

/// Um campo de uma `OperationRegion`.
#[derive(Clone, Copy)]
struct Field {
    /// Caminho da região.
    region: Scope,
    /// Primeiro bit dentro da região.
    bit: u64,
    /// Largura em bits.
    bits: u64,
    /// Bytes de cada acesso (1, 2, 4 ou 8).
    access: u8,
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
        let len = self.pkg_value()?;
        let end = start.checked_add(len).ok_or(Error::Malformed)?;
        if end > limit || end < self.p {
            return Err(Error::Malformed);
        }
        Ok(end)
    }

    /// O número codificado como `PkgLength` (até 28 bits).
    fn pkg_value(&mut self) -> Result<usize, Error> {
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
        Ok(len)
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
            0x12 => {
                let end = self.pkg_end(limit)?;
                self.package(end)?
            }
            _ => {
                self.p = start;
                self.term(limit, budget, 0)?;
                Value::Other
            }
        })
    }

    /// Corpo de um `Package` até `end`: o número de elementos e os bytes.
    fn package(&mut self, end: usize) -> Result<Value<'a>, Error> {
        if self.p >= end {
            return Err(Error::Malformed);
        }
        let count = self.u8()?;
        let data = self.b.get(self.p..end).ok_or(Error::Truncated)?;
        self.p = end;
        Ok(Value::Pkg { count, data })
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

impl<'a, F: FnMut(Event<'a>)> Walker<'a, F> {
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
                    sta_method: None,
                    crs_method: None,
                });
                self.body(pend, sub, &mut me)?;
                if let Some(d) = me {
                    (self.f)(Event::Device(d));
                }
                self.cur.p = pend;
            } else if op == 0x08 {
                let (root, up, segs, n) = self.cur.name()?;
                let v = self.cur.value(end, &mut self.budget)?;
                if let (Some(d), 1) = (dev.as_mut(), n) {
                    record(d, segs[0], &v);
                }
                let at = scope.child(root, up, &segs[..n])?;
                (self.f)(Event::Object(at, Item::Name(v)));
            } else if op == 0x14 {
                let pend = self.cur.pkg_end(end)?;
                let (root, up, segs, n) = self.cur.name()?;
                let flags = self.cur.u8()?;
                if self.cur.p > pend {
                    return Err(Error::Malformed);
                }
                let m = Method {
                    start: self.cur.p,
                    end: pend,
                    args: flags & 7,
                };
                if let (Some(d), 1) = (dev.as_mut(), n) {
                    match &segs[0] {
                        b"_STA" => d.sta_method = Some(m),
                        b"_CRS" => d.crs_method = Some(m),
                        _ => {}
                    }
                }
                let at = scope.child(root, up, &segs[..n])?;
                (self.f)(Event::Object(at, Item::Method(m)));
                self.cur.p = pend;
            } else if (op, ext) == (0x5B, 0x80) {
                let (root, up, segs, n) = self.cur.name()?;
                let space = self.cur.u8()?;
                let base = self.cur.value(end, &mut self.budget)?;
                let len = self.cur.value(end, &mut self.budget)?;
                let range = match (base, len) {
                    (Value::Int(b), Value::Int(l)) => Some((b, l)),
                    _ => None,
                };
                let at = scope.child(root, up, &segs[..n])?;
                (self.f)(Event::Object(at, Item::Region(space, range)));
            } else if (op, ext) == (0x5B, 0x81) {
                let pend = self.cur.pkg_end(end)?;
                self.fields(pend, &scope)?;
                self.cur.p = pend;
            } else {
                self.cur.p = start;
                self.cur.term(end, &mut self.budget, 0)?;
            }
        }
        Ok(())
    }
}

impl<'a, F: FnMut(Event<'a>)> Walker<'a, F> {
    /// Lista de campos de um `Field` até `pend`: cada nome vira um
    /// [`Item::Field`] no escopo atual. Para, sem erro, numa entrada que não
    /// conhece (conexão); o chamador salta o resto.
    fn fields(&mut self, pend: usize, scope: &Scope) -> Result<(), Error> {
        let (root, up, segs, n) = self.cur.name()?;
        let region = scope.child(root, up, &segs[..n])?;
        let mut access = self.cur.u8()? & 0x0F;
        let mut bit = 0u64;
        while self.cur.p < pend {
            self.budget.step(scope.depth)?;
            match self.cur.u8()? {
                0x00 => bit = bit.saturating_add(self.cur.pkg_value()? as u64),
                0x01 => access = self.cur.take(2)?[0] & 0x0F,
                0x03 => access = self.cur.take(3)?[0] & 0x0F,
                0x02 => return Ok(()),
                _ => {
                    self.cur.p -= 1;
                    let seg = self.cur.seg()?;
                    let bits = self.cur.pkg_value()? as u64;
                    let field = Field {
                        region,
                        bit,
                        bits,
                        // AnyAcc e ByteAcc leem byte a byte.
                        access: match access {
                            0 | 1 => 1,
                            2 => 2,
                            3 => 4,
                            4 => 8,
                            _ => 0,
                        },
                    };
                    let at = scope.child(false, 0, &[seg])?;
                    (self.f)(Event::Object(at, Item::Field(field)));
                    bit = bit.saturating_add(bits);
                }
            }
        }
        if self.cur.p > pend {
            return Err(Error::Malformed);
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
pub fn scan<'a>(
    aml: &'a [u8],
    limits: Limits,
    mut f: impl FnMut(&Device<'a>),
) -> Result<(), Error> {
    walk(aml, limits, |e| {
        if let Event::Device(d) = e {
            f(&d);
        }
    })
}

/// GSI de uma rota de `_PRT`: o índice, ou a interrupção estendida do
/// `_CRS` do dispositivo de ligação. `None` se a ligação não existe ou o
/// `_CRS` dela sai do subconjunto.
#[must_use]
pub fn route_gsi(aml: &[u8], route: &Route, width32: bool, limits: Limits) -> Option<u32> {
    let Some(link) = route.source else {
        return Some(route.index);
    };
    let mut gsi = None;
    let _ = scan(aml, limits, |d| {
        if gsi.is_none() && d.depth > 0 && d.path[d.depth - 1] == link {
            gsi = d
                .current_resources(aml, width32, limits)
                .ok()
                .and_then(|mut crs| {
                    crs.find_map(|r| match r {
                        Resource::Gsi { gsi } => Some(gsi),
                        _ => None,
                    })
                });
        }
    });
    gsi
}

/// Como [`scan`], com os `Name` e `Method` além dos `Device`.
fn walk<'a>(aml: &'a [u8], limits: Limits, f: impl FnMut(Event<'a>)) -> Result<(), Error> {
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
