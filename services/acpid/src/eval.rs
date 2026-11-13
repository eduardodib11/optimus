//! Execução de métodos AML (T-405; ADR 0045, itens 2 e 3).
//!
//! Subconjunto: inteiros, strings e buffers constantes, `Local0..7`,
//! `Arg0..6`, `Store`, aritmética e lógica, `If`/`Else`, `While` com
//! `Break` e `Continue`, `Return`, `SizeOf` e referências a `Name` e a
//! outros métodos, com a busca do espaço de nomes (do escopo para cima).
//! Um pacote é devolvido como está, sem avaliar os elementos. Gravar num
//! `Name` inteiro fica em [`State`] (poucas entradas), que vale entre
//! execuções; campos de `OperationRegion` dão [`Error::Unsupported`], e o
//! método é abortado.
//!
//! Sem alocação: cada nome é achado varrendo a tabela de novo, e o número
//! de varreduras ([`MAX_WALKS`]), de operações e de aninhamento é limitado.

use crate::{Budget, Cur, Error, Event, Item, Limits, NameSeg, Scope, Value, walk};

/// Corpo de um método dentro do AML da tabela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Method {
    /// Primeiro byte do corpo.
    pub start: usize,
    /// Fim do corpo.
    pub end: usize,
    /// Número de argumentos (0 a 7).
    pub args: u8,
}

/// Varreduras da tabela (buscas de nome) por execução.
pub const MAX_WALKS: u32 = 64;

/// Entradas de [`State`].
pub const MAX_STATE: usize = 8;

/// Inteiros gravados por métodos em objetos `Name` (por exemplo o `PICF`
/// que o `_PIC` grava). Sem alocação: até [`MAX_STATE`] nomes.
#[derive(Clone, Copy)]
pub struct State {
    names: [(Scope, u64); MAX_STATE],
    len: usize,
}

impl Default for State {
    fn default() -> Self {
        let empty = Scope {
            path: [[0; 4]; crate::MAX_DEPTH],
            depth: 0,
        };
        Self {
            names: [(empty, 0); MAX_STATE],
            len: 0,
        }
    }
}

impl State {
    fn slot(&mut self, at: &Scope) -> Option<&mut u64> {
        self.names[..self.len]
            .iter_mut()
            .find(|(s, _)| s.path[..s.depth] == at.path[..at.depth])
            .map(|(_, v)| v)
    }

    fn set(&mut self, at: Scope, v: u64) -> Result<(), Error> {
        if let Some(old) = self.slot(&at) {
            *old = v;
            return Ok(());
        }
        *self.names.get_mut(self.len).ok_or(Error::Limit)? = (at, v);
        self.len += 1;
        Ok(())
    }
}

/// Como um bloco terminou.
enum Flow<'a> {
    Next,
    Break,
    Continue,
    Return(Value<'a>),
}

/// Locais, argumentos e escopo de uma chamada.
struct Frame<'a> {
    locals: [Value<'a>; 8],
    args: [Value<'a>; 7],
    scope: Scope,
}

struct Interp<'a, 's> {
    aml: &'a [u8],
    state: &'s mut State,
    cur: Cur<'a>,
    budget: Budget,
    limits: Limits,
    walks: u32,
    /// Máscara dos inteiros: 32 ou 64 bits.
    mask: u64,
}

/// Executa `method`, sem argumentos, com o escopo `path` (o do objeto que o
/// contém). `width32` vem de [`crate::Header::width32`].
///
/// # Errors
/// [`Error::Unsupported`] fora do subconjunto, [`Error::Limit`] ao estourar
/// um limite e os erros de leitura; nunca pânico.
pub fn eval<'a>(
    aml: &'a [u8],
    path: &[NameSeg],
    method: Method,
    width32: bool,
    limits: Limits,
) -> Result<Value<'a>, Error> {
    run(
        aml,
        path,
        method,
        &[],
        width32,
        limits,
        &mut State::default(),
    )
}

/// Chama `\_PIC (mode)` (1 escolhe o modo APIC), para o `_PRT` devolver as
/// rotas em GSIs. Devolve `false` se a tabela não tem `_PIC`.
///
/// # Errors
/// Os de [`eval`].
pub fn pic_mode(
    aml: &[u8],
    mode: u64,
    width32: bool,
    limits: Limits,
    state: &mut State,
) -> Result<bool, Error> {
    let mut found = None;
    walk(aml, limits, |e| {
        if let Event::Object(at, Item::Method(m)) = e
            && at.depth == 1
            && at.path[0] == *b"_PIC"
        {
            found = Some(m);
        }
    })?;
    let Some(m) = found else { return Ok(false) };
    run(aml, &[], m, &[mode], width32, limits, state).map(|_| true)
}

/// Como [`eval`], com argumentos inteiros e o estado entre execuções.
pub(crate) fn run<'a>(
    aml: &'a [u8],
    path: &[NameSeg],
    method: Method,
    args: &[u64],
    width32: bool,
    limits: Limits,
    state: &mut State,
) -> Result<Value<'a>, Error> {
    let root = Scope {
        path: [[0; 4]; crate::MAX_DEPTH],
        depth: 0,
    };
    let scope = root.child(true, 0, path)?;
    let mut values = [Value::Other; 7];
    for (v, a) in values.iter_mut().zip(args) {
        *v = Value::Int(*a);
    }
    let mut i = Interp {
        aml,
        state,
        cur: Cur { b: aml, p: 0 },
        budget: Budget { limits, ops: 0 },
        limits,
        walks: 0,
        mask: if width32 { 0xFFFF_FFFF } else { u64::MAX },
    };
    i.call(method, scope, values, 0)
}

impl<'a> Interp<'a, '_> {
    fn call(
        &mut self,
        m: Method,
        scope: Scope,
        args: [Value<'a>; 7],
        depth: usize,
    ) -> Result<Value<'a>, Error> {
        if m.start > m.end || m.end > self.aml.len() {
            return Err(Error::Malformed);
        }
        let mut frame = Frame {
            locals: [Value::Other; 8],
            args,
            scope,
        };
        let back = core::mem::replace(&mut self.cur.p, m.start);
        let flow = self.block(m.end, &mut frame, depth);
        self.cur.p = back;
        Ok(match flow? {
            Flow::Return(v) => v,
            _ => Value::Other,
        })
    }

    fn peek(&self) -> Option<u8> {
        self.aml.get(self.cur.p).copied()
    }

    /// Executa os termos até `end`.
    fn block(&mut self, end: usize, fr: &mut Frame<'a>, depth: usize) -> Result<Flow<'a>, Error> {
        while self.cur.p < end {
            self.budget.step(depth)?;
            match self.peek() {
                Some(0xA0) => {
                    self.cur.p += 1;
                    let pend = self.cur.pkg_end(end)?;
                    let taken = self.int(pend, fr, depth + 1)? != 0;
                    if taken {
                        match self.block(pend, fr, depth + 1)? {
                            Flow::Next => {}
                            other => return Ok(other),
                        }
                    }
                    self.cur.p = pend;
                    if pend < end && self.peek() == Some(0xA1) {
                        self.cur.p += 1;
                        let other_end = self.cur.pkg_end(end)?;
                        if !taken {
                            match self.block(other_end, fr, depth + 1)? {
                                Flow::Next => {}
                                other => return Ok(other),
                            }
                        }
                        self.cur.p = other_end;
                    }
                }
                Some(0xA2) => {
                    self.cur.p += 1;
                    let pend = self.cur.pkg_end(end)?;
                    let top = self.cur.p;
                    loop {
                        self.budget.step(depth)?;
                        self.cur.p = top;
                        if self.int(pend, fr, depth + 1)? == 0 {
                            break;
                        }
                        match self.block(pend, fr, depth + 1)? {
                            Flow::Break => break,
                            Flow::Return(v) => return Ok(Flow::Return(v)),
                            Flow::Next | Flow::Continue => {}
                        }
                    }
                    self.cur.p = pend;
                }
                Some(0xA4) => {
                    self.cur.p += 1;
                    return Ok(Flow::Return(self.expr(end, fr, depth + 1)?));
                }
                Some(0xA5) => {
                    self.cur.p += 1;
                    return Ok(Flow::Break);
                }
                Some(0x9F) => {
                    self.cur.p += 1;
                    return Ok(Flow::Continue);
                }
                Some(0xA3) => self.cur.p += 1,
                _ => drop(self.expr(end, fr, depth + 1)?),
            }
        }
        Ok(Flow::Next)
    }

    fn int(&mut self, limit: usize, fr: &mut Frame<'a>, depth: usize) -> Result<u64, Error> {
        match self.expr(limit, fr, depth)? {
            Value::Int(v) => Ok(v),
            _ => Err(Error::Unsupported),
        }
    }

    fn truth(&self, b: bool) -> Value<'a> {
        Value::Int(if b { self.mask } else { 0 })
    }

    /// `Local` ou `Arg` do opcode `op`.
    fn slot<'f>(op: u8, fr: &'f mut Frame<'a>) -> Result<&'f mut Value<'a>, Error> {
        match op {
            0x60..=0x67 => Ok(&mut fr.locals[usize::from(op - 0x60)]),
            0x68..=0x6E => Ok(&mut fr.args[usize::from(op - 0x68)]),
            _ => Err(Error::Unsupported),
        }
    }

    /// Grava `v` no destino que vem a seguir: nenhum (`Zero`), `Local`,
    /// `Arg` ou um `Name` inteiro, que fica em [`State`].
    fn store(&mut self, v: Value<'a>, fr: &mut Frame<'a>) -> Result<(), Error> {
        match self.cur.u8()? {
            0x00 => {}
            op @ 0x60..=0x6E => *Self::slot(op, fr)? = v,
            _ => {
                self.cur.p -= 1;
                let (root, up, segs, n) = self.cur.name()?;
                let found = self.lookup(&fr.scope, root, up, &segs[..n])?;
                let (Some((at, Item::Name(Value::Int(_)))), Value::Int(v)) = (found, v) else {
                    return Err(Error::Unsupported);
                };
                self.state.set(at, v)?;
            }
        }
        Ok(())
    }

    /// Avalia uma expressão.
    #[allow(clippy::too_many_lines)]
    fn expr(&mut self, limit: usize, fr: &mut Frame<'a>, depth: usize) -> Result<Value<'a>, Error> {
        self.budget.step(depth)?;
        if self.cur.p >= limit {
            return Err(Error::Truncated);
        }
        let op = self.cur.u8()?;
        let v = match op {
            0x00 => Value::Int(0),
            0x01 => Value::Int(1),
            0xFF => Value::Int(self.mask),
            0x0A => Value::Int(self.cur.le(1)?),
            0x0B => Value::Int(self.cur.le(2)?),
            0x0C => Value::Int(self.cur.le(4)?),
            0x0E => Value::Int(self.cur.le(8)? & self.mask),
            0x0D => Value::Str(self.cur.string(limit)?),
            0x11 => {
                let end = self.cur.pkg_end(limit)?;
                self.int(end, fr, depth + 1)?;
                let data = self.aml.get(self.cur.p..end).ok_or(Error::Truncated)?;
                self.cur.p = end;
                Value::Buf(data)
            }
            0x12 => {
                let end = self.cur.pkg_end(limit)?;
                self.cur.package(end)?
            }
            0x60..=0x6E => *Self::slot(op, fr)?,
            0x70 => {
                let v = self.expr(limit, fr, depth + 1)?;
                self.store(v, fr)?;
                v
            }
            0x72 | 0x74 | 0x77 | 0x79..=0x7F | 0x85 => {
                let a = self.int(limit, fr, depth + 1)?;
                let b = self.int(limit, fr, depth + 1)?;
                let shift = u32::try_from(b).ok().filter(|s| *s < 64);
                let r = match op {
                    0x72 => a.wrapping_add(b),
                    0x74 => a.wrapping_sub(b),
                    0x77 => a.wrapping_mul(b),
                    0x79 => shift.map_or(0, |s| a << s),
                    0x7A => shift.map_or(0, |s| a >> s),
                    0x7B => a & b,
                    0x7C => !(a & b),
                    0x7D => a | b,
                    0x7E => !(a | b),
                    0x7F => a ^ b,
                    _ => a.checked_rem(b).ok_or(Error::Unsupported)?,
                };
                let v = Value::Int(r & self.mask);
                self.store(v, fr)?;
                v
            }
            0x78 => {
                let a = self.int(limit, fr, depth + 1)?;
                let b = self.int(limit, fr, depth + 1)?;
                let q = a.checked_div(b).ok_or(Error::Unsupported)?;
                self.store(Value::Int(a % b), fr)?;
                self.store(Value::Int(q), fr)?;
                Value::Int(q)
            }
            0x80 => {
                let v = Value::Int(!self.int(limit, fr, depth + 1)? & self.mask);
                self.store(v, fr)?;
                v
            }
            0x75 | 0x76 => {
                let mask = self.mask;
                let slot = Self::slot(self.cur.u8()?, fr)?;
                let Value::Int(n) = *slot else {
                    return Err(Error::Unsupported);
                };
                let n = if op == 0x75 {
                    n.wrapping_add(1)
                } else {
                    n.wrapping_sub(1)
                };
                *slot = Value::Int(n & mask);
                *slot
            }
            0x90 | 0x91 | 0x93..=0x95 => {
                let a = self.int(limit, fr, depth + 1)?;
                let b = self.int(limit, fr, depth + 1)?;
                self.truth(match op {
                    0x90 => a != 0 && b != 0,
                    0x91 => a != 0 || b != 0,
                    0x93 => a == b,
                    0x94 => a > b,
                    _ => a < b,
                })
            }
            0x92 => {
                let a = self.int(limit, fr, depth + 1)?;
                self.truth(a == 0)
            }
            0x87 => match *Self::slot(self.cur.u8()?, fr)? {
                Value::Buf(b) => Value::Int(b.len() as u64),
                Value::Str(s) => Value::Int(s.len() as u64),
                _ => return Err(Error::Unsupported),
            },
            b'A'..=b'Z' | b'_' | b'\\' | b'^' | 0x2E | 0x2F => {
                self.cur.p -= 1;
                let (root, up, segs, n) = self.cur.name()?;
                self.named(root, up, &segs[..n], limit, fr, depth)?
            }
            _ => return Err(Error::Unsupported),
        };
        if self.cur.p > limit {
            return Err(Error::Malformed);
        }
        Ok(v)
    }

    /// Valor de um nome: um `Name`, ou a chamada de um método (os
    /// argumentos vêm a seguir).
    fn named(
        &mut self,
        root: bool,
        up: usize,
        segs: &[NameSeg],
        limit: usize,
        fr: &mut Frame<'a>,
        depth: usize,
    ) -> Result<Value<'a>, Error> {
        match self.lookup(&fr.scope, root, up, segs)? {
            Some((at, Item::Name(v))) => Ok(match (v, self.state.slot(&at)) {
                (Value::Int(_), Some(now)) => Value::Int(*now),
                _ => v,
            }),
            Some((at, Item::Method(m))) => {
                let mut args = [Value::Other; 7];
                for a in args.iter_mut().take(usize::from(m.args)) {
                    *a = self.expr(limit, fr, depth + 1)?;
                }
                self.call(m, at, args, depth + 1)
            }
            None => Err(Error::Unsupported),
        }
    }

    /// Acha o objeto pelo nome: caminho relativo ao escopo; um nome simples
    /// é procurado também nos escopos de cima.
    fn lookup(
        &mut self,
        scope: &Scope,
        root: bool,
        up: usize,
        segs: &[NameSeg],
    ) -> Result<Option<(Scope, Item<'a>)>, Error> {
        let upward = !root && up == 0 && segs.len() == 1;
        let mut base = *scope;
        loop {
            let Ok(target) = base.child(root, up, segs) else {
                return Ok(None);
            };
            self.walks += 1;
            if self.walks > MAX_WALKS {
                return Err(Error::Limit);
            }
            let mut found = None;
            walk(self.aml, self.limits, |e| {
                if let Event::Object(at, item) = e
                    && found.is_none()
                    && at.path[..at.depth] == target.path[..target.depth]
                {
                    found = Some(item);
                }
            })?;
            if let Some(item) = found {
                return Ok(Some((target, item)));
            }
            if !upward || base.depth == 0 {
                return Ok(None);
            }
            base.depth -= 1;
        }
    }
}
