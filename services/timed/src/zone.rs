//! Fusos horários no formato `OTZ1` (T-359; ADR 0037, item 5).
//!
//! Leitura sem cópia e sem alocação do blob gerado pelo `tools/mktz`. Todos
//! os inteiros são little-endian. Layout:
//!
//! ```text
//! cabeçalho (84 B): "OTZ1", version u32 (=1), n_trans u32, n_types u32,
//!                   n_chars u32, nome[64] (NUL no fim, até 63 bytes)
//! tipos:            n_types × { utc_offset i32 (s), dst u8, abbr_off u8 }
//! abreviações:      n_chars bytes, cada abreviação termina em NUL
//! transições:       n_trans × { at_unix_s i64, type u8 }, em ordem
//! cauda:            len u8 + regra POSIX TZ ("EST5EDT,M3.2.0,M11.1.0")
//! ```
//!
//! Antes da primeira transição vale o tipo 0. Depois da última, a cauda
//! (se houver; só a forma `Mm.w.d`) ou o último tipo.

/// Cabeçalho, em bytes.
pub const HEADER_LEN: usize = 84;

/// Erros do fuso.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZoneError {
    /// Blob inválido ou truncado.
    Malformed,
    /// Regra POSIX fora da forma suportada.
    Unsupported,
}

/// Hora local de um instante (`optimus.time.LocalTime`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalTime {
    /// Deslocamento para leste do UTC, em segundos.
    pub offset_s: i32,
    /// Horário de verão em vigor.
    pub dst: bool,
    abbr: [u8; 8],
    abbr_len: u8,
}

impl LocalTime {
    fn new(offset_s: i32, dst: bool, abbr: &[u8]) -> Self {
        let n = abbr.len().min(8);
        let mut a = [0; 8];
        a[..n].copy_from_slice(&abbr[..n]);
        Self {
            offset_s,
            dst,
            abbr: a,
            abbr_len: u8::try_from(n).unwrap_or(8),
        }
    }

    /// Abreviação (`-03`, `EST`).
    #[must_use]
    pub fn abbr(&self) -> &[u8] {
        &self.abbr[..usize::from(self.abbr_len)]
    }
}

/// Um fuso lido de um blob `OTZ1`.
#[derive(Clone, Copy, Debug)]
pub struct Zone<'a> {
    name: &'a [u8],
    types: &'a [u8],
    chars: &'a [u8],
    trans: &'a [u8],
    tail: &'a [u8],
}

fn u32_at(b: &[u8], i: usize) -> Result<usize, ZoneError> {
    let w = b.get(i..i + 4).ok_or(ZoneError::Malformed)?;
    Ok(u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as usize)
}

impl<'a> Zone<'a> {
    /// Valida e abre o blob.
    ///
    /// # Errors
    /// [`ZoneError::Malformed`] se faltar byte, a versão não for 1 ou um
    /// índice de tipo ou de abreviação apontar para fora.
    pub fn parse(b: &'a [u8]) -> Result<Self, ZoneError> {
        if b.get(..4) != Some(b"OTZ1") || u32_at(b, 4)? != 1 {
            return Err(ZoneError::Malformed);
        }
        let (nt, ny, nc) = (u32_at(b, 8)?, u32_at(b, 12)?, u32_at(b, 16)?);
        let raw = b.get(20..HEADER_LEN).ok_or(ZoneError::Malformed)?;
        let name_len = raw
            .iter()
            .position(|c| *c == 0)
            .ok_or(ZoneError::Malformed)?;
        let sz = |n: usize, m: usize| n.checked_mul(m).ok_or(ZoneError::Malformed);
        let mut p = HEADER_LEN;
        let mut take = |n: usize| -> Result<&'a [u8], ZoneError> {
            let s = b
                .get(p..p.checked_add(n).ok_or(ZoneError::Malformed)?)
                .ok_or(ZoneError::Malformed)?;
            p += n;
            Ok(s)
        };
        let (types, chars, trans) = (take(sz(ny, 6)?)?, take(nc)?, take(sz(nt, 9)?)?);
        let tail_len = usize::from(take(1)?[0]);
        let tail = take(tail_len)?;
        if ny == 0 || types.chunks(6).any(|t| usize::from(t[5]) >= nc) {
            return Err(ZoneError::Malformed);
        }
        if trans.chunks(9).any(|t| usize::from(t[8]) >= ny) {
            return Err(ZoneError::Malformed);
        }
        Ok(Self {
            name: &raw[..name_len],
            types,
            chars,
            trans,
            tail,
        })
    }

    /// Nome (`America/Sao_Paulo`).
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    fn of_type(&self, i: usize) -> LocalTime {
        let t = &self.types[i * 6..i * 6 + 6];
        let off = i32::from_le_bytes([t[0], t[1], t[2], t[3]]);
        let rest = &self.chars[usize::from(t[5])..];
        let n = rest.iter().position(|c| *c == 0).unwrap_or(rest.len());
        LocalTime::new(off, t[4] != 0, &rest[..n])
    }

    fn trans_at(&self, i: usize) -> (i64, usize) {
        let t = &self.trans[i * 9..i * 9 + 9];
        let at = i64::from_le_bytes([t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]]);
        (at, usize::from(t[8]))
    }

    /// Hora local de `unix_s`.
    ///
    /// # Errors
    /// [`ZoneError::Unsupported`] se a cauda usar uma forma que o `OTZ1` v1
    /// não aceita; [`ZoneError::Malformed`] se ela for inválida.
    pub fn local(&self, unix_s: i64) -> Result<LocalTime, ZoneError> {
        let n = self.trans.len() / 9;
        if n == 0 || unix_s < self.trans_at(0).0 {
            return Ok(self.of_type(0));
        }
        let last = self.trans_at(n - 1);
        if unix_s >= last.0 {
            return if self.tail.is_empty() {
                Ok(self.of_type(last.1))
            } else {
                posix(self.tail, unix_s)
            };
        }
        // Última transição com `at <= unix_s`.
        let (mut lo, mut hi) = (0, n - 1);
        while lo + 1 < hi {
            let mid = lo.midpoint(hi);
            if self.trans_at(mid).0 <= unix_s {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let i = if self.trans_at(hi).0 <= unix_s {
            hi
        } else {
            lo
        };
        Ok(self.of_type(self.trans_at(i).1))
    }
}

/// Dias desde 1970-01-01 de uma data civil (Howard Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

fn year_of(days: i64) -> i64 {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    yoe + era * 400 + i64::from(mp >= 10)
}

struct Rule {
    month: i64,
    week: i64,
    wday: i64,
    time: i64,
}

impl Rule {
    /// Segundos Unix locais (sem o deslocamento) do `Mm.w.d/hh` no ano `y`.
    fn local_secs(&self, y: i64) -> i64 {
        let first = days_from_civil(y, self.month, 1);
        let wd = (first + 4).rem_euclid(7);
        let mut day = 1 + (self.wday - wd).rem_euclid(7) + 7 * (self.week - 1);
        let next = if self.month == 12 {
            days_from_civil(y + 1, 1, 1)
        } else {
            days_from_civil(y, self.month + 1, 1)
        };
        while first + day > next {
            day -= 7;
        }
        (first + day - 1) * 86_400 + self.time
    }
}

struct P<'a>(&'a [u8]);

impl<'a> P<'a> {
    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.0 = &self.0[1..];
        Some(c)
    }

    fn name(&mut self) -> Result<&'a [u8], ZoneError> {
        let quoted = self.peek() == Some(b'<');
        if quoted {
            self.bump();
        }
        let n = self
            .0
            .iter()
            .position(|c| {
                if quoted {
                    *c == b'>'
                } else {
                    !c.is_ascii_alphabetic()
                }
            })
            .unwrap_or(self.0.len());
        let (s, rest) = self.0.split_at(n);
        self.0 = if quoted {
            rest.get(1..).ok_or(ZoneError::Malformed)?
        } else {
            rest
        };
        if s.len() < 3 {
            Err(ZoneError::Malformed)
        } else {
            Ok(s)
        }
    }

    fn num(&mut self) -> Result<i64, ZoneError> {
        let n = self.0.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 || n > 4 {
            return Err(ZoneError::Malformed);
        }
        let (d, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(d.iter().fold(0, |a, c| a * 10 + i64::from(c - b'0')))
    }

    /// `[+-]hh[:mm[:ss]]`, em segundos.
    fn hms(&mut self) -> Result<i64, ZoneError> {
        let neg = match self.peek() {
            Some(b'-') => {
                self.bump();
                true
            }
            Some(b'+') => {
                self.bump();
                false
            }
            _ => false,
        };
        let mut v = self.num()? * 3600;
        for unit in [60, 1] {
            if self.peek() != Some(b':') {
                break;
            }
            self.bump();
            v += self.num()? * unit;
        }
        Ok(if neg { -v } else { v })
    }

    fn rule(&mut self) -> Result<Rule, ZoneError> {
        if self.bump() != Some(b'M') {
            return Err(ZoneError::Unsupported);
        }
        let month = self.num()?;
        if self.bump() != Some(b'.') {
            return Err(ZoneError::Malformed);
        }
        let week = self.num()?;
        if self.bump() != Some(b'.') {
            return Err(ZoneError::Malformed);
        }
        let wday = self.num()?;
        let time = if self.peek() == Some(b'/') {
            self.bump();
            self.hms()?
        } else {
            7200
        };
        if !(1..=12).contains(&month) || !(1..=5).contains(&week) || wday > 6 {
            return Err(ZoneError::Malformed);
        }
        Ok(Rule {
            month,
            week,
            wday,
            time,
        })
    }
}

/// Avalia uma regra POSIX TZ em `unix_s`.
fn posix(tz: &[u8], unix_s: i64) -> Result<LocalTime, ZoneError> {
    let mut p = P(tz);
    let std = p.name()?;
    let std_off = -p.hms()?;
    let std_t = || LocalTime::new(i32::try_from(std_off).unwrap_or(0), false, std);
    if p.peek().is_none() {
        return Ok(std_t());
    }
    let dst = p.name()?;
    let dst_off = if matches!(p.peek(), Some(b',') | None) {
        std_off + 3600
    } else {
        -p.hms()?
    };
    if p.bump() != Some(b',') {
        return Err(ZoneError::Unsupported);
    }
    let start = p.rule()?;
    if p.bump() != Some(b',') {
        return Err(ZoneError::Malformed);
    }
    let end = p.rule()?;
    let y = year_of((unix_s + std_off).div_euclid(86_400));
    // O início é dado na hora padrão; o fim, na hora de verão.
    let (s, e) = (start.local_secs(y) - std_off, end.local_secs(y) - dst_off);
    let is_dst = if s < e {
        unix_s >= s && unix_s < e
    } else {
        unix_s >= s || unix_s < e
    };
    Ok(if is_dst {
        LocalTime::new(i32::try_from(dst_off).unwrap_or(0), true, dst)
    } else {
        std_t()
    })
}
