//! Leitor DER estrito (X.690, seção 10): só a forma definida dos
//! comprimentos, com o menor número de bytes, e só etiquetas de um byte.
//! BER (comprimento indefinido, comprimento não mínimo, etiqueta longa) é
//! recusado. Nada aloca: cada valor é uma fatia da entrada.

use crate::Error;

/// Etiquetas universais usadas pelo X.509.
pub mod tag {
    /// BOOLEAN.
    pub const BOOLEAN: u8 = 0x01;
    /// INTEGER.
    pub const INTEGER: u8 = 0x02;
    /// BIT STRING.
    pub const BIT_STRING: u8 = 0x03;
    /// OCTET STRING.
    pub const OCTET_STRING: u8 = 0x04;
    /// NULL.
    pub const NULL: u8 = 0x05;
    /// OBJECT IDENTIFIER.
    pub const OID: u8 = 0x06;
    /// `UTCTime`.
    pub const UTC_TIME: u8 = 0x17;
    /// `GeneralizedTime`.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// SEQUENCE (construída).
    pub const SEQUENCE: u8 = 0x30;
    /// SET (construído).
    pub const SET: u8 = 0x31;
}

/// Um elemento TLV lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Etiqueta (um byte).
    pub tag: u8,
    /// Conteúdo, sem etiqueta nem comprimento.
    pub value: &'a [u8],
    /// O elemento inteiro, com etiqueta e comprimento.
    pub raw: &'a [u8],
}

/// Cursor sobre uma sequência de elementos DER.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Cursor no início de `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// `true` quando não sobra nada.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Etiqueta do próximo elemento, sem consumi-lo.
    #[must_use]
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Lê o próximo elemento, qualquer que seja a etiqueta.
    ///
    /// # Errors
    ///
    /// `Malformed` se a codificação não for DER; `TooLarge` se o comprimento
    /// precisar de mais de dois bytes.
    pub fn any(&mut self) -> Result<Tlv<'a>, Error> {
        let input = self.data;
        let (&t, rest) = input.split_first().ok_or(Error::Malformed)?;
        // Etiqueta longa (número ≥ 31): o X.509 não usa.
        if t & 0x1F == 0x1F {
            return Err(Error::Malformed);
        }
        let (&l0, rest) = rest.split_first().ok_or(Error::Malformed)?;
        let (len, rest) = match l0 {
            0..=0x7F => (usize::from(l0), rest),
            0x81 => match rest.split_first() {
                Some((&b, r)) if b >= 0x80 => (usize::from(b), r),
                _ => return Err(Error::Malformed),
            },
            0x82 => match rest {
                [a, b, r @ ..] if *a != 0 => (usize::from(*a) << 8 | usize::from(*b), r),
                _ => return Err(Error::Malformed),
            },
            // 0x80 é o comprimento indefinido do BER.
            0x80 => return Err(Error::Malformed),
            _ => return Err(Error::TooLarge),
        };
        if rest.len() < len {
            return Err(Error::Malformed);
        }
        let header = input.len() - rest.len();
        let (value, tail) = rest.split_at(len);
        self.data = tail;
        Ok(Tlv {
            tag: t,
            value,
            raw: &input[..header + len],
        })
    }

    /// Lê o próximo elemento e exige a etiqueta `t`.
    ///
    /// # Errors
    ///
    /// `Malformed` se a etiqueta for outra ou a codificação inválida.
    pub fn expect(&mut self, t: u8) -> Result<Tlv<'a>, Error> {
        let e = self.any()?;
        if e.tag == t {
            Ok(e)
        } else {
            Err(Error::Malformed)
        }
    }

    /// Lê o próximo elemento se ele tiver a etiqueta `t`.
    ///
    /// # Errors
    ///
    /// `Malformed` se a codificação for inválida.
    pub fn optional(&mut self, t: u8) -> Result<Option<Tlv<'a>>, Error> {
        if self.peek_tag() == Some(t) {
            self.any().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Conteúdo de uma SEQUENCE, como novo cursor.
    ///
    /// # Errors
    ///
    /// `Malformed` se o próximo elemento não for uma SEQUENCE válida.
    pub fn sequence(&mut self) -> Result<Reader<'a>, Error> {
        self.expect(tag::SEQUENCE).map(|e| Reader::new(e.value))
    }

    /// Exige que o cursor tenha chegado ao fim.
    ///
    /// # Errors
    ///
    /// `Malformed` se sobrarem bytes.
    pub fn finish(&self) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}

/// Lê exatamente um elemento com etiqueta `t` que ocupa `data` inteiro.
///
/// # Errors
///
/// `Malformed` se a etiqueta for outra ou se sobrarem bytes.
pub fn single(data: &[u8], t: u8) -> Result<Tlv<'_>, Error> {
    let mut r = Reader::new(data);
    let e = r.expect(t)?;
    r.finish()?;
    Ok(e)
}

/// Confere o conteúdo de um INTEGER (não vazio, sem byte inicial redundante).
///
/// # Errors
///
/// `Malformed` se a codificação não for a mínima.
pub fn integer(v: &[u8]) -> Result<&[u8], Error> {
    match v {
        [] | [0x00, 0x00..=0x7F, ..] | [0xFF, 0x80..=0xFF, ..] => Err(Error::Malformed),
        _ => Ok(v),
    }
}

/// INTEGER não negativo como `u64`.
///
/// # Errors
///
/// `Malformed` se for negativo ou mal codificado; `TooLarge` se não couber.
pub fn small_uint(v: &[u8]) -> Result<u64, Error> {
    let v = integer(v)?;
    if v[0] & 0x80 != 0 {
        return Err(Error::Malformed);
    }
    let v = if v[0] == 0 { &v[1..] } else { v };
    if v.len() > 8 {
        return Err(Error::TooLarge);
    }
    Ok(v.iter().fold(0, |acc, &b| acc << 8 | u64::from(b)))
}

/// BOOLEAN do DER (0x00 ou 0xFF).
///
/// # Errors
///
/// `Malformed` para qualquer outro conteúdo.
pub fn boolean(v: &[u8]) -> Result<bool, Error> {
    match v {
        [0x00] => Ok(false),
        [0xFF] => Ok(true),
        _ => Err(Error::Malformed),
    }
}

/// Confere um OBJECT IDENTIFIER: não vazio, base 128 sem zeros à esquerda e
/// sem subidentificador truncado.
///
/// # Errors
///
/// `Malformed` se a codificação for inválida.
pub fn oid(v: &[u8]) -> Result<&[u8], Error> {
    let mut start = true;
    for &b in v {
        if start && b == 0x80 {
            return Err(Error::Malformed);
        }
        start = b & 0x80 == 0;
    }
    if v.is_empty() || !start {
        return Err(Error::Malformed);
    }
    Ok(v)
}

/// Conteúdo de uma BIT STRING sem bits sobrando (assinaturas e chaves).
///
/// # Errors
///
/// `Malformed` se houver bits não usados ou se estiver vazia.
pub fn bit_string_bytes(v: &[u8]) -> Result<&[u8], Error> {
    match v {
        [0, rest @ ..] => Ok(rest),
        _ => Err(Error::Malformed),
    }
}

/// `UTCTime` (`AAMMDDhhmmssZ`) ou `GeneralizedTime` (`AAAAMMDDhhmmssZ`), como
/// segundos desde 1970-01-01 em UTC. O DER exige os segundos, o `Z` e
/// nenhuma fração; a RFC 5280 faz o `UTCTime` valer de 1950 a 2049.
///
/// # Errors
///
/// `Malformed` se o formato ou a data forem inválidos.
pub fn time(e: &Tlv<'_>) -> Result<i64, Error> {
    let (year, rest) = match (e.tag, e.value.len()) {
        (tag::UTC_TIME, 13) => {
            let yy = digits(&e.value[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &e.value[2..])
        }
        (tag::GENERALIZED_TIME, 15) => (digits(&e.value[..4])?, &e.value[4..]),
        _ => return Err(Error::Malformed),
    };
    if rest[10] != b'Z' {
        return Err(Error::Malformed);
    }
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let min = digits(&rest[6..8])?;
    let sec = digits(&rest[8..10])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || min > 59
        || sec > 59
    {
        return Err(Error::Malformed);
    }
    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + i64::from(hour * 3600 + min * 60 + sec))
}

fn digits(s: &[u8]) -> Result<u32, Error> {
    s.iter().try_fold(0, |acc, &c| {
        if c.is_ascii_digit() {
            Ok(acc * 10 + u32::from(c - b'0'))
        } else {
            Err(Error::Malformed)
        }
    })
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        2 if y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400)) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Dias desde 1970-01-01 (algoritmo `days_from_civil` de H. Hinnant).
fn days_from_civil(y: u32, m: u32, d: u32) -> i64 {
    let y = i64::from(y) - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
