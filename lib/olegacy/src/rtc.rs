//! RTC CMOS (portas 0x70 e 0x71).

/// Acesso aos registradores do CMOS (o driver escreve o índice em 0x70 e lê
/// 0x71).
pub trait Cmos {
    /// Lê o registrador `reg`.
    fn read(&mut self, reg: u8) -> u8;
}

/// Registrador de status A (bit 7: atualização em curso).
pub const STATUS_A: u8 = 0x0A;
/// Registrador de status B (bit 1: 24 h; bit 2: binário).
pub const STATUS_B: u8 = 0x0B;
/// Registrador de século padrão (o FADT pode indicar outro).
pub const CENTURY_DEFAULT: u8 = 0x32;
/// Tentativas de leitura estável antes de desistir.
pub const MAX_TRIES: u32 = 256;

#[derive(PartialEq, Eq, Clone, Copy)]
struct Raw {
    sec: u8,
    min: u8,
    hour: u8,
    day: u8,
    month: u8,
    year: u8,
    century: u8,
}

fn raw(c: &mut impl Cmos, century_reg: u8) -> Raw {
    Raw {
        sec: c.read(0x00),
        min: c.read(0x02),
        hour: c.read(0x04),
        day: c.read(0x07),
        month: c.read(0x08),
        year: c.read(0x09),
        century: if century_reg == 0 {
            0
        } else {
            c.read(century_reg)
        },
    }
}

fn bcd(v: u8) -> Option<u8> {
    let (h, l) = (v >> 4, v & 15);
    (h < 10 && l < 10).then_some(h * 10 + l)
}

/// Dias desde 1970-01-01 de uma data civil.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// Lê a data e a hora (UTC, como o `timed` assume; ADR 0037) em segundos
/// Unix. Espera a atualização do chip terminar e repete até duas leituras
/// seguidas coincidirem. `century_reg` é o registrador de século (0 se não
/// houver: vale 20xx).
///
/// Devolve `None` se o chip não estabilizar em [`MAX_TRIES`] leituras ou se
/// os valores forem inválidos (bateria fraca, CMOS zerado).
pub fn read_unix(c: &mut impl Cmos, century_reg: u8) -> Option<i64> {
    let mut prev = None;
    for _ in 0..MAX_TRIES {
        if c.read(STATUS_A) & 0x80 != 0 {
            continue;
        }
        let r = raw(c, century_reg);
        if prev == Some(r) {
            return convert(r, c.read(STATUS_B));
        }
        prev = Some(r);
    }
    None
}

fn convert(r: Raw, status_b: u8) -> Option<i64> {
    let binary = status_b & 4 != 0;
    let dec = |v: u8| if binary { Some(v) } else { bcd(v) };
    let pm = status_b & 2 == 0 && r.hour & 0x80 != 0;
    let hour = dec(r.hour & 0x7F)?;
    let hour = if status_b & 2 != 0 {
        hour
    } else {
        // 12 h: 12 AM é 0 h, 12 PM é 12 h.
        match (hour, pm) {
            (1..=12, false) => hour % 12,
            (1..=12, true) => hour % 12 + 12,
            _ => return None,
        }
    };
    let (sec, min, day, month) = (dec(r.sec)?, dec(r.min)?, dec(r.day)?, dec(r.month)?);
    let year = i64::from(dec(r.year)?);
    let century = if r.century == 0 {
        20
    } else {
        i64::from(dec(r.century)?)
    };
    if sec > 59 || min > 59 || hour > 23 || !(1..=31).contains(&day) || !(1..=12).contains(&month) {
        return None;
    }
    let days = days_from_civil(century * 100 + year, i64::from(month), i64::from(day));
    Some(days * 86_400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))
}
