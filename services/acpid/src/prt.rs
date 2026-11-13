//! Decodificação do pacote `_PRT`: as rotas de interrupção `INTx` do PCI.
//!
//! Cada elemento é um pacote `{endereço, pino, origem, índice}`. Com a
//! origem zero, o índice é o GSI; com um nome, a interrupção é a do `_CRS`
//! do dispositivo de ligação com esse nome.

use crate::{Cur, NameSeg};

/// Uma rota de `_PRT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Dispositivo PCI no barramento (os 16 bits altos do endereço).
    pub device: u16,
    /// Pino: 0 é INTA, 3 é INTD.
    pub pin: u8,
    /// Dispositivo de ligação (o último nome do caminho); `None` quando
    /// `index` já é o GSI.
    pub source: Option<NameSeg>,
    /// GSI, ou o índice dentro da origem.
    pub index: u32,
}

/// Iterador sobre as rotas. Para no fim ou no primeiro elemento que não é
/// uma rota bem formada.
pub struct Routes<'a> {
    cur: Cur<'a>,
}

impl<'a> Routes<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            cur: Cur { b: data, p: 0 },
        }
    }

    fn int(&mut self) -> Option<u64> {
        match self.cur.u8().ok()? {
            0x00 => Some(0),
            0x01 => Some(1),
            0xFF => Some(u64::MAX),
            0x0A => self.cur.le(1).ok(),
            0x0B => self.cur.le(2).ok(),
            0x0C => self.cur.le(4).ok(),
            0x0E => self.cur.le(8).ok(),
            _ => None,
        }
    }

    fn route(&mut self) -> Option<Route> {
        if self.cur.u8().ok()? != 0x12 {
            return None;
        }
        let end = self.cur.pkg_end(self.cur.b.len()).ok()?;
        if self.cur.u8().ok()? != 4 {
            return None;
        }
        let address = self.int()?;
        let pin = u8::try_from(self.int()?).ok().filter(|p| *p < 4)?;
        let source = if self.cur.b.get(self.cur.p) == Some(&0) {
            self.cur.p += 1;
            None
        } else {
            let (_, _, segs, n) = self.cur.name().ok()?;
            Some(*segs[..n].last()?)
        };
        let index = u32::try_from(self.int()?).ok()?;
        if self.cur.p != end {
            return None;
        }
        Some(Route {
            device: u16::try_from((address >> 16) & 0xFFFF).ok()?,
            pin,
            source,
            index,
        })
    }
}

impl Iterator for Routes<'_> {
    type Item = Route;

    fn next(&mut self) -> Option<Route> {
        let r = self.route();
        if r.is_none() {
            self.cur.p = self.cur.b.len();
        }
        r
    }
}
