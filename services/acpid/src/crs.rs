//! Decodificação do buffer `_CRS` (descritores de recurso ACPI).

/// Um recurso de `_CRS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    /// Intervalo de portas de E/S.
    Io {
        /// Base.
        base: u16,
        /// Tamanho.
        len: u16,
    },
    /// Intervalo de memória de 32 bits.
    Mem {
        /// Base.
        base: u32,
        /// Tamanho.
        len: u32,
    },
    /// Máscara de IRQs (bit `n` = IRQ `n`).
    Irq {
        /// Máscara.
        mask: u16,
    },
    /// Interrupção estendida: o primeiro GSI do descritor.
    Gsi {
        /// Número global da interrupção.
        gsi: u32,
    },
}

/// Iterador sobre um buffer `_CRS`. Para no fim, no descritor de fim ou no
/// primeiro descritor truncado; descritores que não conhece são saltados.
pub struct Resources<'a> {
    b: &'a [u8],
}

impl<'a> Resources<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b }
    }
}

impl Iterator for Resources<'_> {
    type Item = Resource;

    fn next(&mut self) -> Option<Resource> {
        loop {
            let tag = *self.b.first()?;
            let (name, hdr, len) = if tag & 0x80 == 0 {
                ((tag >> 3) & 0xF, 1usize, usize::from(tag & 7))
            } else {
                let l = self.b.get(1..3)?;
                (tag & 0x7F, 3, usize::from(u16::from_le_bytes([l[0], l[1]])))
            };
            let body = self.b.get(hdr..hdr.checked_add(len)?)?;
            let large = tag & 0x80 != 0;
            self.b = &self.b[hdr + len..];
            let u16_at = |i: usize| u16::from_le_bytes([body[i], body[i + 1]]);
            let u32_at =
                |i: usize| u32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
            match (large, name, len) {
                (false, 0xF, _) => {
                    self.b = &[];
                    return None;
                }
                (false, 0x4, 2 | 3) => return Some(Resource::Irq { mask: u16_at(0) }),
                (false, 0x8, 7) => {
                    return Some(Resource::Io {
                        base: u16_at(1),
                        len: u16::from(body[6]),
                    });
                }
                (false, 0x9, 3) => {
                    return Some(Resource::Io {
                        base: u16_at(0),
                        len: u16::from(body[2]),
                    });
                }
                (true, 0x6, 9) => {
                    return Some(Resource::Mem {
                        base: u32_at(1),
                        len: u32_at(5),
                    });
                }
                (true, 0x9, 6..) if body[1] >= 1 => return Some(Resource::Gsi { gsi: u32_at(2) }),
                _ => {}
            }
        }
    }
}
