//! Unidades de AMD-Vi pela IVRS (ADR 0044, item 1; T-403).
//!
//! A IVRS lista as IOMMUs da AMD em blocos IVHD (tipos 0x10, 0x11 e 0x40),
//! cada um com o endereço dos registradores, o grupo de segmentos, o BDF da
//! própria IOMMU e as entradas de dispositivo que ela cobre. Entram as
//! entradas `ALL` (1), `SELECT` (2) e as faixas `START`/`END` (3 e 4); as
//! de apelido e de nome ACPI são contadas e o dispositivo fica sem
//! unidade, e o `dma_attach` dele falha (fechado). Só o grupo 0 entra.

use super::{AcpiError, HEADER, PhysRead, find, u64_at};

/// Unidades guardadas.
pub const MAX_UNITS: usize = 8;
/// Faixas de dispositivos guardadas por unidade.
pub const MAX_RANGES: usize = 16;

/// Uma IOMMU da AMD.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unit {
    /// Endereço físico dos registradores.
    pub base: u64,
    /// BDF da própria IOMMU.
    pub bdf: u16,
    /// Cobre todos os dispositivos (entrada `ALL`).
    pub all: bool,
    ranges: [(u16, u16); MAX_RANGES],
    count: usize,
    /// Entradas que não entraram (apelidos, nomes ACPI, além do teto).
    pub skipped: u32,
}

impl Unit {
    /// Faixas `[primeiro, último]` de BDFs cobertos.
    #[must_use]
    pub fn ranges(&self) -> &[(u16, u16)] {
        &self.ranges[..self.count]
    }

    /// `bdf` está no escopo desta unidade.
    #[must_use]
    pub fn covers(&self, bdf: u16) -> bool {
        self.all || self.ranges().iter().any(|&(a, b)| (a..=b).contains(&bdf))
    }

    fn push(&mut self, first: u16, last: u16) {
        if self.count < MAX_RANGES && first <= last {
            self.ranges[self.count] = (first, last);
            self.count += 1;
        } else {
            self.skipped += 1;
        }
    }

    fn parse(&mut self, mut entries: &[u8]) {
        let mut start = None;
        while let [kind, ..] = *entries {
            // 4 bytes até 63, 8 até 127; os de tamanho variável (0xF0) levam
            // o tamanho no byte 21.
            let len = match kind {
                0..=63 => 4,
                64..=127 => 8,
                0xf0 => entries.get(21).map_or(usize::MAX, |&l| 22 + usize::from(l)),
                _ => usize::MAX,
            };
            let Some(e) = entries.get(..len) else {
                self.skipped += 1;
                return;
            };
            let id = u16::from_le_bytes([e[1], e[2]]);
            match kind {
                1 => self.all = true,
                2 => self.push(id, id),
                3 => start = Some(id),
                4 => match start.take() {
                    Some(s) => self.push(s, id),
                    None => self.skipped += 1,
                },
                0 => {}
                _ => self.skipped += 1,
            }
            entries = &entries[len..];
        }
    }
}

/// O que a IVRS diz.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ivrs {
    units: [Unit; MAX_UNITS],
    count: usize,
    /// Blocos pulados: outro grupo, além do teto ou estragados.
    pub skipped: u32,
}

impl Ivrs {
    /// As unidades, uma por IOMMU (o primeiro bloco de cada endereço).
    #[must_use]
    pub fn units(&self) -> &[Unit] {
        &self.units[..self.count]
    }

    /// Índice da unidade que cobre `bdf`: a que o lista, senão a de `ALL`.
    #[must_use]
    pub fn unit_for(&self, bdf: u16) -> Option<usize> {
        let mut units = self.units().iter().enumerate();
        let listed = units
            .clone()
            .find(|(_, u)| u.ranges().iter().any(|&(a, b)| (a..=b).contains(&bdf)));
        listed
            .or_else(|| units.find(|(_, u)| u.all))
            .map(|(i, _)| i)
    }
}

/// Lê a IVRS já validada (cabeçalho incluso).
///
/// # Errors
///
/// [`AcpiError::BadLength`] se a tabela for menor que o cabeçalho.
pub fn parse(table: &[u8]) -> Result<Ivrs, AcpiError> {
    let mut out = Ivrs::default();
    let mut rest = table.get(HEADER + 12..).ok_or(AcpiError::BadLength)?;
    while let [kind, _, l0, l1, ..] = *rest {
        let len = usize::from(u16::from_le_bytes([l0, l1]));
        let Some(block) = rest.get(..len).filter(|_| len >= 4) else {
            out.skipped += 1;
            break;
        };
        rest = &rest[len..];
        let fixed = match kind {
            0x10 => 24,
            0x11 | 0x40 => 40,
            // IVMD e outros: não são unidades.
            _ => continue,
        };
        if len < fixed {
            out.skipped += 1;
            continue;
        }
        let (base, segment) = (u64_at(block, 8), u16::from_le_bytes([block[16], block[17]]));
        // Uma IOMMU aparece em mais de um bloco (0x10 e 0x11); fica o primeiro.
        if segment != 0 || out.units().iter().any(|u| u.base == base) {
            continue;
        }
        if out.count == MAX_UNITS {
            out.skipped += 1;
            continue;
        }
        let unit = &mut out.units[out.count];
        unit.base = base;
        unit.bdf = u16::from_le_bytes([block[4], block[5]]);
        unit.parse(&block[fixed..]);
        out.count += 1;
    }
    Ok(out)
}

/// Lê a IVRS de `rsdp`.
///
/// # Errors
///
/// Tabela ausente ou inválida.
pub fn read(mem: &mut impl PhysRead, rsdp: u64) -> Result<Ivrs, AcpiError> {
    let mut buf = [0u8; 4096];
    let len = find(mem, rsdp, b"IVRS", &mut buf)?;
    parse(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ivhd(kind: u8, bdf: u16, base: u64, segment: u16, entries: &[u8]) -> Vec<u8> {
        let fixed = if kind == 0x10 { 24 } else { 40 };
        let mut b = vec![0u8; fixed];
        b[0] = kind;
        b[4..6].copy_from_slice(&bdf.to_le_bytes());
        b[8..16].copy_from_slice(&base.to_le_bytes());
        b[16..18].copy_from_slice(&segment.to_le_bytes());
        b.extend_from_slice(entries);
        let len = u16::try_from(b.len()).unwrap();
        b[2..4].copy_from_slice(&len.to_le_bytes());
        b
    }

    fn table(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut t = vec![0u8; HEADER + 12];
        for b in blocks {
            t.extend(b);
        }
        t
    }

    #[test]
    fn unidade_do_qemu_cobre_tudo() {
        // `-device amd-iommu`: blocos 0x10 e 0x11 da mesma IOMMU, com ALL.
        let all = [1, 0, 0, 0];
        let t = table(&[
            ivhd(0x10, 0x10, 0xfed8_0000, 0, &all),
            ivhd(0x11, 0x10, 0xfed8_0000, 0, &all),
        ]);
        let ivrs = parse(&t).unwrap();
        assert_eq!(ivrs.units().len(), 1);
        let u = ivrs.units()[0];
        assert_eq!(
            (u.base, u.bdf, u.all, u.skipped),
            (0xfed8_0000, 0x10, true, 0)
        );
        assert_eq!(ivrs.unit_for(0x0018), Some(0));
    }

    #[test]
    fn faixas_e_selecao_vencem_o_all() {
        let mut first = vec![2, 0x18, 0, 0];
        first.extend([3, 0x00, 0x01, 0, 4, 0xff, 0x01, 0]);
        // Apelido de 8 bytes: contado e pulado.
        first.extend([66, 0, 2, 0, 0, 0, 0, 0]);
        let t = table(&[
            ivhd(0x10, 0, 0xfed8_0000, 0, &first),
            ivhd(0x10, 0, 0xfed9_0000, 0, &[1, 0, 0, 0]),
            ivhd(0x10, 0, 0xfeda_0000, 1, &[1, 0, 0, 0]),
        ]);
        let ivrs = parse(&t).unwrap();
        assert_eq!(ivrs.units().len(), 2, "o grupo 1 fica de fora");
        assert_eq!(ivrs.units()[0].ranges(), &[(0x18, 0x18), (0x100, 0x1ff)]);
        assert_eq!(ivrs.units()[0].skipped, 1);
        assert_eq!(ivrs.unit_for(0x0018), Some(0));
        assert_eq!(ivrs.unit_for(0x0150), Some(0));
        assert_eq!(ivrs.unit_for(0x0200), Some(1));
    }

    #[test]
    fn tabela_estragada_nao_estoura() {
        assert_eq!(parse(&[0; 40]), Err(AcpiError::BadLength));
        let mut t = table(&[ivhd(0x10, 0, 0xfed8_0000, 0, &[])]);
        t.extend([0x10, 0, 0xff, 0x0f]);
        let ivrs = parse(&t).unwrap();
        assert_eq!((ivrs.units().len(), ivrs.skipped), (1, 1));
        // Bloco menor que a parte fixa; entrada cortada; END sem START.
        let mut short = ivhd(0x11, 0, 0xfed9_0000, 0, &[]);
        short.truncate(30);
        short[2..4].copy_from_slice(&30u16.to_le_bytes());
        let cut = ivhd(0x10, 0, 0xfeda_0000, 0, &[4, 1, 0, 0, 2, 0]);
        let ivrs = parse(&table(&[short, cut])).unwrap();
        assert_eq!(ivrs.skipped, 1);
        assert_eq!(ivrs.units()[0].skipped, 2);
        assert_eq!(ivrs.unit_for(1), None);
    }
}
