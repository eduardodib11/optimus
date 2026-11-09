//! Unidades de VT-d pela DMAR (ADR 0044, item 1; T-403).
//!
//! A DMAR lista as unidades de remapeamento (DRHD, tipo 0) e as faixas que
//! o firmware precisa manter mapeadas para alguns dispositivos (RMRR, tipo
//! 1). Cada unidade cobre os dispositivos do seu escopo ou, com o flag
//! `INCLUDE_PCI_ALL`, todos os do grupo que nenhuma outra cobre. Entram só
//! os escopos de endpoint com caminho de um passo (o dispositivo direto no
//! barramento inicial); pontes e caminhos longos são contados e o
//! dispositivo fica sem unidade, e o `dma_attach` dele falha (fechado, não
//! aberto). Outros tipos de estrutura (ATSR, RHSA, ANDD, SATC) são pulados.

use super::{AcpiError, HEADER, PhysRead, find, u64_at};

/// Unidades guardadas.
pub const MAX_UNITS: usize = 8;
/// Dispositivos guardados por escopo.
pub const MAX_SCOPE: usize = 16;
/// Faixas RMRR guardadas.
pub const MAX_RMRR: usize = 8;

/// Flag da DMAR: o firmware pede remapeamento de interrupções.
pub const INTR_REMAP: u8 = 1;

/// Dispositivos de um escopo, como `barramento << 8 | dispositivo << 3 |
/// função`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    bdfs: [u16; MAX_SCOPE],
    count: usize,
    /// Entradas que não entraram: pontes, caminhos longos ou além de
    /// [`MAX_SCOPE`]. IOAPIC e HPET (remapeamento de interrupção) não
    /// contam.
    pub skipped: u32,
}

impl Scope {
    /// Os dispositivos guardados.
    #[must_use]
    pub fn bdfs(&self) -> &[u16] {
        &self.bdfs[..self.count]
    }

    fn parse(&mut self, mut entries: &[u8]) {
        while let [kind, len, ..] = *entries {
            let len = usize::from(len);
            let Some(entry) = entries.get(..len).filter(|_| len >= 6) else {
                self.skipped += 1;
                return;
            };
            match (kind, entry) {
                // Endpoint com um passo: barramento inicial, dispositivo e
                // função.
                (1, &[_, 8, _, _, _, bus, dev, func]) if self.count < MAX_SCOPE => {
                    let bdf = u16::from(bus) << 8 | u16::from(dev & 31) << 3 | u16::from(func & 7);
                    self.bdfs[self.count] = bdf;
                    self.count += 1;
                }
                // IOAPIC e HPET: assunto do remapeamento de interrupção.
                (3 | 4, _) => {}
                _ => self.skipped += 1,
            }
            entries = &entries[len..];
        }
    }
}

/// Uma unidade de remapeamento (DRHD).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unit {
    /// Endereço físico dos registradores.
    pub base: u64,
    /// Grupo de segmentos.
    pub segment: u16,
    /// Cobre todo dispositivo do grupo que outra unidade não cobre.
    pub all: bool,
    /// Os dispositivos listados.
    pub scope: Scope,
}

/// Uma faixa que o firmware usa por DMA (RMRR): os dispositivos dela
/// precisam dela mapeada em identidade.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rmrr {
    /// Primeiro byte.
    pub base: u64,
    /// Último byte (inclusive).
    pub limit: u64,
    /// Os dispositivos que a usam.
    pub scope: Scope,
}

/// O que a DMAR diz.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dmar {
    /// Largura de endereço do host, em bits.
    pub width: u8,
    /// Flags ([`INTR_REMAP`], ...).
    pub flags: u8,
    units: [Unit; MAX_UNITS],
    unit_count: usize,
    rmrrs: [Rmrr; MAX_RMRR],
    rmrr_count: usize,
    /// Estruturas que não couberam ou estavam estragadas.
    pub skipped: u32,
}

impl Dmar {
    /// As unidades, na ordem da tabela.
    #[must_use]
    pub fn units(&self) -> &[Unit] {
        &self.units[..self.unit_count]
    }

    /// As faixas RMRR.
    #[must_use]
    pub fn rmrrs(&self) -> &[Rmrr] {
        &self.rmrrs[..self.rmrr_count]
    }

    /// Índice da unidade que cobre `bdf` no grupo 0: a que o lista, senão a
    /// de `INCLUDE_PCI_ALL`.
    #[must_use]
    pub fn unit_for(&self, bdf: u16) -> Option<usize> {
        let units = self.units().iter().enumerate();
        let mut group = units.filter(|(_, u)| u.segment == 0);
        let listed = group.clone().find(|(_, u)| u.scope.bdfs().contains(&bdf));
        listed
            .or_else(|| group.find(|(_, u)| u.all))
            .map(|(i, _)| i)
    }
}

/// Lê a DMAR já validada (cabeçalho incluso).
///
/// # Errors
///
/// [`AcpiError::BadLength`] se a tabela for menor que o cabeçalho.
pub fn parse(table: &[u8]) -> Result<Dmar, AcpiError> {
    let mut out = Dmar::default();
    let (fixed, mut rest) = table
        .split_at_checked(HEADER + 12)
        .ok_or(AcpiError::BadLength)?;
    out.width = fixed[HEADER].saturating_add(1);
    out.flags = fixed[HEADER + 1];
    while let [k0, k1, l0, l1, ..] = *rest {
        let len = usize::from(u16::from_le_bytes([l0, l1]));
        let Some(s) = rest.get(..len).filter(|_| len >= 4) else {
            out.skipped += 1;
            break;
        };
        rest = &rest[len..];
        let segment = |s: &[u8]| u16::from_le_bytes([s[6], s[7]]);
        match u16::from_le_bytes([k0, k1]) {
            0 if len >= 16 && out.unit_count < MAX_UNITS => {
                let unit = &mut out.units[out.unit_count];
                (unit.base, unit.segment, unit.all) = (u64_at(s, 8), segment(s), s[4] & 1 != 0);
                unit.scope.parse(&s[16..]);
                out.unit_count += 1;
            }
            1 if len >= 24 && out.rmrr_count < MAX_RMRR && segment(s) == 0 => {
                let r = &mut out.rmrrs[out.rmrr_count];
                (r.base, r.limit) = (u64_at(s, 8), u64_at(s, 16));
                r.scope.parse(&s[24..]);
                out.rmrr_count += 1;
            }
            0 | 1 => out.skipped += 1,
            _ => {}
        }
    }
    Ok(out)
}

/// Lê a DMAR de `rsdp`.
///
/// # Errors
///
/// Tabela ausente ou inválida.
pub fn read(mem: &mut impl PhysRead, rsdp: u64) -> Result<Dmar, AcpiError> {
    let mut buf = [0u8; 4096];
    let len = find(mem, rsdp, b"DMAR", &mut buf)?;
    parse(&buf[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(kind: u8, bus: u8, path: &[(u8, u8)]) -> Vec<u8> {
        let len = u8::try_from(6 + 2 * path.len()).unwrap();
        let mut s = vec![kind, len, 0, 0, 0, bus];
        for &(d, f) in path {
            s.extend([d, f]);
        }
        s
    }

    fn structure(kind: u16, fixed: &[u8], scopes: &[Vec<u8>]) -> Vec<u8> {
        let mut s = kind.to_le_bytes().to_vec();
        s.extend([0, 0]);
        s.extend_from_slice(fixed);
        for sc in scopes {
            s.extend(sc);
        }
        let len = u16::try_from(s.len()).unwrap();
        s[2..4].copy_from_slice(&len.to_le_bytes());
        s
    }

    fn drhd(flags: u8, segment: u16, base: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
        let mut fixed = vec![flags, 0];
        fixed.extend(segment.to_le_bytes());
        fixed.extend(base.to_le_bytes());
        structure(0, &fixed, scopes)
    }

    fn table(width: u8, flags: u8, structures: &[Vec<u8>]) -> Vec<u8> {
        let mut t = vec![0u8; HEADER];
        t[..4].copy_from_slice(b"DMAR");
        t.extend([width - 1, flags]);
        t.extend([0; 10]);
        for s in structures {
            t.extend(s);
        }
        t
    }

    #[test]
    fn unidade_do_qemu_cobre_tudo() {
        // `-device intel-iommu`: uma unidade com INCLUDE_PCI_ALL e o IOAPIC.
        let t = table(
            39,
            INTR_REMAP,
            &[drhd(1, 0, 0xfed9_0000, &[scope(3, 0, &[(31, 0)])])],
        );
        let d = parse(&t).unwrap();
        assert_eq!((d.width, d.flags, d.skipped), (39, INTR_REMAP, 0));
        assert_eq!(d.units().len(), 1);
        let u = d.units()[0];
        assert_eq!(
            (u.base, u.all, u.scope.bdfs(), u.scope.skipped),
            (0xfed9_0000, true, &[][..], 0)
        );
        assert_eq!(d.unit_for(0x0018), Some(0));
    }

    #[test]
    fn escopo_explicito_vence_e_ponte_fica_sem_unidade() {
        let gpu = drhd(0, 0, 0xfed9_0000, &[scope(1, 0, &[(2, 0)])]);
        let bridge = drhd(
            0,
            0,
            0xfed9_1000,
            &[scope(2, 0, &[(28, 0)]), scope(1, 0, &[(28, 0), (0, 0)])],
        );
        let rest = drhd(1, 0, 0xfed9_2000, &[]);
        let mut rmrr = vec![0, 0, 0, 0];
        rmrr.extend(0x7d00_0000u64.to_le_bytes());
        rmrr.extend(0x7d0f_ffffu64.to_le_bytes());
        let rmrr = structure(1, &rmrr, &[scope(1, 0, &[(20, 0)])]);
        let other = structure(2, &[0; 4], &[]);
        let d = parse(&table(46, 0, &[gpu, bridge, rest, rmrr, other])).unwrap();
        assert_eq!(d.unit_for(0x0010), Some(0));
        assert_eq!(d.units()[1].scope.skipped, 2);
        // Atrás da ponte: cai na unidade geral (o firmware garante que
        // pontes listadas não estão nela; aqui é só a regra de busca).
        assert_eq!(d.unit_for(0x0100), Some(2));
        let r = d.rmrrs()[0];
        assert_eq!(
            (r.base, r.limit, r.scope.bdfs()),
            (0x7d00_0000, 0x7d0f_ffff, &[0x00a0][..])
        );
        assert_eq!(d.skipped, 0);
    }

    #[test]
    fn tabela_estragada_nao_estoura() {
        assert_eq!(parse(&[0; 40]), Err(AcpiError::BadLength));
        let mut t = table(39, 0, &[drhd(1, 0, 0xfed9_0000, &[])]);
        // Estrutura que diz ser maior que a tabela.
        t.extend([0, 0, 0xff, 0x0f]);
        let d = parse(&t).unwrap();
        assert_eq!((d.units().len(), d.skipped), (1, 1));
        // Escopo com tamanho zero.
        let mut bad = drhd(0, 0, 0xfed9_0000, &[]);
        bad.extend([1, 0, 0, 0]);
        let len = u16::try_from(bad.len()).unwrap();
        bad[2..4].copy_from_slice(&len.to_le_bytes());
        let d = parse(&table(39, 0, &[bad])).unwrap();
        assert_eq!(d.units()[0].scope.skipped, 1);
        assert_eq!(d.unit_for(0), None);
    }
}
