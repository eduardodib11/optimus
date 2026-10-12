//! Topologia de CPUs pela MADT (ADR 0030, item 1; T-316).
//!
//! A MADT (assinatura `APIC`) lista os APICs locais. Entram as entradas de
//! tipo 0 (APIC local, id de 8 bits) e 9 (x2APIC, id de 32 bits) com o bit
//! `Enabled`; o bit `Online Capable` (hotplug) só é contado. Ids repetidos
//! (a mesma CPU nos tipos 0 e 9) contam uma vez. O BSP recebe o id lógico
//! 0 e as demais seguem a ordem da tabela. Ficam de fora, contadas, as CPUs
//! além de [`MAX_CPUS`] (ou do limite `smp=N`) e, com o BSP em xAPIC, as de
//! id acima de 254. IOAPICs (tipo 1) são guardados para os drivers; ISO (2)
//! e NMI (4 e 0xA) só contados.

use kabi::MAX_CPUS;

use super::{AcpiError, HEADER, PhysRead, find, u32_at, u64_at};

/// IOAPICs guardados.
pub const MAX_IOAPICS: usize = 8;

/// Maior id de APIC endereçável em xAPIC (255 é o broadcast).
pub const XAPIC_MAX_ID: u32 = 254;

/// Um IOAPIC da MADT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoApic {
    /// Id do IOAPIC.
    pub id: u8,
    /// Endereço físico dos registradores.
    pub addr: u32,
    /// Primeira GSI atendida.
    pub gsi_base: u32,
}

/// O que a MADT diz das CPUs e dos controladores de interrupção.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topology {
    /// Id de APIC de cada CPU, indexado pelo id lógico (0 é o BSP).
    apic_ids: [u32; MAX_CPUS],
    count: usize,
    /// Endereço físico do APIC local (com o override de tipo 5).
    pub local_apic: u64,
    /// O BSP estava na tabela (senão entra como 0 do mesmo jeito).
    pub bsp_listed: bool,
    /// CPUs desligadas (sem `Enabled`).
    pub disabled: u32,
    /// Desligadas que podem ser ligadas depois (`Online Capable`).
    pub online_capable: u32,
    /// Entradas repetidas (mesmo id de APIC).
    pub duplicates: u32,
    /// CPUs além do limite.
    pub over_limit: u32,
    /// CPUs com id acima de 254 com o BSP em xAPIC.
    pub unaddressable: u32,
    /// IOAPICs guardados (até [`MAX_IOAPICS`]).
    ioapics: [IoApic; MAX_IOAPICS],
    ioapic_count: usize,
    /// Overrides de fonte de interrupção (tipo 2).
    pub overrides: u32,
    /// Entradas de NMI (tipos 4 e 0xA).
    pub nmis: u32,
}

impl Topology {
    /// Ids de APIC das CPUs, pelo id lógico.
    #[must_use]
    pub fn apic_ids(&self) -> &[u32] {
        &self.apic_ids[..self.count]
    }

    /// Número de CPUs que vão subir.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// IOAPICs da tabela.
    #[must_use]
    pub fn ioapics(&self) -> &[IoApic] {
        &self.ioapics[..self.ioapic_count]
    }

    fn push(&mut self, apic_id: u32, limit: usize) {
        if self.apic_ids().contains(&apic_id) {
            self.duplicates += 1;
        } else if self.count >= limit {
            self.over_limit += 1;
        } else {
            self.apic_ids[self.count] = apic_id;
            self.count += 1;
        }
    }
}

/// Opções da leitura.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Id de APIC do BSP (lido do próprio APIC).
    pub bsp_apic_id: u32,
    /// O BSP está em xAPIC: ids acima de 254 ficam de fora.
    pub xapic: bool,
    /// Máximo de CPUs (`smp=N`), até [`MAX_CPUS`].
    pub limit: usize,
}

const ENABLED: u32 = 1;
const ONLINE_CAPABLE: u32 = 1 << 1;

/// Lê a topologia de uma MADT já conferida (`table` inteira, cabeçalho
/// incluído).
///
/// # Errors
///
/// [`AcpiError::BadSignature`] se não for a MADT; [`AcpiError::BadLength`]
/// se a tabela ou alguma entrada estiver truncada.
pub fn parse(table: &[u8], opts: Options) -> Result<Topology, AcpiError> {
    if table.len() < HEADER + 8 {
        return Err(AcpiError::BadLength);
    }
    if &table[..4] != b"APIC" {
        return Err(AcpiError::BadSignature);
    }
    let limit = opts.limit.clamp(1, MAX_CPUS);
    let mut t = Topology {
        apic_ids: [0; MAX_CPUS],
        count: 1,
        local_apic: u64::from(u32_at(table, HEADER)),
        bsp_listed: false,
        disabled: 0,
        online_capable: 0,
        duplicates: 0,
        over_limit: 0,
        unaddressable: 0,
        ioapics: [IoApic::default(); MAX_IOAPICS],
        ioapic_count: 0,
        overrides: 0,
        nmis: 0,
    };
    t.apic_ids[0] = opts.bsp_apic_id;
    let mut at = HEADER + 8;
    while at < table.len() {
        let rest = &table[at..];
        let len = usize::from(*rest.get(1).ok_or(AcpiError::BadLength)?);
        if len < 2 || len > rest.len() {
            return Err(AcpiError::BadLength);
        }
        let e = &rest[..len];
        let need = |n: usize| {
            if len < n {
                Err(AcpiError::BadLength)
            } else {
                Ok(())
            }
        };
        let cpu = match e[0] {
            0 => {
                need(8)?;
                Some((u32::from(e[3]), u32_at(e, 4)))
            }
            9 => {
                need(16)?;
                Some((u32_at(e, 4), u32_at(e, 8)))
            }
            1 => {
                need(12)?;
                if t.ioapic_count < MAX_IOAPICS {
                    t.ioapics[t.ioapic_count] = IoApic {
                        id: e[2],
                        addr: u32_at(e, 4),
                        gsi_base: u32_at(e, 8),
                    };
                    t.ioapic_count += 1;
                }
                None
            }
            2 => {
                t.overrides += 1;
                None
            }
            4 | 0xa => {
                t.nmis += 1;
                None
            }
            5 => {
                need(12)?;
                t.local_apic = u64_at(e, 4);
                None
            }
            _ => None,
        };
        at += len;
        let Some((apic_id, flags)) = cpu else {
            continue;
        };
        if apic_id == opts.bsp_apic_id {
            t.bsp_listed = true;
        } else if flags & ENABLED == 0 {
            t.disabled += 1;
            if flags & ONLINE_CAPABLE != 0 {
                t.online_capable += 1;
            }
        } else if opts.xapic && apic_id > XAPIC_MAX_ID {
            t.unaddressable += 1;
        } else {
            t.push(apic_id, limit);
        }
    }
    Ok(t)
}

/// Acha a MADT pelo RSDP e lê a topologia.
///
/// # Errors
///
/// Os de [`find`] e [`parse`].
pub fn read(mem: &mut impl PhysRead, rsdp: u64, opts: Options) -> Result<Topology, AcpiError> {
    // 256 CPUs com entradas de tipo 0 e 9 cabem em pouco mais de 6 KiB.
    let mut buf = [0u8; 8192];
    let len = find(mem, rsdp, b"APIC", &mut buf)?;
    parse(&buf[..len], opts)
}

#[cfg(test)]
mod tests;
