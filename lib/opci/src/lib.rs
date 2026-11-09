//! `opci`: varredura do espaço de configuração `PCIe` (ADR 0043; T-402).
//!
//! Núcleo do `pcid`, sem syscalls: o acesso de configuração (ECAM ou portas
//! `0xCF8`/`0xCFC`) fica atrás de [`Config`]. A varredura percorre os
//! barramentos de 0 a 255, lê vendor, device, classe, BARs e a lista de
//! capabilities (MSI, MSI-X e `PCIe`) e entrega cada função a quem chama.
//!
//! O espaço de configuração vem do dispositivo: é superfície externa. Nada
//! aqui entra em pânico com valores arbitrários (aritmética com
//! `wrapping`/`checked` e laços com teto), e a crate tem alvo de fuzzing
//! (T-421).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "campos de registradores de 32 bits extraídos com máscara"
)]

use core::fmt;

/// Barramento, dispositivo e função.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bdf {
    /// Barramento (0 a 255).
    pub bus: u8,
    /// Dispositivo (0 a 31).
    pub dev: u8,
    /// Função (0 a 7).
    pub func: u8,
}

impl Bdf {
    /// Deslocamento da função numa janela ECAM que começa no barramento 0:
    /// `bus << 20 | dev << 15 | func << 12`.
    #[must_use]
    pub const fn ecam_offset(self) -> u64 {
        ((self.bus as u64) << 20)
            | (((self.dev & 31) as u64) << 15)
            | (((self.func & 7) as u64) << 12)
    }
}

impl fmt::Display for Bdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{:x}", self.bus, self.dev, self.func)
    }
}

/// Acesso ao espaço de configuração, em palavras de 32 bits alinhadas.
///
/// `offset` vai de 0 a 4092 (ECAM) e é múltiplo de 4. Uma função ausente
/// devolve `0xFFFF_FFFF`.
pub trait Config {
    /// Lê a palavra em `offset` da função `bdf`.
    fn read(&mut self, bdf: Bdf, offset: u16) -> u32;
    /// Grava `value` na palavra em `offset` da função `bdf`.
    fn write(&mut self, bdf: Bdf, offset: u16, value: u32);
}

/// Registradores do cabeçalho comum.
pub mod reg {
    /// Vendor (bits 0..16) e device (16..32).
    pub const ID: u16 = 0x00;
    /// Comando (bits 0..16) e status (16..32).
    pub const COMMAND: u16 = 0x04;
    /// Revisão (0..8), `prog_if` (8..16), subclasse (16..24) e classe.
    pub const CLASS: u16 = 0x08;
    /// Tipo de cabeçalho no byte 2 (bit 7: multifunção).
    pub const HEADER: u16 = 0x0C;
    /// Primeiro BAR.
    pub const BAR0: u16 = 0x10;
    /// Barramentos primário, secundário e subordinado de uma ponte.
    pub const BUSES: u16 = 0x18;
    /// Ponteiro da lista de capabilities.
    pub const CAP_PTR: u16 = 0x34;
    /// Linha e pino de interrupção (`INTx`).
    pub const INTERRUPT: u16 = 0x3C;
    /// Comando: decodifica portas de E/S.
    pub const CMD_IO: u32 = 1;
    /// Comando: decodifica memória.
    pub const CMD_MEMORY: u32 = 1 << 1;
    /// Comando: bus master (DMA). O `pcid` nunca liga (ADR 0043, item 4).
    pub const CMD_BUS_MASTER: u32 = 1 << 2;
    /// Status: a função tem lista de capabilities.
    pub const STATUS_CAP_LIST: u32 = 1 << 4;
}

/// Ids das capabilities reconhecidas.
pub mod cap_id {
    /// MSI.
    pub const MSI: u8 = 0x05;
    /// PCI Express.
    pub const PCIE: u8 = 0x10;
    /// MSI-X.
    pub const MSIX: u8 = 0x11;
}

/// Um BAR decodificado e dimensionado.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Bar {
    /// Sem BAR (ou a metade alta de um BAR de 64 bits).
    #[default]
    None,
    /// Janela de memória.
    Memory {
        /// Endereço físico.
        base: u64,
        /// Tamanho em bytes (potência de 2).
        size: u64,
        /// Prefetchable.
        prefetch: bool,
        /// BAR de 64 bits (ocupa dois registradores).
        wide: bool,
    },
    /// Faixa de portas de E/S.
    Io {
        /// Primeira porta.
        base: u32,
        /// Tamanho em portas.
        size: u32,
    },
}

/// Localização da tabela MSI-X ou do PBA: BAR e deslocamento.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarOffset {
    /// Índice do BAR (0 a 5).
    pub bar: u8,
    /// Deslocamento dentro do BAR.
    pub offset: u32,
}

/// Capability MSI-X.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msix {
    /// Deslocamento da capability no espaço de configuração.
    pub at: u16,
    /// Entradas da tabela (1 a 2048).
    pub entries: u16,
    /// Tabela de vetores.
    pub table: BarOffset,
    /// Pending Bit Array.
    pub pba: BarOffset,
}

/// Capabilities reconhecidas de uma função.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Caps {
    /// Deslocamento da capability MSI.
    pub msi: Option<u16>,
    /// Capability MSI-X.
    pub msix: Option<Msix>,
    /// Deslocamento da capability PCI Express.
    pub pcie: Option<u16>,
}

/// Uma função encontrada na varredura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    /// Endereço.
    pub bdf: Bdf,
    /// Vendor.
    pub vendor: u16,
    /// Device.
    pub device: u16,
    /// Classe, subclasse e `prog_if`.
    pub class: (u8, u8, u8),
    /// Revisão.
    pub revision: u8,
    /// Tipo de cabeçalho sem o bit de multifunção (0 = função, 1 = ponte).
    pub header: u8,
    /// BARs (uma ponte tem só os dois primeiros).
    pub bars: [Bar; 6],
    /// Barramentos secundário e subordinado, se for ponte.
    pub bridge: Option<(u8, u8)>,
    /// Pino de `INTx` (0 = nenhum, 1 a 4 = `INTA` a `INTD`).
    pub irq_pin: u8,
    /// Capabilities.
    pub caps: Caps,
}

impl fmt::Display for Function {
    /// Como `lspci -n`: `00:1f.2 0106: 8086:2922 (rev 02)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (class, sub, _) = self.class;
        write!(
            f,
            "{} {class:02x}{sub:02x}: {:04x}:{:04x}",
            self.bdf, self.vendor, self.device
        )?;
        if self.revision != 0 {
            write!(f, " (rev {:02x})", self.revision)?;
        }
        Ok(())
    }
}

/// Maior número de capabilities seguidas antes de desistir da lista (o
/// espaço de 256 bytes cabe 48 de 4 bytes depois do cabeçalho).
const MAX_CAPS: usize = 48;

/// Percorre a lista de capabilities, com teto contra listas em laço.
fn caps(cfg: &mut impl Config, bdf: Bdf) -> Caps {
    let mut out = Caps::default();
    if (cfg.read(bdf, reg::COMMAND) >> 16) & reg::STATUS_CAP_LIST == 0 {
        return out;
    }
    let mut at = (cfg.read(bdf, reg::CAP_PTR) & 0xFC) as u16;
    for _ in 0..MAX_CAPS {
        if at < 0x40 {
            break;
        }
        let head = cfg.read(bdf, at);
        match (head & 0xFF) as u8 {
            cap_id::MSI => out.msi = out.msi.or(Some(at)),
            cap_id::PCIE => out.pcie = out.pcie.or(Some(at)),
            cap_id::MSIX if out.msix.is_none() => {
                let place = |w: u32| BarOffset {
                    bar: (w & 7) as u8,
                    offset: w & !7,
                };
                out.msix = Some(Msix {
                    at,
                    entries: ((head >> 16) & 0x7FF) as u16 + 1,
                    table: place(cfg.read(bdf, at.wrapping_add(4))),
                    pba: place(cfg.read(bdf, at.wrapping_add(8))),
                });
            }
            _ => {}
        }
        at = ((head >> 8) & 0xFC) as u16;
    }
    out
}

/// Dimensiona o BAR `i` com a decodificação desligada; devolve o BAR e
/// quantos registradores ele ocupa.
fn bar(cfg: &mut impl Config, bdf: Bdf, i: usize, count: usize) -> (Bar, usize) {
    let at = reg::BAR0 + 4 * i as u16;
    let orig = cfg.read(bdf, at);
    cfg.write(bdf, at, u32::MAX);
    let mask = cfg.read(bdf, at);
    cfg.write(bdf, at, orig);
    if orig & 1 == 1 {
        let size = (!(mask & !3) & 0xFFFF).wrapping_add(1);
        let bar = if mask & !3 == 0 || size == 0 {
            Bar::None
        } else {
            Bar::Io {
                base: orig & !3,
                size,
            }
        };
        return (bar, 1);
    }
    let wide = (orig >> 1) & 3 == 2 && i + 1 < count;
    let mut base = u64::from(orig & !0xF);
    let mut bits = u64::from(mask & !0xF);
    if wide {
        let high = cfg.read(bdf, at + 4);
        cfg.write(bdf, at + 4, u32::MAX);
        let mask_high = cfg.read(bdf, at + 4);
        cfg.write(bdf, at + 4, high);
        base |= u64::from(high) << 32;
        bits |= u64::from(mask_high) << 32;
    }
    let used = if wide { 2 } else { 1 };
    if bits == 0 {
        return (Bar::None, used);
    }
    // Os bits de endereço que não fixam em 1 dão o tamanho; um BAR de 32
    // bits tem os altos fixos.
    let size = if wide {
        (!bits).wrapping_add(1)
    } else {
        u64::from((!(bits as u32)).wrapping_add(1))
    };
    if size == 0 || !size.is_power_of_two() {
        return (Bar::None, used);
    }
    let bar = Bar::Memory {
        base,
        size,
        prefetch: orig & 8 != 0,
        wide,
    };
    (bar, used)
}

/// Lê a função `bdf`; `None` se ela não existe.
pub fn probe(cfg: &mut impl Config, bdf: Bdf) -> Option<Function> {
    let id = cfg.read(bdf, reg::ID);
    let vendor = (id & 0xFFFF) as u16;
    if vendor == 0xFFFF || vendor == 0 {
        return None;
    }
    let class = cfg.read(bdf, reg::CLASS);
    let header = ((cfg.read(bdf, reg::HEADER) >> 16) & 0x7F) as u8;
    let count = match header {
        0 => 6,
        1 => 2,
        _ => 0,
    };
    let mut f = Function {
        bdf,
        vendor,
        device: (id >> 16) as u16,
        class: ((class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8),
        revision: class as u8,
        header,
        bars: [Bar::None; 6],
        bridge: None,
        irq_pin: (cfg.read(bdf, reg::INTERRUPT) >> 8) as u8,
        caps: caps(cfg, bdf),
    };
    if count > 0 {
        // Decodificação desligada durante o dimensionamento (ADR 0043, item 2).
        let command = cfg.read(bdf, reg::COMMAND);
        let off = command & 0xFFFF & !(reg::CMD_IO | reg::CMD_MEMORY);
        cfg.write(bdf, reg::COMMAND, off);
        let mut i = 0;
        while i < count {
            let (b, used) = bar(cfg, bdf, i, count);
            f.bars[i] = b;
            i += used;
        }
        cfg.write(bdf, reg::COMMAND, command & 0xFFFF);
    }
    if header == 1 {
        let buses = cfg.read(bdf, reg::BUSES);
        f.bridge = Some(((buses >> 8) as u8, (buses >> 16) as u8));
    }
    Some(f)
}

/// Varre os barramentos `0..=last_bus` e chama `found` para cada função,
/// em ordem de BDF. Funções 1 a 7 só são lidas se a função 0 for
/// multifunção.
pub fn scan(cfg: &mut impl Config, last_bus: u8, mut found: impl FnMut(&Function)) {
    for bus in 0..=last_bus {
        for dev in 0..32 {
            let Some(f0) = probe(cfg, Bdf { bus, dev, func: 0 }) else {
                continue;
            };
            found(&f0);
            let multi = (cfg.read(f0.bdf, reg::HEADER) >> 16) & 0x80 != 0;
            if !multi {
                continue;
            }
            for func in 1..8 {
                if let Some(f) = probe(cfg, Bdf { bus, dev, func }) {
                    found(&f);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
