//! Capabilities PCI do virtio (seção 4.1.4 da especificação).
//!
//! A varredura `PCIe` (T-402) entrega o espaço de configuração; aqui só se
//! acham as regiões de configuração comum, notificação, ISR e do dispositivo.

use crate::Error;

/// Configuração comum.
pub const COMMON: u8 = 1;
/// Notificação de fila.
pub const NOTIFY: u8 = 2;
/// Status de interrupção (ISR).
pub const ISR: u8 = 3;
/// Configuração específica do dispositivo.
pub const DEVICE: u8 = 4;

/// Onde fica uma região: BAR, deslocamento e tamanho.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Region {
    /// Índice do BAR (0 a 5).
    pub bar: u8,
    /// Deslocamento dentro do BAR.
    pub offset: u32,
    /// Tamanho da região.
    pub length: u32,
}

/// Regiões achadas no espaço de configuração.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    /// Configuração comum.
    pub common: Region,
    /// Notificação.
    pub notify: Region,
    /// Multiplicador de `queue_notify_off` (da capability de notificação).
    pub notify_multiplier: u32,
    /// ISR.
    pub isr: Region,
    /// Configuração do dispositivo, se houver.
    pub device: Option<Region>,
}

fn le32(cfg: &[u8], at: usize) -> Option<u32> {
    let b = cfg.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Percorre a lista de capabilities (ID 0x09, fornecedor) em `cfg`, os 256
/// bytes de configuração. A lista é limitada para não girar em laço.
///
/// # Errors
/// [`Error::BadCap`] se faltar uma região obrigatória ou algo estiver fora
/// do espaço de configuração.
pub fn find(cfg: &[u8]) -> Result<Caps, Error> {
    let mut caps = Caps::default();
    let (mut have_c, mut have_n, mut have_i) = (false, false, false);
    let mut ptr = usize::from(*cfg.get(0x34).ok_or(Error::BadCap)?) & !3;
    for _ in 0..48 {
        if ptr < 0x40 {
            break;
        }
        let id = *cfg.get(ptr).ok_or(Error::BadCap)?;
        let next = usize::from(*cfg.get(ptr + 1).ok_or(Error::BadCap)?) & !3;
        if id == 0x09 {
            let len = *cfg.get(ptr + 2).ok_or(Error::BadCap)?;
            let kind = *cfg.get(ptr + 3).ok_or(Error::BadCap)?;
            let bar = *cfg.get(ptr + 4).ok_or(Error::BadCap)?;
            if len >= 16 && bar < 6 {
                let r = Region {
                    bar,
                    offset: le32(cfg, ptr + 8).ok_or(Error::BadCap)?,
                    length: le32(cfg, ptr + 12).ok_or(Error::BadCap)?,
                };
                match kind {
                    COMMON => (caps.common, have_c) = (r, true),
                    NOTIFY if len >= 20 => {
                        caps.notify = r;
                        caps.notify_multiplier = le32(cfg, ptr + 16).ok_or(Error::BadCap)?;
                        have_n = true;
                    }
                    ISR => (caps.isr, have_i) = (r, true),
                    DEVICE => caps.device = Some(r),
                    _ => {}
                }
            }
        }
        ptr = next;
    }
    if have_c && have_n && have_i && caps.common.length >= 56 {
        Ok(caps)
    } else {
        Err(Error::BadCap)
    }
}
