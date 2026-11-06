//! `osvc`: o protocolo `optimus.svc.Supervisor@1` (ADR 0034, item 6) no
//! formato de fio do OIDL (ADR 0033), sem syscalls: rótulos dos métodos e
//! das respostas e o descritor de partida ([`Boot`]). O `svcmgr` codifica
//! e os serviços decodificam (pelo `ostd`).
//!
//! A especificação está em `idl/optimus/svc.oidl`; este código à mão vale
//! até os stubs gerados pelo `oidlc`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use oidl_rt::{Reader, Writer};

/// Métodos de `Supervisor`, pelo ordinal da declaração.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Method {
    /// `bootstrap() -> Boot`.
    Bootstrap = 0,
    /// `ready()`.
    Ready = 1,
    /// `connect(interface, minor) -> handle<Endpoint>`.
    Connect = 2,
    /// `name_of(id) -> string<31>`.
    NameOf = 3,
}

/// `SvcError` no fio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SvcError {
    /// Fora do manifesto.
    NotInManifest = 0,
    /// Provedor parado ou instância velha.
    NotRunning = 1,
    /// Versão menor abaixo da pedida.
    VersionTooOld = 2,
    /// O kernel recusou.
    Busy = 3,
}

impl SvcError {
    /// Do byte do fio.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::NotInManifest,
            1 => Self::NotRunning,
            2 => Self::VersionTooOld,
            3 => Self::Busy,
            _ => return None,
        })
    }
}

/// `interface_id` de `optimus.svc.Supervisor@1` (ADR 0033).
#[must_use]
pub fn interface_id() -> u32 {
    let h = optcrypt::blake3::hash(b"optimus.svc.Supervisor@1");
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Rótulo do pedido de `m` (`minor_min` 0 em todos os métodos da 1.0).
#[must_use]
pub fn label(m: Method) -> u64 {
    (u64::from(interface_id()) << 32) | m as u64
}

/// Método de um rótulo de pedido, se for desta interface.
#[must_use]
pub fn method_of(label: u64) -> Option<Method> {
    if label >> 32 != u64::from(interface_id()) || (label >> 16) & 0xFFFF != 0 {
        return None;
    }
    Some(match label & 0xFFFF {
        0 => Method::Bootstrap,
        1 => Method::Ready,
        2 => Method::Connect,
        3 => Method::NameOf,
        _ => return None,
    })
}

/// Rótulo de resposta `Ok`.
pub const REPLY_OK: u64 = 0;
/// Rótulo de resposta `Err` (corpo: o `SvcError`, um byte).
pub const REPLY_ERR: u64 = 1 << 62;
/// Rótulo de erro de protocolo `UnknownMethod`.
pub const REPLY_UNKNOWN_METHOD: u64 = (2 << 62) | 2;
/// Rótulo de erro de protocolo `BadMessage`.
pub const REPLY_BAD_MESSAGE: u64 = (2 << 62) | 4;

/// Limite de capabilities do descritor.
pub const MAX_CAPS: usize = 96;
/// Bytes de um `CapDesc` no fio.
pub const CAP_DESC_BYTES: usize = 12;
/// Cabeça de `Boot`: o ponteiro do `vec` (8) e `generation` (2).
const BOOT_HEAD: usize = 10;
/// Maior corpo de `Boot`.
pub const MAX_BOOT_BYTES: usize = 16 + MAX_CAPS * CAP_DESC_BYTES;

/// `kind` do canal de controle.
pub const KIND_CONTROL: u8 = 0;
/// `kind` de `mem:`; a cota do processo tem `index` [`QUOTA_INDEX`].
pub const KIND_MEM: u8 = 2;
/// `kind` de uma interface provida.
pub const KIND_PROVIDE: u8 = 6;
/// `index` da cota do processo.
pub const QUOTA_INDEX: u16 = 0xFFFF;

/// Uma capability do descritor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapDesc {
    /// 0 controle, 1 a 5 como em `needs`, 6 `provide`.
    pub kind: u8,
    /// Posição em `needs` ou `provides`.
    pub index: u16,
    /// Handle no `CapSpace` do serviço.
    pub handle: u32,
    /// `interface_id` ou hash do nome.
    pub name_hash: u32,
}

/// Descritor de partida decodificado, sem alocar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Boot {
    caps: [CapDesc; MAX_CAPS],
    count: usize,
    /// Geração da instância.
    pub generation: u16,
}

impl Boot {
    /// As capabilities, na ordem do item 6.
    #[must_use]
    pub fn caps(&self) -> &[CapDesc] {
        &self.caps[..self.count]
    }

    /// A primeira capability de `kind` e `index`.
    #[must_use]
    pub fn find(&self, kind: u8, index: u16) -> Option<CapDesc> {
        self.caps()
            .iter()
            .copied()
            .find(|c| c.kind == kind && c.index == index)
    }

    /// A cota do processo.
    #[must_use]
    pub fn quota(&self) -> Option<u32> {
        self.find(KIND_MEM, QUOTA_INDEX).map(|c| c.handle)
    }

    /// O endpoint da interface provida `name_hash`.
    #[must_use]
    pub fn provided(&self, name_hash: u32) -> Option<u32> {
        self.caps()
            .iter()
            .find(|c| c.kind == KIND_PROVIDE && c.name_hash == name_hash)
            .map(|c| c.handle)
    }
}

/// Codifica `Boot` em `out`; devolve os bytes do corpo.
///
/// # Errors
/// [`oidl_rt::Error::TooLarge`] acima de [`MAX_CAPS`] ou sem espaço.
pub fn encode_boot(caps: &[CapDesc], generation: u16, out: &mut [u8]) -> oidl_rt::Result<usize> {
    let mut w = Writer::new(out, BOOT_HEAD)?;
    let off = w.vec(caps.len(), CAP_DESC_BYTES, MAX_CAPS)?;
    w.u16(generation)?;
    for (i, c) in caps.iter().enumerate() {
        w.seek(off + i * CAP_DESC_BYTES);
        w.u8(c.kind)?;
        w.u16(c.index)?;
        w.u32(c.handle)?;
        w.u32(c.name_hash)?;
    }
    Ok(w.finish())
}

/// Decodifica um corpo de `Boot`.
///
/// # Errors
/// [`oidl_rt::Error::BadMessage`] para corpo fora do formato.
pub fn decode_boot(body: &[u8]) -> oidl_rt::Result<Boot> {
    let mut r = Reader::new(body, BOOT_HEAD)?;
    let elems = r.vec(MAX_CAPS, CAP_DESC_BYTES)?;
    let generation = r.u16()?;
    let mut caps = [CapDesc::default(); MAX_CAPS];
    for (i, c) in caps.iter_mut().take(elems.count()).enumerate() {
        r.seek(elems.off() + i * CAP_DESC_BYTES);
        c.kind = r.u8()?;
        c.index = r.u16()?;
        c.handle = r.u32()?;
        c.name_hash = r.u32()?;
    }
    r.finish()?;
    Ok(Boot {
        caps,
        count: elems.count(),
        generation,
    })
}

#[cfg(test)]
mod tests;
