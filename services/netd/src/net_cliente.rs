// Gerado pelo oidlc a partir do arquivo .oidl. Não edite à mão.
//
// Cliente de IPC (T-345): cada chamada usa `ostd::ipc::call_corpo`.

#![allow(
    unused_parens,
    unused_variables,
    dead_code,
    clippy::double_parens,
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::unnecessary_wraps,
    clippy::too_many_arguments,
    clippy::trivially_copy_pass_by_ref,
    clippy::manual_let_else,
    clippy::elidable_lifetime_names,
    clippy::needless_lifetimes,
    clippy::explicit_auto_deref,
    clippy::needless_pass_by_value,
    clippy::match_single_binding,
    clippy::manual_range_patterns,
    clippy::identity_op,
    non_upper_case_globals,
    reason = "código gerado: estilo e campos que um serviço pode não usar"
)]

use oidl_rt::{Error, Reader, Writer};

/// Erro de codificação ou decodificação vira erro de IPC.
fn erro_oidl(_: Error) -> ostd::kabi::Error {
    ostd::kabi::Error::InvalidArgument
}

/// Enumeração `NetError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetError(pub u8);

impl NetError {
    /// Variante `Io`.
    pub const Io: NetError = NetError(0);
    /// Variante `BadRequest`.
    pub const BadRequest: NetError = NetError(1);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<NetError> {
        match v {
            0 | 1 => Some(NetError(v)),
            _ => None,
        }
    }
}

/// Struct `NetInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetInfo {
    /// Campo `mac`.
    pub mac: u64,
    /// Campo `ring_bytes`.
    pub ring_bytes: u32,
    /// Campo `mtu`.
    pub mtu: u16,
    /// Campo `max_frame`.
    pub max_frame: u16,
}

fn enc_net_info(w: &mut Writer<'_>, v: &NetInfo, base: usize) -> Result<(), Error> {
    w.seek(base);
    w.u64(v.mac)?;
    w.seek(base + 8);
    w.u32(v.ring_bytes)?;
    w.seek(base + 12);
    w.u16(v.mtu)?;
    w.seek(base + 14);
    w.u16(v.max_frame)?;
    Ok(())
}

/// Cliente da interface `NetDevice` (T-345).
pub struct NetDeviceCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl NetDeviceCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `info` (ordinal 0).
    pub fn info(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<NetInfo, NetError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_net_device_0(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 16];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xC3BD310E00000000,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_net_device_0(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_net_device_0(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `session` (ordinal 1).
    pub fn session(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<ostd::kabi::Handle, NetError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_net_device_1(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xC3BD310E00000001,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            let h = buf.get().caps[0];
            if h == 0 {
                return Err(ostd::kabi::Error::InvalidArgument);
            }
            Ok(Ok(ostd::kabi::Handle::from_raw(h)))
        } else {
            Ok(Err(
                decodifica_err_net_device_1(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `tx_ring` (ordinal 2).
    pub fn tx_ring(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<ostd::kabi::Handle, NetError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_net_device_2(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xC3BD310E00000002,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            let h = buf.get().caps[0];
            if h == 0 {
                return Err(ostd::kabi::Error::InvalidArgument);
            }
            Ok(Ok(ostd::kabi::Handle::from_raw(h)))
        } else {
            Ok(Err(
                decodifica_err_net_device_2(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `tx_signal` (ordinal 3).
    pub fn tx_signal(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<ostd::kabi::Handle, NetError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_net_device_3(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xC3BD310E00000003,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            let h = buf.get().caps[0];
            if h == 0 {
                return Err(ostd::kabi::Error::InvalidArgument);
            }
            Ok(Ok(ostd::kabi::Handle::from_raw(h)))
        } else {
            Ok(Err(
                decodifica_err_net_device_3(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `attach_rx` (ordinal 4).
    pub fn attach_rx(
        &self,
        buf: &mut ostd::ipc::Buffer,
        ring: ostd::kabi::Handle,
        signal: ostd::kabi::Handle,
    ) -> Result<Result<(), NetError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_net_device_4(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo_caps(
            self.ep,
            buf,
            0xC3BD310E00000004,
            &pedido[..n],
            &[ring, signal],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_net_device_4(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_net_device_4(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }
}

fn codifica_net_device_0(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_net_device_0(corpo: &[u8]) -> Result<NetInfo, Error> {
    let mut r = Reader::new(corpo, 16)?;
    let v = NetInfo {
        mac: r.u64()?,
        ring_bytes: r.u32()?,
        mtu: r.u16()?,
        max_frame: r.u16()?,
    };
    r.finish()?;
    Ok(v)
}

fn decodifica_err_net_device_0(corpo: &[u8]) -> Result<NetError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = NetError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_net_device_1(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_net_device_1(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_net_device_1(corpo: &[u8]) -> Result<NetError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = NetError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_net_device_2(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_net_device_2(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_net_device_2(corpo: &[u8]) -> Result<NetError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = NetError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_net_device_3(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_net_device_3(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_net_device_3(corpo: &[u8]) -> Result<NetError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = NetError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_net_device_4(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_net_device_4(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_net_device_4(corpo: &[u8]) -> Result<NetError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = NetError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}
