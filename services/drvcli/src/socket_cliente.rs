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

/// Enumeração `SocketError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketError(pub u8);

impl SocketError {
    /// Variante `Denied`.
    pub const Denied: SocketError = SocketError(0);
    /// Variante `Limit`.
    pub const Limit: SocketError = SocketError(1);
    /// Variante `Quota`.
    pub const Quota: SocketError = SocketError(2);
    /// Variante `BadRequest`.
    pub const BadRequest: SocketError = SocketError(3);
    /// Variante `NoRoute`.
    pub const NoRoute: SocketError = SocketError(4);
    /// Variante `Busy`.
    pub const Busy: SocketError = SocketError(5);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<SocketError> {
        match v {
            0 | 1 | 2 | 3 | 4 | 5 => Some(SocketError(v)),
            _ => None,
        }
    }
}

/// Cliente da interface `Socket` (T-345).
pub struct SocketCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl SocketCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `open` (ordinal 0).
    pub fn open(
        &self,
        buf: &mut ostd::ipc::Buffer,
        proto: u8,
        rx: ostd::kabi::Handle,
        wake: ostd::kabi::Handle,
    ) -> Result<Result<u32, SocketError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_socket_0(&mut pedido, &proto).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo_caps(
            self.ep,
            buf,
            0xEA972EB300000000,
            &pedido[..n],
            &[rx, wake],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_socket_0(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(decodifica_err_socket_0(&saida[..m]).map_err(erro_oidl)?))
        }
    }

    /// Método `tx_ring` (ordinal 1).
    pub fn tx_ring(
        &self,
        buf: &mut ostd::ipc::Buffer,
        sock: u32,
    ) -> Result<Result<ostd::kabi::Handle, SocketError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_socket_1(&mut pedido, &sock).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xEA972EB300000001,
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
            Ok(Err(decodifica_err_socket_1(&saida[..m]).map_err(erro_oidl)?))
        }
    }

    /// Método `tx_signal` (ordinal 2).
    pub fn tx_signal(
        &self,
        buf: &mut ostd::ipc::Buffer,
        sock: u32,
    ) -> Result<Result<ostd::kabi::Handle, SocketError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_socket_2(&mut pedido, &sock).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xEA972EB300000002,
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
            Ok(Err(decodifica_err_socket_2(&saida[..m]).map_err(erro_oidl)?))
        }
    }

    /// Método `connect` (ordinal 3).
    pub fn connect(
        &self,
        buf: &mut ostd::ipc::Buffer,
        sock: u32,
        ip: u32,
        port: u16,
    ) -> Result<Result<(), SocketError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 16];
        let n = codifica_socket_3(&mut pedido, &sock, &ip, &port).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xEA972EB300000003,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_socket_3(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(decodifica_err_socket_3(&saida[..m]).map_err(erro_oidl)?))
        }
    }

    /// Método `close` (ordinal 4).
    pub fn close(
        &self,
        buf: &mut ostd::ipc::Buffer,
        sock: u32,
    ) -> Result<Result<(), SocketError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_socket_4(&mut pedido, &sock).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xEA972EB300000004,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_socket_4(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(decodifica_err_socket_4(&saida[..m]).map_err(erro_oidl)?))
        }
    }
}

fn codifica_socket_0(saida: &mut [u8], proto: &u8) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 1)?;
    w.seek(0);
    w.u8((*proto))?;
    Ok(w.finish())
}

fn decodifica_ok_socket_0(corpo: &[u8]) -> Result<u32, Error> {
    let mut r = Reader::new(corpo, 4)?;
    let v = r.u32()?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_socket_0(corpo: &[u8]) -> Result<SocketError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = SocketError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_socket_1(saida: &mut [u8], sock: &u32) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 4)?;
    w.seek(0);
    w.u32((*sock))?;
    Ok(w.finish())
}

fn decodifica_ok_socket_1(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_socket_1(corpo: &[u8]) -> Result<SocketError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = SocketError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_socket_2(saida: &mut [u8], sock: &u32) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 4)?;
    w.seek(0);
    w.u32((*sock))?;
    Ok(w.finish())
}

fn decodifica_ok_socket_2(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_socket_2(corpo: &[u8]) -> Result<SocketError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = SocketError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_socket_3(saida: &mut [u8], sock: &u32, ip: &u32, port: &u16) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 12)?;
    w.seek(0);
    w.u32((*sock))?;
    w.seek(4);
    w.u32((*ip))?;
    w.seek(8);
    w.u16((*port))?;
    Ok(w.finish())
}

fn decodifica_ok_socket_3(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_socket_3(corpo: &[u8]) -> Result<SocketError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = SocketError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_socket_4(saida: &mut [u8], sock: &u32) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 4)?;
    w.seek(0);
    w.u32((*sock))?;
    Ok(w.finish())
}

fn decodifica_ok_socket_4(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_socket_4(corpo: &[u8]) -> Result<SocketError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = SocketError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}
