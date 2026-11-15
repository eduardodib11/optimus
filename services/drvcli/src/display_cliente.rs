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

/// Enumeração `DisplayError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayError(pub u8);

impl DisplayError {
    /// Variante `BadMode`.
    pub const BadMode: DisplayError = DisplayError(0);
    /// Variante `BadRect`.
    pub const BadRect: DisplayError = DisplayError(1);
    /// Variante `Io`.
    pub const Io: DisplayError = DisplayError(2);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<DisplayError> {
        match v {
            0 | 1 | 2 => Some(DisplayError(v)),
            _ => None,
        }
    }
}

/// Struct `Mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    /// Campo `id`.
    pub id: u16,
    /// Campo `width`.
    pub width: u16,
    /// Campo `height`.
    pub height: u16,
}

fn enc_mode(w: &mut Writer<'_>, v: &Mode, base: usize) -> Result<(), Error> {
    w.seek(base);
    w.u16(v.id)?;
    w.seek(base + 2);
    w.u16(v.width)?;
    w.seek(base + 4);
    w.u16(v.height)?;
    Ok(())
}

/// Cliente da interface `DisplayDevice` (T-345).
pub struct DisplayDeviceCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl DisplayDeviceCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `mode_count` (ordinal 0).
    pub fn mode_count(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<u16, DisplayError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_display_device_0(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xF2FA998F00000000,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_display_device_0(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_display_device_0(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `mode` (ordinal 1).
    pub fn mode(
        &self,
        buf: &mut ostd::ipc::Buffer,
        index: u16,
    ) -> Result<Result<Mode, DisplayError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_display_device_1(&mut pedido, &index).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xF2FA998F00000001,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_display_device_1(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_display_device_1(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `set_mode` (ordinal 2).
    pub fn set_mode(
        &self,
        buf: &mut ostd::ipc::Buffer,
        id: u16,
    ) -> Result<Result<(), DisplayError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_display_device_2(&mut pedido, &id).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xF2FA998F00000002,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_display_device_2(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_display_device_2(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `present` (ordinal 3).
    pub fn present(
        &self,
        buf: &mut ostd::ipc::Buffer,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<Result<(), DisplayError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n =
            codifica_display_device_3(&mut pedido, &x, &y, &width, &height).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xF2FA998F00000003,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_display_device_3(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_display_device_3(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }
}

fn codifica_display_device_0(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_display_device_0(corpo: &[u8]) -> Result<u16, Error> {
    let mut r = Reader::new(corpo, 2)?;
    let v = r.u16()?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_display_device_0(corpo: &[u8]) -> Result<DisplayError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = DisplayError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_display_device_1(saida: &mut [u8], index: &u16) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 2)?;
    w.seek(0);
    w.u16((*index))?;
    Ok(w.finish())
}

fn decodifica_ok_display_device_1(corpo: &[u8]) -> Result<Mode, Error> {
    let mut r = Reader::new(corpo, 6)?;
    let v = Mode {
        id: r.u16()?,
        width: r.u16()?,
        height: r.u16()?,
    };
    r.finish()?;
    Ok(v)
}

fn decodifica_err_display_device_1(corpo: &[u8]) -> Result<DisplayError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = DisplayError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_display_device_2(saida: &mut [u8], id: &u16) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 2)?;
    w.seek(0);
    w.u16((*id))?;
    Ok(w.finish())
}

fn decodifica_ok_display_device_2(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_display_device_2(corpo: &[u8]) -> Result<DisplayError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = DisplayError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_display_device_3(
    saida: &mut [u8],
    x: &u16,
    y: &u16,
    width: &u16,
    height: &u16,
) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 8)?;
    w.seek(0);
    w.u16((*x))?;
    w.seek(2);
    w.u16((*y))?;
    w.seek(4);
    w.u16((*width))?;
    w.seek(6);
    w.u16((*height))?;
    Ok(w.finish())
}

fn decodifica_ok_display_device_3(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_display_device_3(corpo: &[u8]) -> Result<DisplayError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = DisplayError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}
