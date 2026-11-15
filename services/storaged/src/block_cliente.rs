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

/// Enumeração `BlockError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockError(pub u8);

impl BlockError {
    /// Variante `Io`.
    pub const Io: BlockError = BlockError(0);
    /// Variante `OutOfRange`.
    pub const OutOfRange: BlockError = BlockError(1);
    /// Variante `ReadOnly`.
    pub const ReadOnly: BlockError = BlockError(2);
    /// Variante `Reset`.
    pub const Reset: BlockError = BlockError(3);
    /// Variante `Full`.
    pub const Full: BlockError = BlockError(4);
    /// Variante `BadRequest`.
    pub const BadRequest: BlockError = BlockError(5);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<BlockError> {
        match v {
            0 | 1 | 2 | 3 | 4 | 5 => Some(BlockError(v)),
            _ => None,
        }
    }
}

/// Struct `BlockInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    /// Campo `sectors`.
    pub sectors: u64,
    /// Campo `sector_size`.
    pub sector_size: u32,
    /// Campo `data_bytes`.
    pub data_bytes: u32,
    /// Campo `ring_bytes`.
    pub ring_bytes: u32,
    /// Campo `max_sectors`.
    pub max_sectors: u16,
    /// Campo `depth`.
    pub depth: u16,
    /// Campo `read_only`.
    pub read_only: bool,
    /// Campo `flush`.
    pub flush: bool,
}

fn enc_block_info(w: &mut Writer<'_>, v: &BlockInfo, base: usize) -> Result<(), Error> {
    w.seek(base);
    w.u64(v.sectors)?;
    w.seek(base + 8);
    w.u32(v.sector_size)?;
    w.seek(base + 12);
    w.u32(v.data_bytes)?;
    w.seek(base + 16);
    w.u32(v.ring_bytes)?;
    w.seek(base + 20);
    w.u16(v.max_sectors)?;
    w.seek(base + 22);
    w.u16(v.depth)?;
    w.seek(base + 24);
    w.bool(v.read_only)?;
    w.seek(base + 25);
    w.bool(v.flush)?;
    Ok(())
}

/// Cliente da interface `BlockDevice` (T-345).
pub struct BlockDeviceCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl BlockDeviceCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `info` (ordinal 0).
    pub fn info(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<BlockInfo, BlockError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_block_device_0(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 32];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x207CD81100000000,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_block_device_0(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_block_device_0(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `session` (ordinal 1).
    pub fn session(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<ostd::kabi::Handle, BlockError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_block_device_1(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x207CD81100000001,
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
                decodifica_err_block_device_1(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `submit_ring` (ordinal 2).
    pub fn submit_ring(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<ostd::kabi::Handle, BlockError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_block_device_2(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x207CD81100000002,
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
                decodifica_err_block_device_2(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `submit_signal` (ordinal 3).
    pub fn submit_signal(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<ostd::kabi::Handle, BlockError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_block_device_3(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x207CD81100000003,
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
                decodifica_err_block_device_3(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `data_region` (ordinal 4).
    pub fn data_region(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<ostd::kabi::Handle, BlockError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_block_device_4(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x207CD81100000004,
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
                decodifica_err_block_device_4(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `attach_done` (ordinal 5).
    pub fn attach_done(
        &self,
        buf: &mut ostd::ipc::Buffer,
        ring: ostd::kabi::Handle,
        signal: ostd::kabi::Handle,
    ) -> Result<Result<(), BlockError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_block_device_5(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo_caps(
            self.ep,
            buf,
            0x207CD81100000005,
            &pedido[..n],
            &[ring, signal],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_block_device_5(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_block_device_5(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }
}

fn codifica_block_device_0(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_block_device_0(corpo: &[u8]) -> Result<BlockInfo, Error> {
    let mut r = Reader::new(corpo, 32)?;
    let v = BlockInfo {
        sectors: r.u64()?,
        sector_size: r.u32()?,
        data_bytes: r.u32()?,
        ring_bytes: r.u32()?,
        max_sectors: r.u16()?,
        depth: r.u16()?,
        read_only: r.bool()?,
        flush: r.bool()?,
    };
    r.finish()?;
    Ok(v)
}

fn decodifica_err_block_device_0(corpo: &[u8]) -> Result<BlockError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = BlockError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_device_1(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_block_device_1(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_block_device_1(corpo: &[u8]) -> Result<BlockError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = BlockError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_device_2(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_block_device_2(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_block_device_2(corpo: &[u8]) -> Result<BlockError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = BlockError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_device_3(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_block_device_3(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_block_device_3(corpo: &[u8]) -> Result<BlockError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = BlockError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_device_4(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_block_device_4(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_block_device_4(corpo: &[u8]) -> Result<BlockError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = BlockError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_device_5(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_block_device_5(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_block_device_5(corpo: &[u8]) -> Result<BlockError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = BlockError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}
