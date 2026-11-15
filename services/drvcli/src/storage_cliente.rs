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

/// Enumeração `IoError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError(pub u8);

impl IoError {
    /// Variante `Io`.
    pub const Io: IoError = IoError(0);
    /// Variante `OutOfRange`.
    pub const OutOfRange: IoError = IoError(1);
    /// Variante `ReadOnly`.
    pub const ReadOnly: IoError = IoError(2);
    /// Variante `Reset`.
    pub const Reset: IoError = IoError(3);
    /// Variante `Full`.
    pub const Full: IoError = IoError(4);
    /// Variante `BadRequest`.
    pub const BadRequest: IoError = IoError(5);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<IoError> {
        match v {
            0 | 1 | 2 | 3 | 4 | 5 => Some(IoError(v)),
            _ => None,
        }
    }
}

/// Struct `Info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    /// Campo `blocks`.
    pub blocks: u64,
    /// Campo `read_only`.
    pub read_only: bool,
    /// Campo `flush`.
    pub flush: bool,
    /// Campo `max_depth`.
    pub max_depth: u16,
    /// Campo `max_blocks`.
    pub max_blocks: u16,
}

fn enc_info(w: &mut Writer<'_>, v: &Info, base: usize) -> Result<(), Error> {
    w.seek(base);
    w.u64(v.blocks)?;
    w.seek(base + 8);
    w.bool(v.read_only)?;
    w.seek(base + 9);
    w.bool(v.flush)?;
    w.seek(base + 10);
    w.u16(v.max_depth)?;
    w.seek(base + 12);
    w.u16(v.max_blocks)?;
    Ok(())
}

/// Cliente da interface `Storage` (T-345).
pub struct StorageCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl StorageCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `open` (ordinal 0).
    pub fn open(
        &self,
        buf: &mut ostd::ipc::Buffer,
        name: &str,
    ) -> Result<Result<ostd::kabi::Handle, IoError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 48];
        let n = codifica_storage_0(&mut pedido, &name).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x78F2461000000000,
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
                decodifica_err_storage_0(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }
}

fn codifica_storage_0(saida: &mut [u8], name: &&str) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 8)?;
    w.seek(0);
    w.string((*name), 36)?;
    Ok(w.finish())
}

fn decodifica_ok_storage_0(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_storage_0(corpo: &[u8]) -> Result<IoError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = IoError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

/// Cliente da interface `BlockStore` (T-345).
pub struct BlockStoreCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl BlockStoreCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `info` (ordinal 0).
    pub fn info(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<Info, IoError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_block_store_0(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 16];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xCAB5849900000000,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_block_store_0(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_block_store_0(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `open_queue` (ordinal 1).
    pub fn open_queue(
        &self,
        buf: &mut ostd::ipc::Buffer,
        area: ostd::kabi::Handle,
        done: ostd::kabi::Handle,
        depth: u16,
        priority: u8,
        data_blocks: u16,
    ) -> Result<Result<u32, IoError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_block_store_1(&mut pedido, &depth, &priority, &data_blocks)
            .map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo_caps(
            self.ep,
            buf,
            0xCAB5849900000001,
            &pedido[..n],
            &[area, done],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_block_store_1(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_block_store_1(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `submit_ring` (ordinal 2).
    pub fn submit_ring(
        &self,
        buf: &mut ostd::ipc::Buffer,
        queue: u32,
    ) -> Result<Result<ostd::kabi::Handle, IoError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_block_store_2(&mut pedido, &queue).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xCAB5849900000002,
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
                decodifica_err_block_store_2(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `kick` (ordinal 3).
    pub fn kick(
        &self,
        buf: &mut ostd::ipc::Buffer,
        queue: u32,
    ) -> Result<Result<ostd::kabi::Handle, IoError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_block_store_3(&mut pedido, &queue).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xCAB5849900000003,
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
                decodifica_err_block_store_3(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `close_queue` (ordinal 4).
    pub fn close_queue(
        &self,
        buf: &mut ostd::ipc::Buffer,
        queue: u32,
    ) -> Result<Result<(), IoError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_block_store_4(&mut pedido, &queue).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xCAB5849900000004,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_block_store_4(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_block_store_4(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `release` (ordinal 5).
    pub fn release(
        &self,
        buf: &mut ostd::ipc::Buffer,
    ) -> Result<Result<(), IoError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 0];
        let n = codifica_block_store_5(&mut pedido).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xCAB5849900000005,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_block_store_5(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_block_store_5(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }
}

fn codifica_block_store_0(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_block_store_0(corpo: &[u8]) -> Result<Info, Error> {
    let mut r = Reader::new(corpo, 16)?;
    let v = Info {
        blocks: r.u64()?,
        read_only: r.bool()?,
        flush: r.bool()?,
        max_depth: r.u16()?,
        max_blocks: r.u16()?,
    };
    r.finish()?;
    Ok(v)
}

fn decodifica_err_block_store_0(corpo: &[u8]) -> Result<IoError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = IoError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_store_1(
    saida: &mut [u8],
    depth: &u16,
    priority: &u8,
    data_blocks: &u16,
) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 6)?;
    w.seek(0);
    w.u16((*depth))?;
    w.seek(2);
    w.u8((*priority))?;
    w.seek(4);
    w.u16((*data_blocks))?;
    Ok(w.finish())
}

fn decodifica_ok_block_store_1(corpo: &[u8]) -> Result<u32, Error> {
    let mut r = Reader::new(corpo, 4)?;
    let v = r.u32()?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_block_store_1(corpo: &[u8]) -> Result<IoError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = IoError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_store_2(saida: &mut [u8], queue: &u32) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 4)?;
    w.seek(0);
    w.u32((*queue))?;
    Ok(w.finish())
}

fn decodifica_ok_block_store_2(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_block_store_2(corpo: &[u8]) -> Result<IoError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = IoError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_store_3(saida: &mut [u8], queue: &u32) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 4)?;
    w.seek(0);
    w.u32((*queue))?;
    Ok(w.finish())
}

fn decodifica_ok_block_store_3(corpo: &[u8]) -> Result<ostd::kabi::Handle, Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(ostd::kabi::Handle::from_raw(0))
}

fn decodifica_err_block_store_3(corpo: &[u8]) -> Result<IoError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = IoError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_store_4(saida: &mut [u8], queue: &u32) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 4)?;
    w.seek(0);
    w.u32((*queue))?;
    Ok(w.finish())
}

fn decodifica_ok_block_store_4(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_block_store_4(corpo: &[u8]) -> Result<IoError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = IoError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_block_store_5(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn decodifica_ok_block_store_5(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_block_store_5(corpo: &[u8]) -> Result<IoError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = IoError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}
