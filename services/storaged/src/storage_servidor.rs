// Gerado pelo oidlc a partir do arquivo .oidl. Não edite à mão.
//
// Layout e formato de fio: ADR 0033. Usa só `oidl_rt` e `core`.

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
    unused_assignments,
    reason = "código gerado: estilo e campos que um serviço pode não usar"
)]

use oidl_rt::{Error, Reader, Writer};

/// Contexto de uma chamada: o badge do remetente (ADR 0027).
pub struct Contexto {
    /// Badge do endpoint que chamou.
    pub badge: u64,
}

/// Mensagem recebida.
pub struct Entrada<'a> {
    /// Rótulo de 64 bits (ADR 0033, seção 2).
    pub rotulo: u64,
    /// Badge do remetente.
    pub badge: u64,
    /// Corpo recebido.
    pub corpo: &'a [u8],
    /// Capabilities recebidas, na ordem dos `handle` dos parâmetros.
    pub caps: &'a [u64],
}

/// Resposta a ser enviada: rótulo, bytes do corpo e capabilities.
pub struct Despacho {
    /// Rótulo da resposta.
    pub rotulo: u64,
    /// Bytes escritos no buffer de saída.
    pub corpo: usize,
    /// Capabilities escritas em `caps_out`.
    pub caps: usize,
}

const fn rotulo_resposta(tipo: u8, codigo: u16) -> u64 {
    ((tipo as u64 & 0b11) << 62) | codigo as u64
}

/// Erro de protocolo (ADR 0033, seção 2): 1 UnknownInterface, 2 UnknownMethod,
/// 3 VersionTooOld, 4 BadMessage, 5 TooLarge.
fn protocolo(codigo: u16) -> Option<Despacho> {
    Some(Despacho {
        rotulo: rotulo_resposta(2, codigo),
        corpo: 0,
        caps: 0,
    })
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

/// Identificador da interface `Storage` (ADR 0033, seção 2).
pub const ID_STORAGE: u32 = 0x78F24610;

/// Interface `Storage`: implemente para servir.
pub trait Storage {
    /// Método `open` (ordinal 0).
    fn open(&mut self, ctx: &Contexto, name: &str) -> Result<u64, IoError>;
}

fn pedido_storage_0<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(&'a str,), Error> {
    let _ = caps;
    Ok((r.string(36)?,))
}

fn resp_ok_storage_0(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_storage_0(saida: &mut [u8], v: &IoError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `Storage`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_storage<S: Storage>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_STORAGE {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if e.corpo.len() as u64 > 48 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 8) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_name,) = match pedido_storage_0(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.open(&ctx, p_name) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_storage_0(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_storage_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        _ => protocolo(2),
    }
}

/// Despacho pelo caminho de registradores (T-345 parte 3): atende os
/// métodos que cabem em seis palavras. Os outros devolvem `None` e vão pelo
/// despacho de bytes.
pub fn despacha_storage_palavras<S: Storage>(
    s: &mut S,
    rotulo: u64,
    p: &[u64; 6],
    ctx: &Contexto,
) -> Option<(u64, [u64; 6])> {
    if (rotulo >> 32) as u32 != ID_STORAGE {
        return None;
    }
    match (rotulo & 0xFFFF) as u16 {
        _ => None,
    }
}

/// Identificador da interface `BlockStore` (ADR 0033, seção 2).
pub const ID_BLOCKSTORE: u32 = 0xCAB58499;

/// Interface `BlockStore`: implemente para servir.
pub trait BlockStore {
    /// Método `info` (ordinal 0).
    fn info(&mut self, ctx: &Contexto) -> Result<Info, IoError>;
    /// Método `open_queue` (ordinal 1).
    fn open_queue(
        &mut self,
        ctx: &Contexto,
        area: u64,
        done: u64,
        depth: u16,
        priority: u8,
        data_blocks: u16,
    ) -> Result<u32, IoError>;
    /// Método `submit_ring` (ordinal 2).
    fn submit_ring(&mut self, ctx: &Contexto, queue: u32) -> Result<u64, IoError>;
    /// Método `kick` (ordinal 3).
    fn kick(&mut self, ctx: &Contexto, queue: u32) -> Result<u64, IoError>;
    /// Método `close_queue` (ordinal 4).
    fn close_queue(&mut self, ctx: &Contexto, queue: u32) -> Result<(), IoError>;
    /// Método `release` (ordinal 5).
    fn release(&mut self, ctx: &Contexto) -> Result<(), IoError>;
}

fn resp_ok_block_store_0(saida: &mut [u8], v: &Info) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 16)?;
    {
        let w = &mut escritor;
        enc_info(w, v, 0)?;
    }
    Ok(escritor.finish())
}

fn resp_err_block_store_0(saida: &mut [u8], v: &IoError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_block_store_1<'a>(
    r: &mut Reader<'a>,
    caps: &[u64],
) -> Result<(u64, u64, u16, u8, u16), Error> {
    let mut ci = 0usize;
    let _ = caps;
    Ok((
        {
            let h = caps.get(ci).copied().ok_or(Error::BadMessage)?;
            ci += 1;
            h
        },
        {
            let h = caps.get(ci).copied().ok_or(Error::BadMessage)?;
            ci += 1;
            h
        },
        r.u16()?,
        r.u8()?,
        r.u16()?,
    ))
}

fn resp_ok_block_store_1(saida: &mut [u8], v: &u32) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 4)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u32((*v))?;
    }
    Ok(escritor.finish())
}

fn resp_err_block_store_1(saida: &mut [u8], v: &IoError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_block_store_2<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u32,), Error> {
    let _ = caps;
    Ok((r.u32()?,))
}

fn resp_ok_block_store_2(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_block_store_2(saida: &mut [u8], v: &IoError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_block_store_3<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u32,), Error> {
    let _ = caps;
    Ok((r.u32()?,))
}

fn resp_ok_block_store_3(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_block_store_3(saida: &mut [u8], v: &IoError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_block_store_4<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u32,), Error> {
    let _ = caps;
    Ok((r.u32()?,))
}

fn resp_ok_block_store_4(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_block_store_4(saida: &mut [u8], v: &IoError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn resp_ok_block_store_5(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_block_store_5(saida: &mut [u8], v: &IoError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `BlockStore`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_block_store<S: BlockStore>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_BLOCKSTORE {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if !e.corpo.is_empty() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.info(&ctx) {
                Ok(x) => match resp_ok_block_store_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_block_store_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        1 => {
            if e.corpo.len() as u64 > 8 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 6) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_area, p_done, p_depth, p_priority, p_data_blocks) =
                match pedido_block_store_1(&mut r, e.caps) {
                    Ok(x) => x,
                    Err(_) => return protocolo(4),
                };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.open_queue(&ctx, p_area, p_done, p_depth, p_priority, p_data_blocks) {
                Ok(x) => match resp_ok_block_store_1(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_block_store_1(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        2 => {
            if e.corpo.len() as u64 > 8 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 4) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_queue,) = match pedido_block_store_2(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.submit_ring(&ctx, p_queue) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_block_store_2(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_block_store_2(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        3 => {
            if e.corpo.len() as u64 > 8 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 4) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_queue,) = match pedido_block_store_3(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.kick(&ctx, p_queue) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_block_store_3(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_block_store_3(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        4 => {
            if e.corpo.len() as u64 > 8 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 4) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_queue,) = match pedido_block_store_4(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.close_queue(&ctx, p_queue) {
                Ok(()) => match resp_ok_block_store_4(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_block_store_4(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        5 => {
            if !e.corpo.is_empty() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.release(&ctx) {
                Ok(()) => match resp_ok_block_store_5(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_block_store_5(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        _ => protocolo(2),
    }
}

/// Despacho pelo caminho de registradores (T-345 parte 3): atende os
/// métodos que cabem em seis palavras. Os outros devolvem `None` e vão pelo
/// despacho de bytes.
pub fn despacha_block_store_palavras<S: BlockStore>(
    s: &mut S,
    rotulo: u64,
    p: &[u64; 6],
    ctx: &Contexto,
) -> Option<(u64, [u64; 6])> {
    if (rotulo >> 32) as u32 != ID_BLOCKSTORE {
        return None;
    }
    match (rotulo & 0xFFFF) as u16 {
        _ => None,
    }
}
