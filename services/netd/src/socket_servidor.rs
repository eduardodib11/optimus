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

/// Identificador da interface `Socket` (ADR 0033, seção 2).
pub const ID_SOCKET: u32 = 0xEA972EB3;

/// Interface `Socket`: implemente para servir.
pub trait Socket {
    /// Método `open` (ordinal 0).
    fn open(&mut self, ctx: &Contexto, proto: u8, rx: u64, wake: u64) -> Result<u32, SocketError>;
    /// Método `tx_ring` (ordinal 1).
    fn tx_ring(&mut self, ctx: &Contexto, sock: u32) -> Result<u64, SocketError>;
    /// Método `tx_signal` (ordinal 2).
    fn tx_signal(&mut self, ctx: &Contexto, sock: u32) -> Result<u64, SocketError>;
    /// Método `connect` (ordinal 3).
    fn connect(&mut self, ctx: &Contexto, sock: u32, ip: u32, port: u16)
    -> Result<(), SocketError>;
    /// Método `close` (ordinal 4).
    fn close(&mut self, ctx: &Contexto, sock: u32) -> Result<(), SocketError>;
}

fn pedido_socket_0<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u8, u64, u64), Error> {
    let mut ci = 0usize;
    let _ = caps;
    Ok((
        r.u8()?,
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
    ))
}

fn resp_ok_socket_0(saida: &mut [u8], v: &u32) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 4)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u32((*v))?;
    }
    Ok(escritor.finish())
}

fn resp_err_socket_0(saida: &mut [u8], v: &SocketError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_socket_1<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u32,), Error> {
    let _ = caps;
    Ok((r.u32()?,))
}

fn resp_ok_socket_1(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_socket_1(saida: &mut [u8], v: &SocketError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_socket_2<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u32,), Error> {
    let _ = caps;
    Ok((r.u32()?,))
}

fn resp_ok_socket_2(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_socket_2(saida: &mut [u8], v: &SocketError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_socket_3<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u32, u32, u16), Error> {
    let _ = caps;
    Ok((r.u32()?, r.u32()?, r.u16()?))
}

fn resp_ok_socket_3(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_socket_3(saida: &mut [u8], v: &SocketError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_socket_4<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u32,), Error> {
    let _ = caps;
    Ok((r.u32()?,))
}

fn resp_ok_socket_4(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_socket_4(saida: &mut [u8], v: &SocketError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `Socket`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_socket<S: Socket>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_SOCKET {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if e.corpo.len() as u64 > 8 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 1) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_proto, p_rx, p_wake) = match pedido_socket_0(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.open(&ctx, p_proto, p_rx, p_wake) {
                Ok(x) => match resp_ok_socket_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_socket_0(saida, &x) {
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
            let mut r = match Reader::new(e.corpo, 4) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_sock,) = match pedido_socket_1(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.tx_ring(&ctx, p_sock) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_socket_1(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_socket_1(saida, &x) {
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
            let (p_sock,) = match pedido_socket_2(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.tx_signal(&ctx, p_sock) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_socket_2(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_socket_2(saida, &x) {
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
            if e.corpo.len() as u64 > 16 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 12) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_sock, p_ip, p_port) = match pedido_socket_3(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.connect(&ctx, p_sock, p_ip, p_port) {
                Ok(()) => match resp_ok_socket_3(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_socket_3(saida, &x) {
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
            let (p_sock,) = match pedido_socket_4(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.close(&ctx, p_sock) {
                Ok(()) => match resp_ok_socket_4(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_socket_4(saida, &x) {
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
pub fn despacha_socket_palavras<S: Socket>(
    s: &mut S,
    rotulo: u64,
    p: &[u64; 6],
    ctx: &Contexto,
) -> Option<(u64, [u64; 6])> {
    if (rotulo >> 32) as u32 != ID_SOCKET {
        return None;
    }
    match (rotulo & 0xFFFF) as u16 {
        _ => None,
    }
}
