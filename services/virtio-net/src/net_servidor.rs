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

/// Identificador da interface `NetDevice` (ADR 0033, seção 2).
pub const ID_NETDEVICE: u32 = 0xC3BD310E;

/// Interface `NetDevice`: implemente para servir.
pub trait NetDevice {
    /// Método `info` (ordinal 0).
    fn info(&mut self, ctx: &Contexto) -> Result<NetInfo, NetError>;
    /// Método `session` (ordinal 1).
    fn session(&mut self, ctx: &Contexto) -> Result<u64, NetError>;
    /// Método `tx_ring` (ordinal 2).
    fn tx_ring(&mut self, ctx: &Contexto) -> Result<u64, NetError>;
    /// Método `tx_signal` (ordinal 3).
    fn tx_signal(&mut self, ctx: &Contexto) -> Result<u64, NetError>;
    /// Método `attach_rx` (ordinal 4).
    fn attach_rx(&mut self, ctx: &Contexto, ring: u64, signal: u64) -> Result<(), NetError>;
}

fn resp_ok_net_device_0(saida: &mut [u8], v: &NetInfo) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 16)?;
    {
        let w = &mut escritor;
        enc_net_info(w, v, 0)?;
    }
    Ok(escritor.finish())
}

fn resp_err_net_device_0(saida: &mut [u8], v: &NetError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn resp_ok_net_device_1(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_net_device_1(saida: &mut [u8], v: &NetError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn resp_ok_net_device_2(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_net_device_2(saida: &mut [u8], v: &NetError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn resp_ok_net_device_3(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_net_device_3(saida: &mut [u8], v: &NetError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_net_device_4<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u64, u64), Error> {
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
    ))
}

fn resp_ok_net_device_4(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_net_device_4(saida: &mut [u8], v: &NetError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `NetDevice`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_net_device<S: NetDevice>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_NETDEVICE {
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
                Ok(x) => match resp_ok_net_device_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_net_device_0(saida, &x) {
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
            if !e.corpo.is_empty() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.session(&ctx) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_net_device_1(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_net_device_1(saida, &x) {
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
            if !e.corpo.is_empty() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.tx_ring(&ctx) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_net_device_2(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_net_device_2(saida, &x) {
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
            if !e.corpo.is_empty() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.tx_signal(&ctx) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_net_device_3(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_net_device_3(saida, &x) {
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
            if e.corpo.len() as u64 > 0 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 0) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_ring, p_signal) = match pedido_net_device_4(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.attach_rx(&ctx, p_ring, p_signal) {
                Ok(()) => match resp_ok_net_device_4(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_net_device_4(saida, &x) {
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
pub fn despacha_net_device_palavras<S: NetDevice>(
    s: &mut S,
    rotulo: u64,
    p: &[u64; 6],
    ctx: &Contexto,
) -> Option<(u64, [u64; 6])> {
    if (rotulo >> 32) as u32 != ID_NETDEVICE {
        return None;
    }
    match (rotulo & 0xFFFF) as u16 {
        _ => None,
    }
}
