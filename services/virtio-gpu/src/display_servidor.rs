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
    non_upper_case_globals,
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

/// Identificador da interface `DisplayDevice` (ADR 0033, seção 2).
pub const ID_DISPLAYDEVICE: u32 = 0xF2FA998F;

/// Interface `DisplayDevice`: implemente para servir.
pub trait DisplayDevice {
    /// Método `mode_count` (ordinal 0).
    fn mode_count(&mut self, ctx: &Contexto) -> Result<u16, DisplayError>;
    /// Método `mode` (ordinal 1).
    fn mode(&mut self, ctx: &Contexto, index: u16) -> Result<Mode, DisplayError>;
    /// Método `set_mode` (ordinal 2).
    fn set_mode(&mut self, ctx: &Contexto, id: u16) -> Result<(), DisplayError>;
    /// Método `present` (ordinal 3).
    fn present(
        &mut self,
        ctx: &Contexto,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), DisplayError>;
}

fn resp_ok_display_device_0(saida: &mut [u8], v: &u16) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 2)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u16((*v))?;
    }
    Ok(escritor.finish())
}

fn resp_err_display_device_0(saida: &mut [u8], v: &DisplayError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_display_device_1<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u16,), Error> {
    let _ = caps;
    Ok((r.u16()?,))
}

fn resp_ok_display_device_1(saida: &mut [u8], v: &Mode) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 6)?;
    {
        let w = &mut escritor;
        enc_mode(w, v, 0)?;
    }
    Ok(escritor.finish())
}

fn resp_err_display_device_1(saida: &mut [u8], v: &DisplayError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_display_device_2<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u16,), Error> {
    let _ = caps;
    Ok((r.u16()?,))
}

fn resp_ok_display_device_2(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_display_device_2(saida: &mut [u8], v: &DisplayError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_display_device_3<'a>(
    r: &mut Reader<'a>,
    caps: &[u64],
) -> Result<(u16, u16, u16, u16), Error> {
    let _ = caps;
    Ok((r.u16()?, r.u16()?, r.u16()?, r.u16()?))
}

fn resp_ok_display_device_3(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_display_device_3(saida: &mut [u8], v: &DisplayError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `DisplayDevice`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_display_device<S: DisplayDevice>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_DISPLAYDEVICE {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if !e.corpo.is_empty() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.mode_count(&ctx) {
                Ok(x) => match resp_ok_display_device_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_display_device_0(saida, &x) {
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
            let mut r = match Reader::new(e.corpo, 2) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_index,) = match pedido_display_device_1(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.mode(&ctx, p_index) {
                Ok(x) => match resp_ok_display_device_1(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_display_device_1(saida, &x) {
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
            let mut r = match Reader::new(e.corpo, 2) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_id,) = match pedido_display_device_2(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.set_mode(&ctx, p_id) {
                Ok(()) => match resp_ok_display_device_2(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_display_device_2(saida, &x) {
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
            let mut r = match Reader::new(e.corpo, 8) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_x, p_y, p_width, p_height) = match pedido_display_device_3(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.present(&ctx, p_x, p_y, p_width, p_height) {
                Ok(()) => match resp_ok_display_device_3(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_display_device_3(saida, &x) {
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
pub fn despacha_display_device_palavras<S: DisplayDevice>(
    s: &mut S,
    rotulo: u64,
    p: &[u64; 6],
    ctx: &Contexto,
) -> Option<(u64, [u64; 6])> {
    if (rotulo >> 32) as u32 != ID_DISPLAYDEVICE {
        return None;
    }
    match (rotulo & 0xFFFF) as u16 {
        _ => None,
    }
}
