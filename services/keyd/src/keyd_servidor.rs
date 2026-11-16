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

/// Enumeração `KeydError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeydError(pub u8);

impl KeydError {
    /// Variante `NoConsole`.
    pub const NoConsole: KeydError = KeydError(0);
    /// Variante `BadSlot`.
    pub const BadSlot: KeydError = KeydError(1);
    /// Variante `WrongPassword`.
    pub const WrongPassword: KeydError = KeydError(2);
    /// Variante `Cancelled`.
    pub const Cancelled: KeydError = KeydError(3);
    /// Variante `NoEntropy`.
    pub const NoEntropy: KeydError = KeydError(4);
    /// Variante `Memory`.
    pub const Memory: KeydError = KeydError(5);
    /// Variante `Locked`.
    pub const Locked: KeydError = KeydError(6);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<KeydError> {
        match v {
            0 | 1 | 2 | 3 | 4 | 5 | 6 => Some(KeydError(v)),
            _ => None,
        }
    }
}

/// Identificador da interface `Keyring` (ADR 0033, seção 2).
pub const ID_KEYRING: u32 = 0x76565134;

/// Interface `Keyring`: implemente para servir.
pub trait Keyring {
    /// Método `create_volume` (ordinal 0).
    fn create_volume(&mut self, ctx: &Contexto, uuid: &str) -> Result<&[u8], KeydError>;
    /// Método `unlock` (ordinal 1).
    fn unlock(&mut self, ctx: &Contexto, uuid: &str, slots: &str) -> Result<&[u8], KeydError>;
    /// Método `dataset_key` (ordinal 2).
    fn dataset_key(&mut self, ctx: &Contexto, uuid: &str, dataset: u32)
    -> Result<&[u8], KeydError>;
}

fn pedido_keyring_0<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(&'a str,), Error> {
    let _ = caps;
    Ok((r.string(32)?,))
}

fn resp_ok_keyring_0(saida: &mut [u8], v: &&[u8]) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 8)?;
    {
        let w = &mut escritor;
        let off1 = {
            w.seek(0);
            w.vec((*v).len(), 1, 202)?
        };
        for (i1, el) in (*v).iter().enumerate() {
            let at2 = off1 + i1 * 1;
            w.seek(at2);
            w.u8((*el))?;
        }
    }
    Ok(escritor.finish())
}

fn resp_err_keyring_0(saida: &mut [u8], v: &KeydError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_keyring_1<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(&'a str, &'a str), Error> {
    let _ = caps;
    Ok((r.string(32)?, r.string(1616)?))
}

fn resp_ok_keyring_1(saida: &mut [u8], v: &&[u8]) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 8)?;
    {
        let w = &mut escritor;
        let off2 = {
            w.seek(0);
            w.vec((*v).len(), 1, 96)?
        };
        for (i2, el) in (*v).iter().enumerate() {
            let at2 = off2 + i2 * 1;
            w.seek(at2);
            w.u8((*el))?;
        }
    }
    Ok(escritor.finish())
}

fn resp_err_keyring_1(saida: &mut [u8], v: &KeydError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_keyring_2<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(&'a str, u32), Error> {
    let _ = caps;
    Ok((r.string(32)?, r.u32()?))
}

fn resp_ok_keyring_2(saida: &mut [u8], v: &&[u8]) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 8)?;
    {
        let w = &mut escritor;
        let off3 = {
            w.seek(0);
            w.vec((*v).len(), 1, 32)?
        };
        for (i3, el) in (*v).iter().enumerate() {
            let at2 = off3 + i3 * 1;
            w.seek(at2);
            w.u8((*el))?;
        }
    }
    Ok(escritor.finish())
}

fn resp_err_keyring_2(saida: &mut [u8], v: &KeydError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `Keyring`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_keyring<S: Keyring>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_KEYRING {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if versao_menor < 1 {
                return protocolo(3);
            }
            if e.corpo.len() as u64 > 40 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 8) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_uuid,) = match pedido_keyring_0(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.create_volume(&ctx, p_uuid) {
                Ok(x) => match resp_ok_keyring_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_keyring_0(saida, &x) {
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
            if versao_menor < 1 {
                return protocolo(3);
            }
            if e.corpo.len() as u64 > 1664 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 16) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_uuid, p_slots) = match pedido_keyring_1(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.unlock(&ctx, p_uuid, p_slots) {
                Ok(x) => match resp_ok_keyring_1(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_keyring_1(saida, &x) {
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
            if versao_menor < 1 {
                return protocolo(3);
            }
            if e.corpo.len() as u64 > 48 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 12) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_uuid, p_dataset) = match pedido_keyring_2(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.dataset_key(&ctx, p_uuid, p_dataset) {
                Ok(x) => match resp_ok_keyring_2(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_keyring_2(saida, &x) {
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
pub fn despacha_keyring_palavras<S: Keyring>(
    s: &mut S,
    rotulo: u64,
    p: &[u64; 6],
    ctx: &Contexto,
) -> Option<(u64, [u64; 6])> {
    if (rotulo >> 32) as u32 != ID_KEYRING {
        return None;
    }
    match (rotulo & 0xFFFF) as u16 {
        _ => None,
    }
}
