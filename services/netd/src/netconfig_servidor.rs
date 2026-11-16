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

/// Enumeração `ConfigError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError(pub u8);

impl ConfigError {
    /// Variante `Busy`.
    pub const Busy: ConfigError = ConfigError(0);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<ConfigError> {
        match v {
            0 => Some(ConfigError(v)),
            _ => None,
        }
    }
}

/// Struct `NetStatus`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetStatus {
    /// Campo `mac`.
    pub mac: u64,
    /// Campo `ip`.
    pub ip: u32,
    /// Campo `mask`.
    pub mask: u32,
    /// Campo `gateway`.
    pub gateway: u32,
    /// Campo `dns`.
    pub dns: u32,
}

fn enc_net_status(w: &mut Writer<'_>, v: &NetStatus, base: usize) -> Result<(), Error> {
    w.seek(base);
    w.u64(v.mac)?;
    w.seek(base + 8);
    w.u32(v.ip)?;
    w.seek(base + 12);
    w.u32(v.mask)?;
    w.seek(base + 16);
    w.u32(v.gateway)?;
    w.seek(base + 20);
    w.u32(v.dns)?;
    Ok(())
}

/// Identificador da interface `Config` (ADR 0033, seção 2).
pub const ID_CONFIG: u32 = 0xA18CCC64;

/// Interface `Config`: implemente para servir.
pub trait Config {
    /// Método `status` (ordinal 0).
    fn status(&mut self, ctx: &Contexto) -> Result<NetStatus, ConfigError>;
}

fn resp_ok_config_0(saida: &mut [u8], v: &NetStatus) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 24)?;
    {
        let w = &mut escritor;
        enc_net_status(w, v, 0)?;
    }
    Ok(escritor.finish())
}

fn resp_err_config_0(saida: &mut [u8], v: &ConfigError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `Config`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_config<S: Config>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_CONFIG {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if !e.corpo.is_empty() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.status(&ctx) {
                Ok(x) => match resp_ok_config_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_config_0(saida, &x) {
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
pub fn despacha_config_palavras<S: Config>(
    s: &mut S,
    rotulo: u64,
    p: &[u64; 6],
    ctx: &Contexto,
) -> Option<(u64, [u64; 6])> {
    if (rotulo >> 32) as u32 != ID_CONFIG {
        return None;
    }
    match (rotulo & 0xFFFF) as u16 {
        _ => None,
    }
}
