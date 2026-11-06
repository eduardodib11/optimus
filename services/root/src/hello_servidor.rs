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

/// Struct `Seis`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seis {
    /// Campo `w0`.
    pub w0: u64,
    /// Campo `w1`.
    pub w1: u64,
    /// Campo `w2`.
    pub w2: u64,
    /// Campo `w3`.
    pub w3: u64,
    /// Campo `w4`.
    pub w4: u64,
    /// Campo `w5`.
    pub w5: u64,
}

fn enc_seis(w: &mut Writer<'_>, v: &Seis, base: usize) -> Result<(), Error> {
    w.seek(base);
    w.u64(v.w0)?;
    w.seek(base + 8);
    w.u64(v.w1)?;
    w.seek(base + 16);
    w.u64(v.w2)?;
    w.seek(base + 24);
    w.u64(v.w3)?;
    w.seek(base + 32);
    w.u64(v.w4)?;
    w.seek(base + 40);
    w.u64(v.w5)?;
    Ok(())
}

/// Identificador da interface `Hello` (ADR 0033, seção 2).
pub const ID_HELLO: u32 = 0x0C5F05E3;

/// Interface `Hello`: implemente para servir.
pub trait Hello {
    /// Método `saudacao` (ordinal 0).
    fn saudacao(&mut self, ctx: &Contexto, texto: &str) -> Result<u64, u8>;
    /// Método `ping` (ordinal 1).
    fn ping(
        &mut self,
        ctx: &Contexto,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) -> Result<Seis, u8>;
    /// Método `bye` (ordinal 2).
    fn bye(&mut self, ctx: &Contexto, voltas: u64, erros: u64) -> Result<(), u8>;
}

fn pedido_hello_0<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(&'a str,), Error> {
    let _ = caps;
    Ok((r.string(64)?,))
}

fn resp_ok_hello_0(saida: &mut [u8], v: &u64) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 8)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u64((*v))?;
    }
    Ok(escritor.finish())
}

fn resp_err_hello_0(saida: &mut [u8], v: &u8) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((*v))?;
    }
    Ok(escritor.finish())
}

fn pedido_hello_1<'a>(
    r: &mut Reader<'a>,
    caps: &[u64],
) -> Result<(u64, u64, u64, u64, u64, u64), Error> {
    let _ = caps;
    Ok((r.u64()?, r.u64()?, r.u64()?, r.u64()?, r.u64()?, r.u64()?))
}

fn resp_ok_hello_1(saida: &mut [u8], v: &Seis) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 48)?;
    {
        let w = &mut escritor;
        enc_seis(w, v, 0)?;
    }
    Ok(escritor.finish())
}

fn resp_err_hello_1(saida: &mut [u8], v: &u8) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((*v))?;
    }
    Ok(escritor.finish())
}

fn pedido_hello_2<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(u64, u64), Error> {
    let _ = caps;
    Ok((r.u64()?, r.u64()?))
}

fn resp_ok_hello_2(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_hello_2(saida: &mut [u8], v: &u8) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((*v))?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `Hello`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_hello<S: Hello>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_HELLO {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if e.corpo.len() as u64 > 72 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 8) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_texto,) = match pedido_hello_0(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.saudacao(&ctx, p_texto) {
                Ok(x) => match resp_ok_hello_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_hello_0(saida, &x) {
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
            if e.corpo.len() as u64 > 48 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 48) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_a, p_b, p_c, p_d, p_e, p_f) = match pedido_hello_1(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.ping(&ctx, p_a, p_b, p_c, p_d, p_e, p_f) {
                Ok(x) => match resp_ok_hello_1(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_hello_1(saida, &x) {
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
            if e.corpo.len() as u64 > 16 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 16) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_voltas, p_erros) = match pedido_hello_2(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.bye(&ctx, p_voltas, p_erros) {
                Ok(()) => match resp_ok_hello_2(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_hello_2(saida, &x) {
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
pub fn despacha_hello_palavras<S: Hello>(
    s: &mut S,
    rotulo: u64,
    p: &[u64; 6],
    ctx: &Contexto,
) -> Option<(u64, [u64; 6])> {
    if (rotulo >> 32) as u32 != ID_HELLO {
        return None;
    }
    match (rotulo & 0xFFFF) as u16 {
        1 => {
            let p_a = p[0];
            let p_b = p[1];
            let p_c = p[2];
            let p_d = p[3];
            let p_e = p[4];
            let p_f = p[5];
            Some(match s.ping(ctx, p_a, p_b, p_c, p_d, p_e, p_f) {
                Ok(x) => (rotulo_resposta(0, 0), [x.w0, x.w1, x.w2, x.w3, x.w4, x.w5]),
                Err(e) => (rotulo_resposta(1, 0), [u64::from(e), 0, 0, 0, 0, 0]),
            })
        }
        2 => {
            let p_voltas = p[0];
            let p_erros = p[1];
            Some(match s.bye(ctx, p_voltas, p_erros) {
                Ok(x) => (rotulo_resposta(0, 0), [0; 6]),
                Err(e) => (rotulo_resposta(1, 0), [u64::from(e), 0, 0, 0, 0, 0]),
            })
        }
        _ => None,
    }
}
