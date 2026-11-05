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
    reason = "código gerado: estilo e campos que um serviço pode não usar"
)]

use oidl_rt::{Error, Reader, Writer};

/// Erro de codificação ou decodificação vira erro de IPC.
fn erro_oidl(_: Error) -> ostd::kabi::Error {
    ostd::kabi::Error::InvalidArgument
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

/// Cliente da interface `Hello` (T-345).
pub struct HelloCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl HelloCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `saudacao` (ordinal 0).
    pub fn saudacao(
        &self,
        buf: &mut ostd::ipc::Buffer,
        texto: &str,
    ) -> Result<Result<u64, u8>, ostd::kabi::Error> {
        let mut pedido = [0u8; 72];
        let n = codifica_hello_0(&mut pedido, &texto).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x0C5F05E300000000,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_hello_0(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(decodifica_err_hello_0(&saida[..m]).map_err(erro_oidl)?))
        }
    }

    /// Método `ping` (ordinal 1).
    pub fn ping(
        &self,
        buf: &mut ostd::ipc::Buffer,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) -> Result<Result<Seis, u8>, ostd::kabi::Error> {
        let _ = buf;
        let (rotulo, w) =
            ostd::ipc::call_palavras(self.ep, 0x0C5F05E300000001, [a, b, c, d, e, f], 0)?;
        if rotulo >> 62 == 0 {
            Ok(Ok(Seis {
                w0: w[0],
                w1: w[1],
                w2: w[2],
                w3: w[3],
                w4: w[4],
                w5: w[5],
            }))
        } else {
            Ok(Err(0))
        }
    }

    /// Método `bye` (ordinal 2).
    pub fn bye(
        &self,
        buf: &mut ostd::ipc::Buffer,
        voltas: u64,
        erros: u64,
    ) -> Result<Result<(), u8>, ostd::kabi::Error> {
        let mut pedido = [0u8; 16];
        let n = codifica_hello_2(&mut pedido, &voltas, &erros).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x0C5F05E300000002,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_hello_2(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(decodifica_err_hello_2(&saida[..m]).map_err(erro_oidl)?))
        }
    }
}

fn codifica_hello_0(saida: &mut [u8], texto: &&str) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 8)?;
    w.seek(0);
    w.string((*texto), 64)?;
    Ok(w.finish())
}

fn decodifica_ok_hello_0(corpo: &[u8]) -> Result<u64, Error> {
    let mut r = Reader::new(corpo, 8)?;
    let v = r.u64()?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_hello_0(corpo: &[u8]) -> Result<u8, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = r.u8()?;
    r.finish()?;
    Ok(v)
}

fn codifica_hello_1(
    saida: &mut [u8],
    a: &u64,
    b: &u64,
    c: &u64,
    d: &u64,
    e: &u64,
    f: &u64,
) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 48)?;
    w.seek(0);
    w.u64((*a))?;
    w.seek(8);
    w.u64((*b))?;
    w.seek(16);
    w.u64((*c))?;
    w.seek(24);
    w.u64((*d))?;
    w.seek(32);
    w.u64((*e))?;
    w.seek(40);
    w.u64((*f))?;
    Ok(w.finish())
}

fn decodifica_ok_hello_1(corpo: &[u8]) -> Result<Seis, Error> {
    let mut r = Reader::new(corpo, 48)?;
    let v = Seis {
        w0: r.u64()?,
        w1: r.u64()?,
        w2: r.u64()?,
        w3: r.u64()?,
        w4: r.u64()?,
        w5: r.u64()?,
    };
    r.finish()?;
    Ok(v)
}

fn decodifica_err_hello_1(corpo: &[u8]) -> Result<u8, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = r.u8()?;
    r.finish()?;
    Ok(v)
}

fn codifica_hello_2(saida: &mut [u8], voltas: &u64, erros: &u64) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 16)?;
    w.seek(0);
    w.u64((*voltas))?;
    w.seek(8);
    w.u64((*erros))?;
    Ok(w.finish())
}

fn decodifica_ok_hello_2(corpo: &[u8]) -> Result<(), Error> {
    let r = Reader::new(corpo, 0)?;
    let _ = corpo;
    r.finish()?;
    Ok(())
}

fn decodifica_err_hello_2(corpo: &[u8]) -> Result<u8, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = r.u8()?;
    r.finish()?;
    Ok(v)
}
