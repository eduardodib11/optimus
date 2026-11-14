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
    non_upper_case_globals,
    reason = "código gerado: estilo e campos que um serviço pode não usar"
)]

use oidl_rt::{Error, Reader, Writer};

/// Erro de codificação ou decodificação vira erro de IPC.
fn erro_oidl(_: Error) -> ostd::kabi::Error {
    ostd::kabi::Error::InvalidArgument
}

/// Enumeração `ConsoleError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleError(pub u8);

impl ConsoleError {
    /// Variante `Io`.
    pub const Io: ConsoleError = ConsoleError(0);
    /// Variante `Timeout`.
    pub const Timeout: ConsoleError = ConsoleError(1);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<ConsoleError> {
        match v {
            0 | 1 => Some(ConsoleError(v)),
            _ => None,
        }
    }
}

/// Cliente da interface `Console` (T-345).
pub struct ConsoleCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl ConsoleCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `write` (ordinal 0).
    pub fn write(
        &self,
        buf: &mut ostd::ipc::Buffer,
        texto: &str,
    ) -> Result<Result<u32, ConsoleError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 136];
        let n = codifica_console_0(&mut pedido, &texto).map_err(erro_oidl)?;
        let mut saida = [0u8; 8];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x9A70903500000000,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_console_0(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(
                decodifica_err_console_0(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }
}

fn codifica_console_0(saida: &mut [u8], texto: &&str) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 8)?;
    w.seek(0);
    w.string((*texto), 128)?;
    Ok(w.finish())
}

fn decodifica_ok_console_0(corpo: &[u8]) -> Result<u32, Error> {
    let mut r = Reader::new(corpo, 4)?;
    let v = r.u32()?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_console_0(corpo: &[u8]) -> Result<ConsoleError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = ConsoleError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}
