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

/// Enumeração `RngError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RngError(pub u8);

impl RngError {
    /// Variante `Failed`.
    pub const Failed: RngError = RngError(0);
    /// Variante `Busy`.
    pub const Busy: RngError = RngError(1);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<RngError> {
        match v {
            0 | 1 => Some(RngError(v)),
            _ => None,
        }
    }
}

/// Cliente da interface `EntropySource` (T-345).
pub struct EntropySourceCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl EntropySourceCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `read` (ordinal 0).
    pub fn read(
        &self,
        buf: &mut ostd::ipc::Buffer,
        len: u8,
    ) -> Result<Result<oidl_rt::Bytes<64>, RngError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 8];
        let n = codifica_entropy_source_0(&mut pedido, &len).map_err(erro_oidl)?;
        let mut saida = [0u8; 72];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0xE9E49FF100000000,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(
                decodifica_ok_entropy_source_0(&saida[..m]).map_err(erro_oidl)?
            ))
        } else {
            Ok(Err(
                decodifica_err_entropy_source_0(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }
}

fn codifica_entropy_source_0(saida: &mut [u8], len: &u8) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 1)?;
    w.seek(0);
    w.u8((*len))?;
    Ok(w.finish())
}

fn decodifica_ok_entropy_source_0(corpo: &[u8]) -> Result<oidl_rt::Bytes<64>, Error> {
    let mut r = Reader::new(corpo, 8)?;
    let v = oidl_rt::Bytes::<64>::from_slice(r.bytes(64)?)?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_entropy_source_0(corpo: &[u8]) -> Result<RngError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = RngError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}
