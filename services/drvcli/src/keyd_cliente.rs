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

/// Cliente da interface `Keyring` (T-345).
pub struct KeyringCliente {
    /// Endpoint para onde as chamadas vão.
    pub ep: ostd::kabi::Handle,
}

impl KeyringCliente {
    /// Cliente para `ep`.
    #[must_use]
    pub const fn new(ep: ostd::kabi::Handle) -> Self {
        Self { ep }
    }
    /// Método `create_volume` (ordinal 0).
    pub fn create_volume(
        &self,
        buf: &mut ostd::ipc::Buffer,
        uuid: &str,
    ) -> Result<Result<oidl_rt::Bytes<202>, KeydError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 40];
        let n = codifica_keyring_0(&mut pedido, &uuid).map_err(erro_oidl)?;
        let mut saida = [0u8; 216];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x7656513400010000,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_keyring_0(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(
                decodifica_err_keyring_0(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `unlock` (ordinal 1).
    pub fn unlock(
        &self,
        buf: &mut ostd::ipc::Buffer,
        uuid: &str,
        slots: &str,
    ) -> Result<Result<oidl_rt::Bytes<96>, KeydError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 1664];
        let n = codifica_keyring_1(&mut pedido, &uuid, &slots).map_err(erro_oidl)?;
        let mut saida = [0u8; 104];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x7656513400010001,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_keyring_1(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(
                decodifica_err_keyring_1(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }

    /// Método `dataset_key` (ordinal 2).
    pub fn dataset_key(
        &self,
        buf: &mut ostd::ipc::Buffer,
        uuid: &str,
        dataset: u32,
    ) -> Result<Result<oidl_rt::Bytes<32>, KeydError>, ostd::kabi::Error> {
        let mut pedido = [0u8; 48];
        let n = codifica_keyring_2(&mut pedido, &uuid, &dataset).map_err(erro_oidl)?;
        let mut saida = [0u8; 40];
        let (rotulo, m) = ostd::ipc::call_corpo(
            self.ep,
            buf,
            0x7656513400010002,
            &pedido[..n],
            &mut saida,
            0,
        )?;
        if rotulo >> 62 == 0 {
            Ok(Ok(decodifica_ok_keyring_2(&saida[..m]).map_err(erro_oidl)?))
        } else {
            Ok(Err(
                decodifica_err_keyring_2(&saida[..m]).map_err(erro_oidl)?
            ))
        }
    }
}

fn codifica_keyring_0(saida: &mut [u8], uuid: &&str) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 8)?;
    w.seek(0);
    w.string((*uuid), 32)?;
    Ok(w.finish())
}

fn decodifica_ok_keyring_0(corpo: &[u8]) -> Result<oidl_rt::Bytes<202>, Error> {
    let mut r = Reader::new(corpo, 8)?;
    let v = oidl_rt::Bytes::<202>::from_slice(r.bytes(202)?)?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_keyring_0(corpo: &[u8]) -> Result<KeydError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = KeydError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_keyring_1(saida: &mut [u8], uuid: &&str, slots: &&str) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 16)?;
    w.seek(0);
    w.string((*uuid), 32)?;
    w.seek(8);
    w.string((*slots), 1616)?;
    Ok(w.finish())
}

fn decodifica_ok_keyring_1(corpo: &[u8]) -> Result<oidl_rt::Bytes<96>, Error> {
    let mut r = Reader::new(corpo, 8)?;
    let v = oidl_rt::Bytes::<96>::from_slice(r.bytes(96)?)?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_keyring_1(corpo: &[u8]) -> Result<KeydError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = KeydError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}

fn codifica_keyring_2(saida: &mut [u8], uuid: &&str, dataset: &u32) -> Result<usize, Error> {
    let mut w = Writer::new(saida, 12)?;
    w.seek(0);
    w.string((*uuid), 32)?;
    w.seek(8);
    w.u32((*dataset))?;
    Ok(w.finish())
}

fn decodifica_ok_keyring_2(corpo: &[u8]) -> Result<oidl_rt::Bytes<32>, Error> {
    let mut r = Reader::new(corpo, 8)?;
    let v = oidl_rt::Bytes::<32>::from_slice(r.bytes(32)?)?;
    r.finish()?;
    Ok(v)
}

fn decodifica_err_keyring_2(corpo: &[u8]) -> Result<KeydError, Error> {
    let mut r = Reader::new(corpo, 1)?;
    let v = KeydError::from_raw(r.u8()?).ok_or(Error::BadMessage)?;
    r.finish()?;
    Ok(v)
}
