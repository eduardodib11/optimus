//! `obfs`: o formato OBFS do bootfs (SDD v1.0, seções 5.3 e 14.5).
//!
//! Imagem little-endian em três partes:
//!
//! | Faixa | Conteúdo |
//! |---|---|
//! | `0..128` | Cabeçalho ([`HEADER_LEN`]) |
//! | `128..128 + 128·n` | Tabela de `n` entradas ([`ENTRY_LEN`] cada) |
//! | `data_offset..` | Dados de cada entrada, cada um alinhado a 4 KiB |
//!
//! Cabeçalho: `magic` `"OBFS"` (0), `version` u32 = 1 (4), `entry_count`
//! u32 (8), reservado u32 (12), `table_offset` u64 = 128 (16),
//! `data_offset` u64 (24, alinhado a 4 KiB, logo depois da tabela),
//! `image_len` u64 (32, o tamanho exato do arquivo, múltiplo de 4 KiB),
//! `table_hash` (40, BLAKE3 da tabela) e reservado até 128.
//!
//! Entrada: `name` (0, 64 bytes UTF-8 completados com zeros), `offset`
//! u64 (64), `size` u64 (72), `hash` (80, BLAKE3 dos `size` bytes) e
//! reservado até 128.
//!
//! [`Image::parse`] valida tudo sem alocar e sem pânico: campos
//! reservados zerados, nomes únicos e legíveis, dados alinhados, dentro da
//! imagem, em ordem e sem sobreposição, e o hash da tabela. Os hashes dos
//! dados ficam para [`Entry::verify`] (ou [`Image::verify`]), porque leem
//! a imagem inteira. Os dados ficam alinhados a 4 KiB para serem mapeados
//! sem cópia.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

use optcrypt::blake3;

#[cfg(any(test, feature = "alloc"))]
mod build;
#[cfg(any(test, feature = "alloc"))]
pub use build::build;

/// `"OBFS"`.
pub const MAGIC: [u8; 4] = *b"OBFS";
/// Versão do formato.
pub const VERSION: u32 = 1;
/// Bytes do cabeçalho; a tabela começa logo depois.
pub const HEADER_LEN: usize = 128;
/// Bytes de cada entrada da tabela.
pub const ENTRY_LEN: usize = 128;
/// Bytes do campo de nome.
pub const NAME_LEN: usize = 64;
/// Alinhamento dos dados.
pub const ALIGN: u64 = 4096;
/// Máximo de entradas aceitas.
pub const MAX_ENTRIES: usize = 1024;

/// Motivo pelo qual uma imagem foi recusada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Menor que o cabeçalho, que a tabela ou que `image_len`.
    Truncated,
    /// Não começa com [`MAGIC`].
    BadMagic,
    /// Versão diferente de [`VERSION`].
    BadVersion,
    /// Campo reservado diferente de zero.
    Reserved,
    /// Nenhuma entrada ou mais que [`MAX_ENTRIES`].
    BadCount,
    /// `table_offset`, `data_offset` ou `image_len` fora do formato.
    BadLayout,
    /// Nome vazio, com bytes depois do zero final, inválido em UTF-8 ou
    /// com caractere de controle.
    BadName,
    /// Dois nomes iguais.
    DuplicateName,
    /// Dados desalinhados, fora da imagem, fora de ordem ou sobrepostos.
    BadData,
    /// O hash da tabela não confere.
    TableHash,
    /// O hash dos dados de uma entrada não confere.
    DataHash,
}

fn u32_at(d: &[u8], at: usize) -> u32 {
    let mut b = [0; 4];
    b.copy_from_slice(&d[at..at + 4]);
    u32::from_le_bytes(b)
}

fn u64_at(d: &[u8], at: usize) -> u64 {
    let mut b = [0; 8];
    b.copy_from_slice(&d[at..at + 8]);
    u64::from_le_bytes(b)
}

fn zeros(d: &[u8]) -> bool {
    d.iter().all(|&b| b == 0)
}

/// Nome aceito numa entrada: 1 a [`NAME_LEN`] bytes UTF-8, sem
/// caracteres de controle.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= NAME_LEN && !name.chars().any(char::is_control)
}

/// Uma entrada validada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Nome.
    pub name: &'a str,
    /// Deslocamento dos dados na imagem (múltiplo de [`ALIGN`]).
    pub offset: u64,
    /// Os dados.
    pub data: &'a [u8],
    /// BLAKE3 esperado dos dados.
    pub hash: [u8; 32],
}

impl Entry<'_> {
    /// Os dados conferem com o hash da tabela.
    #[must_use]
    pub fn verify(&self) -> bool {
        blake3::hash(self.data) == self.hash
    }
}

/// Imagem OBFS validada.
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    data: &'a [u8],
    count: usize,
}

/// Lê e valida a entrada `i` (bytes da tabela já dentro da imagem).
fn entry(data: &[u8], i: usize) -> Result<Entry<'_>, Error> {
    let at = HEADER_LEN + i * ENTRY_LEN;
    let raw = &data[at..at + ENTRY_LEN];
    if !zeros(&raw[112..]) {
        return Err(Error::Reserved);
    }
    let field = &raw[..NAME_LEN];
    let len = field.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
    if !zeros(&field[len..]) {
        return Err(Error::BadName);
    }
    let name = core::str::from_utf8(&field[..len]).map_err(|_| Error::BadName)?;
    if !valid_name(name) {
        return Err(Error::BadName);
    }
    let (offset, size) = (u64_at(raw, 64), u64_at(raw, 72));
    let end = offset.checked_add(size).ok_or(Error::BadData)?;
    if !offset.is_multiple_of(ALIGN) {
        return Err(Error::BadData);
    }
    let range = usize::try_from(offset).map_err(|_| Error::BadData)?
        ..usize::try_from(end).map_err(|_| Error::BadData)?;
    let bytes = data.get(range).ok_or(Error::BadData)?;
    let mut hash = [0; 32];
    hash.copy_from_slice(&raw[80..112]);
    Ok(Entry {
        name,
        offset,
        data: bytes,
        hash,
    })
}

impl<'a> Image<'a> {
    /// Valida cabeçalho, tabela e a posição dos dados de `data`.
    ///
    /// # Errors
    ///
    /// O primeiro problema encontrado; veja [`Error`].
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header = data.get(..HEADER_LEN).ok_or(Error::Truncated)?;
        if header[..4] != MAGIC {
            return Err(Error::BadMagic);
        }
        if u32_at(header, 4) != VERSION {
            return Err(Error::BadVersion);
        }
        if u32_at(header, 12) != 0 || !zeros(&header[72..]) {
            return Err(Error::Reserved);
        }
        let count = usize::try_from(u32_at(header, 8)).map_err(|_| Error::BadCount)?;
        if count == 0 || count > MAX_ENTRIES {
            return Err(Error::BadCount);
        }
        let table_end = HEADER_LEN + count * ENTRY_LEN;
        let data_offset = (table_end as u64).next_multiple_of(ALIGN);
        let image_len = u64_at(header, 32);
        if u64_at(header, 16) != HEADER_LEN as u64
            || u64_at(header, 24) != data_offset
            || !image_len.is_multiple_of(ALIGN)
            || image_len < data_offset
        {
            return Err(Error::BadLayout);
        }
        if data.len() as u64 != image_len {
            return Err(if (data.len() as u64) < image_len {
                Error::Truncated
            } else {
                Error::BadLayout
            });
        }
        if blake3::hash(&data[HEADER_LEN..table_end]) != header[40..72] {
            return Err(Error::TableHash);
        }
        let mut next = data_offset;
        for i in 0..count {
            let e = entry(data, i)?;
            if e.offset < next {
                return Err(Error::BadData);
            }
            next = (e.offset + e.data.len() as u64).next_multiple_of(ALIGN);
            for j in 0..i {
                if entry(data, j)?.name == e.name {
                    return Err(Error::DuplicateName);
                }
            }
        }
        Ok(Self { data, count })
    }

    /// Quantidade de entradas.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Sempre falso: uma imagem válida tem ao menos uma entrada.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// As entradas, na ordem da tabela (crescente de deslocamento).
    pub fn entries(&self) -> impl Iterator<Item = Entry<'a>> + '_ {
        (0..self.count).filter_map(|i| entry(self.data, i).ok())
    }

    /// A entrada chamada `name`.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Entry<'a>> {
        self.entries().find(|e| e.name == name)
    }

    /// Confere o hash dos dados de todas as entradas.
    ///
    /// # Errors
    ///
    /// [`Error::DataHash`] com o nome da primeira entrada que não confere.
    pub fn verify(&self) -> Result<(), (Error, &'a str)> {
        match self.entries().find(|e| !e.verify()) {
            Some(bad) => Err((Error::DataHash, bad.name)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests;
