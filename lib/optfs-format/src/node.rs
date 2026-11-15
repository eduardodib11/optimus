//! Cabeçalho de nó e chave das árvores B+ (ADR 0052, item 3).

use crate::{Error, NODE_HEADER_LEN, all_zero, rd_u16, rd_u64};

/// `"OFNd"` em little-endian.
pub const NODE_MAGIC: u32 = u32::from_le_bytes(*b"OFNd");

/// Tipo de item de uma chave, na ordem em que aparecem dentro de um objeto.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum KeyKind {
    /// Inode.
    Inode = 0,
    /// Entrada de diretório (deslocamento = hash do nome).
    Dirent = 1,
    /// Extent de arquivo (deslocamento = posição lógica).
    Extent = 2,
    /// Atributo estendido (deslocamento = hash do nome).
    Xattr = 3,
}

/// Chave `(objeto, tipo, deslocamento)`, em ordem lexicográfica.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    /// Número do objeto (ou do diretório).
    pub object: u64,
    /// Tipo do item.
    pub kind: KeyKind,
    /// Deslocamento ou hash.
    pub offset: u64,
}

impl Key {
    /// Bytes de uma chave serializada.
    pub const LEN: usize = 24;

    /// Serializa: objeto (0), tipo (8), 7 zeros, deslocamento (16).
    #[must_use]
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..8].copy_from_slice(&self.object.to_le_bytes());
        b[8] = self.kind as u8;
        b[16..24].copy_from_slice(&self.offset.to_le_bytes());
        b
    }

    /// Lê uma chave de 24 bytes.
    ///
    /// # Errors
    /// [`Error::BadLen`], [`Error::BadField`] (tipo) ou [`Error::Reserved`].
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != Self::LEN {
            return Err(Error::BadLen);
        }
        let kind = match b[8] {
            0 => KeyKind::Inode,
            1 => KeyKind::Dirent,
            2 => KeyKind::Extent,
            3 => KeyKind::Xattr,
            _ => return Err(Error::BadField),
        };
        if !all_zero(&b[9..16]) {
            return Err(Error::Reserved);
        }
        Ok(Self {
            object: rd_u64(b, 0),
            kind,
            offset: rd_u64(b, 16),
        })
    }
}

/// Cabeçalho de 64 bytes de um nó de 4 KiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeHeader {
    /// Nível (0 = folha).
    pub level: u8,
    /// Itens no nó.
    pub count: u16,
    /// Árvore dona.
    pub tree: u64,
    /// Txg em que o nó foi escrito.
    pub txg: u64,
    /// Endereço do próprio bloco (detecta escrita no lugar errado).
    pub addr: u64,
}

impl NodeHeader {
    /// Serializa em 64 bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; NODE_HEADER_LEN] {
        let mut b = [0u8; NODE_HEADER_LEN];
        b[0..4].copy_from_slice(&NODE_MAGIC.to_le_bytes());
        b[4] = self.level;
        b[6..8].copy_from_slice(&self.count.to_le_bytes());
        b[8..16].copy_from_slice(&self.tree.to_le_bytes());
        b[16..24].copy_from_slice(&self.txg.to_le_bytes());
        b[24..32].copy_from_slice(&self.addr.to_le_bytes());
        b
    }

    /// Lê o cabeçalho dos primeiros 64 bytes de `b`.
    ///
    /// # Errors
    /// [`Error::BadLen`], [`Error::BadMagic`] ou [`Error::Reserved`].
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() < NODE_HEADER_LEN {
            return Err(Error::BadLen);
        }
        if crate::rd_u32(b, 0) != NODE_MAGIC {
            return Err(Error::BadMagic);
        }
        if b[5] != 0 || !all_zero(&b[32..NODE_HEADER_LEN]) {
            return Err(Error::Reserved);
        }
        Ok(Self {
            level: b[4],
            count: rd_u16(b, 6),
            tree: rd_u64(b, 8),
            txg: rd_u64(b, 16),
            addr: rd_u64(b, 24),
        })
    }
}
