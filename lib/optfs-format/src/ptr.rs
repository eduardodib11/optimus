//! Ponteiro de bloco (ADR 0052, item 2).

use crate::{Error, MAX_EXTENT, PTR_LEN, all_zero, rd_u32, rd_u64};

/// Modo de integridade do filho (um por volume).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integrity {
    /// SHA-256 do bloco gravado em `autenticação`.
    Hash = 0,
    /// AEAD: tag de 16 bytes em `autenticação` e `nonce` (ADR 0053).
    Aead = 1,
}

/// Compressão do extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// Gravado cru.
    None = 0,
    /// LZ4 (`lib/olz4`).
    Lz4 = 1,
}

/// Tipo do bloco apontado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PtrKind {
    /// Nó de árvore.
    Node = 0,
    /// Dados de arquivo.
    Data = 1,
    /// Mapa de bits de um grupo de alocação.
    Bitmap = 2,
}

/// Ponteiro de bloco de 72 bytes: onde o filho está, quando nasceu e como
/// conferi-lo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockPtr {
    /// Primeiro bloco.
    pub addr: u64,
    /// Txg em que o bloco foi escrito.
    pub birth: u64,
    /// Bytes antes da compressão (até [`MAX_EXTENT`]).
    pub logical: u32,
    /// Bytes gravados, múltiplo de 4 KiB.
    pub physical: u32,
    /// Nível na árvore (0 = folha).
    pub level: u8,
    /// Tipo do bloco.
    pub kind: PtrKind,
    /// Compressão.
    pub compression: Compression,
    /// Modo de integridade.
    pub integrity: Integrity,
    /// Modo AEAD: época `u32` e contador `u64`; modo hash: zero.
    pub nonce: [u8; 12],
    /// Modo AEAD: tag (16 bytes) e 16 zeros; modo hash: SHA-256.
    pub auth: [u8; 32],
}

impl BlockPtr {
    /// Ponteiro nulo (tudo zero): "sem filho".
    #[must_use]
    pub fn null() -> Self {
        Self {
            addr: 0,
            birth: 0,
            logical: 0,
            physical: 0,
            level: 0,
            kind: PtrKind::Node,
            compression: Compression::None,
            integrity: Integrity::Hash,
            nonce: [0; 12],
            auth: [0; 32],
        }
    }

    /// Se é o ponteiro nulo.
    #[must_use]
    pub fn is_null(&self) -> bool {
        *self == Self::null()
    }

    /// Serializa em 72 bytes little-endian.
    #[must_use]
    pub fn encode(&self) -> [u8; PTR_LEN] {
        let mut b = [0u8; PTR_LEN];
        b[0..8].copy_from_slice(&self.addr.to_le_bytes());
        b[8..16].copy_from_slice(&self.birth.to_le_bytes());
        b[16..20].copy_from_slice(&self.logical.to_le_bytes());
        b[20..24].copy_from_slice(&self.physical.to_le_bytes());
        let tipo = u32::from(self.level)
            | (self.kind as u32) << 8
            | (self.compression as u32) << 16
            | (self.integrity as u32) << 24;
        b[24..28].copy_from_slice(&tipo.to_le_bytes());
        b[28..40].copy_from_slice(&self.nonce);
        b[40..72].copy_from_slice(&self.auth);
        b
    }

    /// Lê um ponteiro de 72 bytes, recusando valores fora do domínio.
    ///
    /// # Errors
    /// [`Error::BadLen`] se `b` não tem 72 bytes; [`Error::BadField`] para
    /// tamanho, tipo, compressão ou modo inválidos; [`Error::Reserved`]
    /// se o AEAD tem os 16 bytes finais da tag diferentes de zero ou o
    /// modo hash tem `nonce` diferente de zero.
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != PTR_LEN {
            return Err(Error::BadLen);
        }
        let tipo = rd_u32(b, 24);
        let kind = match (tipo >> 8) & 0xff {
            0 => PtrKind::Node,
            1 => PtrKind::Data,
            2 => PtrKind::Bitmap,
            _ => return Err(Error::BadField),
        };
        let compression = match (tipo >> 16) & 0xff {
            0 => Compression::None,
            1 => Compression::Lz4,
            _ => return Err(Error::BadField),
        };
        let integrity = match tipo >> 24 {
            0 => Integrity::Hash,
            1 => Integrity::Aead,
            _ => return Err(Error::BadField),
        };
        let p = Self {
            addr: rd_u64(b, 0),
            birth: rd_u64(b, 8),
            logical: rd_u32(b, 16),
            physical: rd_u32(b, 20),
            level: (tipo & 0xff) as u8,
            kind,
            compression,
            integrity,
            nonce: b[28..40].try_into().map_err(|_| Error::BadLen)?,
            auth: b[40..72].try_into().map_err(|_| Error::BadLen)?,
        };
        if p.logical > MAX_EXTENT || !p.physical.is_multiple_of(4096) || p.physical > MAX_EXTENT {
            return Err(Error::BadField);
        }
        match integrity {
            Integrity::Hash if !all_zero(&p.nonce) => return Err(Error::Reserved),
            Integrity::Aead if !all_zero(&p.auth[16..]) => return Err(Error::Reserved),
            _ => {}
        }
        Ok(p)
    }
}
