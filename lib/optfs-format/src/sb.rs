//! Superbloco (ADR 0052, item 4).

use crate::{BLOCK_SIZE, BlockPtr, Error, Integrity, PTR_LEN, Sha256, all_zero, rd_u32, rd_u64};

/// `"OPTFSSB1"`.
pub const SB_MAGIC: [u8; 8] = *b"OPTFSSB1";
/// Versão do formato.
pub const SB_VERSION: u32 = 1;
/// Onde começa o SHA-256 dos bytes anteriores.
pub const SB_SHA_OFFSET: usize = BLOCK_SIZE - 64;
/// Onde começa o HMAC-SHA-256 dos bytes anteriores (inclui o SHA-256).
pub const SB_HMAC_OFFSET: usize = BLOCK_SIZE - 32;

/// Superbloco decodificado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Superblock {
    /// UUID do volume.
    pub uuid: [u8; 16],
    /// Txg deste superbloco.
    pub txg: u64,
    /// Modo de integridade do volume.
    pub integrity: Integrity,
    /// Ponteiro da raiz das raízes.
    pub root: BlockPtr,
    /// Tamanho do volume em blocos.
    pub volume_blocks: u64,
    /// Épocas de chave já usadas (ADR 0053).
    pub epochs: u32,
    /// Blocos livres.
    pub free_blocks: u64,
}

impl Superblock {
    /// Serializa em um bloco, com o SHA-256 preenchido e o HMAC zerado.
    /// Quem tem a chave de cabeçalho calcula o HMAC sobre
    /// `block[..SB_HMAC_OFFSET]` e o grava em `block[SB_HMAC_OFFSET..]`.
    #[must_use]
    pub fn encode(&self, h: &impl Sha256) -> [u8; BLOCK_SIZE] {
        let mut b = [0u8; BLOCK_SIZE];
        b[0..8].copy_from_slice(&SB_MAGIC);
        b[8..12].copy_from_slice(&SB_VERSION.to_le_bytes());
        b[16..32].copy_from_slice(&self.uuid);
        b[32..40].copy_from_slice(&self.txg.to_le_bytes());
        b[40..44].copy_from_slice(&(self.integrity as u32).to_le_bytes());
        b[48..48 + PTR_LEN].copy_from_slice(&self.root.encode());
        b[120..128].copy_from_slice(&self.volume_blocks.to_le_bytes());
        b[128..132].copy_from_slice(&self.epochs.to_le_bytes());
        b[136..144].copy_from_slice(&self.free_blocks.to_le_bytes());
        let sha = h.sha256(&b[..SB_SHA_OFFSET]);
        b[SB_SHA_OFFSET..SB_HMAC_OFFSET].copy_from_slice(&sha);
        b
    }

    /// Lê e confere um superbloco. O HMAC fica para o chamador, depois do
    /// desbloqueio (ver [`Superblock::encode`]).
    ///
    /// # Errors
    /// [`Error::BadLen`], [`Error::BadMagic`], [`Error::BadVersion`],
    /// [`Error::BadChecksum`], [`Error::Reserved`] ou [`Error::BadField`].
    pub fn decode(b: &[u8], h: &impl Sha256) -> Result<Self, Error> {
        if b.len() != BLOCK_SIZE {
            return Err(Error::BadLen);
        }
        if b[0..8] != SB_MAGIC {
            return Err(Error::BadMagic);
        }
        if rd_u32(b, 8) != SB_VERSION {
            return Err(Error::BadVersion);
        }
        if h.sha256(&b[..SB_SHA_OFFSET])[..] != b[SB_SHA_OFFSET..SB_HMAC_OFFSET] {
            return Err(Error::BadChecksum);
        }
        let reserved = rd_u32(b, 12) != 0
            || rd_u32(b, 44) != 0
            || rd_u32(b, 132) != 0
            || !all_zero(&b[144..SB_SHA_OFFSET]);
        if reserved {
            return Err(Error::Reserved);
        }
        let integrity = match rd_u32(b, 40) {
            0 => Integrity::Hash,
            1 => Integrity::Aead,
            _ => return Err(Error::BadField),
        };
        let sb = Self {
            uuid: b[16..32].try_into().map_err(|_| Error::BadLen)?,
            txg: rd_u64(b, 32),
            integrity,
            root: BlockPtr::decode(&b[48..48 + PTR_LEN])?,
            volume_blocks: rd_u64(b, 120),
            epochs: rd_u32(b, 128),
            free_blocks: rd_u64(b, 136),
        };
        if sb.volume_blocks <= crate::FIRST_ALLOC || sb.free_blocks > sb.volume_blocks {
            return Err(Error::BadField);
        }
        Ok(sb)
    }
}
