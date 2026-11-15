//! Cifra por bloco do `OptFS` (ADR 0053, item 2; T-528): nós com `K_meta` e
//! dados com `K_ds`, cada um selado por uma época. O nonce e a tag vão no
//! ponteiro (modo AEAD, ADR 0052).

use crate::io::IoError;
use alloc::vec::Vec;
use optcrypt::block::{EpochOpener, EpochSealer, SALT_LEN, Sealed};
use optcrypt::chacha20::KEY_LEN;
use optcrypt::secret::Secret;
use optfs_format::{BLOCK_SIZE, PtrKind};

/// Cifra injetada no [`crate::Tx`]: sela o bloco no lugar e devolve o nonce
/// e a tag do ponteiro; abre conferindo a tag. O AAD (UUID ‖ endereço ‖
/// nascimento ‖ dataset ‖ tipo) é montado por quem implementa.
pub trait BlockCipher {
    /// Cifra `buf` no lugar.
    ///
    /// # Errors
    /// [`IoError::Io`] se o contador da época acabou.
    fn seal(
        &mut self,
        kind: PtrKind,
        addr: u64,
        birth: u64,
        buf: &mut [u8; BLOCK_SIZE],
    ) -> Result<([u8; 12], [u8; 16]), IoError>;

    /// Confere a tag e decifra `buf` no lugar.
    ///
    /// # Errors
    /// [`IoError::Integrity`] se a tag não confere, o nonce é de uma época
    /// desconhecida ou o bloco foi movido ou trocado.
    fn open(
        &self,
        kind: PtrKind,
        addr: u64,
        birth: u64,
        nonce: &[u8; 12],
        tag: &[u8; 16],
        buf: &mut [u8; BLOCK_SIZE],
    ) -> Result<(), IoError>;
}

/// Cifra de um volume: sela na época corrente e abre em qualquer época
/// registrada (a árvore de épocas dá o sal de cada uma).
pub struct VolumeCipher {
    uuid: [u8; 16],
    dataset: u64,
    meta: Secret<KEY_LEN>,
    data: Secret<KEY_LEN>,
    meta_seal: EpochSealer,
    data_seal: EpochSealer,
    open: Vec<(u32, EpochOpener, EpochOpener)>,
}

fn aad(uuid: &[u8; 16], addr: u64, birth: u64, dataset: u64, kind: PtrKind) -> [u8; 41] {
    let mut a = [0u8; 41];
    a[..16].copy_from_slice(uuid);
    a[16..24].copy_from_slice(&addr.to_le_bytes());
    a[24..32].copy_from_slice(&birth.to_le_bytes());
    a[32..40].copy_from_slice(&dataset.to_le_bytes());
    a[40] = kind as u8;
    a
}

impl VolumeCipher {
    /// Abre a época `epoch` com o sal `salt` (de `ostd::rand::secure_fill`)
    /// sobre as chaves `meta` (`K_meta`) e `data` (`K_ds` do dataset).
    #[must_use]
    pub fn new(
        uuid: [u8; 16],
        dataset: u64,
        meta: Secret<KEY_LEN>,
        data: Secret<KEY_LEN>,
        epoch: u32,
        salt: &[u8; SALT_LEN],
    ) -> Self {
        let meta_seal = EpochSealer::new(&meta, epoch, salt);
        let data_seal = EpochSealer::new(&data, epoch, salt);
        let open = alloc::vec![(
            epoch,
            EpochOpener::new(&meta, epoch, salt),
            EpochOpener::new(&data, epoch, salt)
        )];
        Self {
            uuid,
            dataset,
            meta,
            data,
            meta_seal,
            data_seal,
            open,
        }
    }

    /// Registra uma época anterior, para ler os blocos dela.
    pub fn add_epoch(&mut self, epoch: u32, salt: &[u8; SALT_LEN]) {
        if self.open.iter().all(|(e, ..)| *e != epoch) {
            self.open.push((
                epoch,
                EpochOpener::new(&self.meta, epoch, salt),
                EpochOpener::new(&self.data, epoch, salt),
            ));
        }
    }
}

impl BlockCipher for VolumeCipher {
    fn seal(
        &mut self,
        kind: PtrKind,
        addr: u64,
        birth: u64,
        buf: &mut [u8; BLOCK_SIZE],
    ) -> Result<([u8; 12], [u8; 16]), IoError> {
        let a = aad(&self.uuid, addr, birth, self.dataset, kind);
        let sealer = if kind == PtrKind::Data {
            &mut self.data_seal
        } else {
            &mut self.meta_seal
        };
        let s = sealer.seal(&a, buf).map_err(|_| IoError::Io)?;
        Ok((s.nonce, s.tag))
    }

    fn open(
        &self,
        kind: PtrKind,
        addr: u64,
        birth: u64,
        nonce: &[u8; 12],
        tag: &[u8; 16],
        buf: &mut [u8; BLOCK_SIZE],
    ) -> Result<(), IoError> {
        let epoch = u32::from_be_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        let (_, m, d) = self
            .open
            .iter()
            .find(|(e, ..)| *e == epoch)
            .ok_or(IoError::Integrity)?;
        let o = if kind == PtrKind::Data { d } else { m };
        let a = aad(&self.uuid, addr, birth, self.dataset, kind);
        o.open(
            &Sealed {
                nonce: *nonce,
                tag: *tag,
            },
            &a,
            buf,
        )
        .map_err(|_| IoError::Integrity)
    }
}
