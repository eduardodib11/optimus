//! API de bloco com época (ADR 0053, item 2; P7). O chamador nunca escolhe
//! o nonce: ele é `época (u32) ‖ contador (u64)`, e o contador sai do
//! [`EpochSealer`]. A chave de época é `HKDF-Expand(K_x, "época" ‖ e ‖ s)`,
//! com `s` aleatório de 32 bytes, então épocas diferentes nunca compartilham
//! chave mesmo que o número `e` se repita após uma queda.

use crate::aead::{self, AuthError};
#[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
use crate::aes_gcm::AesGcm;
use crate::chacha20::{KEY_LEN, NONCE_LEN};
use crate::hkdf;
use crate::poly1305::TAG_LEN;
use crate::secret::Secret;

/// Bytes do sal de época.
pub const SALT_LEN: usize = 32;

/// Nonce e tag de um bloco selado; vão no ponteiro do bloco (ADR 0052).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed {
    /// `época ‖ contador`.
    pub nonce: [u8; NONCE_LEN],
    /// Tag de autenticação.
    pub tag: [u8; TAG_LEN],
}

/// AEAD do volume, escolhido na criação e gravado no cabeçalho (ADR 0053).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    /// ChaCha20-Poly1305: roda em qualquer CPU.
    ChaCha20Poly1305,
    /// AES-256-GCM: exige AES-NI e PCLMULQDQ.
    Aes256Gcm,
}

#[allow(
    clippy::large_enum_variant,
    reason = "sem alloc na imagem; a chave AES expandida mora na pilha"
)]
enum Cipher {
    ChaCha(Secret<KEY_LEN>),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    Aes(AesGcm),
}

impl Cipher {
    fn new(algo: Algo, key: Secret<KEY_LEN>) -> Result<Self, Error> {
        match algo {
            Algo::ChaCha20Poly1305 => Ok(Self::ChaCha(key)),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Algo::Aes256Gcm => AesGcm::new(&key).map(Self::Aes).ok_or(Error::Unsupported),
            #[cfg(not(all(target_arch = "x86_64", target_feature = "sse2")))]
            Algo::Aes256Gcm => Err(Error::Unsupported),
        }
    }

    fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> [u8; TAG_LEN] {
        match self {
            Self::ChaCha(k) => aead::seal(k, nonce, aad, buf),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Aes(g) => g.seal(nonce, aad, buf),
        }
    }

    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), AuthError> {
        match self {
            Self::ChaCha(k) => aead::open(k, nonce, aad, buf, tag),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Self::Aes(g) => g.open(nonce, aad, buf, tag),
        }
    }
}

/// Erros da API de bloco.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// O contador da época chegou ao fim; é preciso abrir outra época.
    EpochExhausted,
    /// O nonce é de outra época.
    WrongEpoch,
    /// A tag não confere.
    Auth,
    /// A CPU não tem o que o algoritmo pede (AES-NI e PCLMULQDQ).
    Unsupported,
}

impl From<AuthError> for Error {
    fn from(_: AuthError) -> Self {
        Self::Auth
    }
}

const LABEL: &[u8] = "época".as_bytes();

fn epoch_key(base: &Secret<KEY_LEN>, epoch: u32, salt: &[u8; SALT_LEN]) -> Secret<KEY_LEN> {
    let mut info = [0u8; 6 + 4 + SALT_LEN];
    const { assert!(LABEL.len() == 6) };
    info[..6].copy_from_slice(LABEL);
    info[6..10].copy_from_slice(&epoch.to_be_bytes());
    info[10..].copy_from_slice(salt);
    // 32 bytes está sempre dentro do limite do HKDF.
    hkdf::expand_secret::<KEY_LEN>(base, &info).unwrap_or_else(|_| Secret::zeroed())
}

fn nonce(epoch: u32, counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..4].copy_from_slice(&epoch.to_be_bytes());
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// Sela blocos de uma época. Dono do contador: cada chamada usa um valor
/// novo, e não há como o chamador escolher o nonce (P7).
pub struct EpochSealer {
    key: Cipher,
    epoch: u32,
    next: u64,
}

impl EpochSealer {
    /// Abre a época `epoch` com o sal `salt` (de `ostd::rand::secure_fill`)
    /// sobre a chave `base` (`K_meta`, `K_ds`…).
    #[must_use]
    pub fn new(base: &Secret<KEY_LEN>, epoch: u32, salt: &[u8; SALT_LEN]) -> Self {
        Self {
            key: Cipher::ChaCha(epoch_key(base, epoch, salt)),
            epoch,
            next: 0,
        }
    }

    /// Como [`EpochSealer::new`], com o algoritmo do volume.
    ///
    /// # Errors
    /// [`Error::Unsupported`] se pede AES-256-GCM numa CPU sem AES-NI.
    pub fn with_algo(
        algo: Algo,
        base: &Secret<KEY_LEN>,
        epoch: u32,
        salt: &[u8; SALT_LEN],
    ) -> Result<Self, Error> {
        Ok(Self {
            key: Cipher::new(algo, epoch_key(base, epoch, salt))?,
            epoch,
            next: 0,
        })
    }

    /// Cifra `buf` no lugar. `aad` é UUID ‖ endereço ‖ nascimento ‖ dataset
    /// ‖ tipo (ADR 0053, item 2).
    ///
    /// # Errors
    /// [`Error::EpochExhausted`] quando o contador acaba.
    pub fn seal(&mut self, aad: &[u8], buf: &mut [u8]) -> Result<Sealed, Error> {
        let counter = self.next;
        self.next = counter.checked_add(1).ok_or(Error::EpochExhausted)?;
        let n = nonce(self.epoch, counter);
        let tag = self.key.seal(&n, aad, buf);
        Ok(Sealed { nonce: n, tag })
    }
}

/// Abre blocos de uma época.
pub struct EpochOpener {
    key: Cipher,
    epoch: u32,
}

impl EpochOpener {
    /// Mesma derivação do [`EpochSealer::new`].
    #[must_use]
    pub fn new(base: &Secret<KEY_LEN>, epoch: u32, salt: &[u8; SALT_LEN]) -> Self {
        Self {
            key: Cipher::ChaCha(epoch_key(base, epoch, salt)),
            epoch,
        }
    }

    /// Como [`EpochOpener::new`], com o algoritmo do volume.
    ///
    /// # Errors
    /// [`Error::Unsupported`] se pede AES-256-GCM numa CPU sem AES-NI.
    pub fn with_algo(
        algo: Algo,
        base: &Secret<KEY_LEN>,
        epoch: u32,
        salt: &[u8; SALT_LEN],
    ) -> Result<Self, Error> {
        Ok(Self {
            key: Cipher::new(algo, epoch_key(base, epoch, salt))?,
            epoch,
        })
    }

    /// Confere e decifra `buf` no lugar; com tag errada `buf` fica zerado.
    ///
    /// # Errors
    /// [`Error::WrongEpoch`] se o nonce é de outra época; [`Error::Auth`] se
    /// a tag não confere.
    pub fn open(&self, sealed: &Sealed, aad: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        if sealed.nonce[..4] != self.epoch.to_be_bytes() {
            return Err(Error::WrongEpoch);
        }
        self.key.open(&sealed.nonce, aad, buf, &sealed.tag)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
