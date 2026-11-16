//! `otls`: núcleo do TLS 1.3 do `tlsd` (ADR 0070; T-652).
//!
//! Aqui ficam a agenda de chaves ([`schedule`]) e a camada de registro
//! protegida ([`record`]). O handshake (T-653) usa as duas. Só TLS 1.3, só
//! as suítes `TLS_AES_256_GCM_SHA384` e `TLS_CHACHA20_POLY1305_SHA256`
//! (ADR 0070, item 3), sem PSK nem 0-RTT (item 5). Toda cripto vem do
//! `optcrypt`; nada aloca.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod record;
pub mod schedule;

/// Suíte de cifra (ADR 0070, item 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suite {
    /// `TLS_AES_256_GCM_SHA384` (0x1302).
    Aes256GcmSha384,
    /// `TLS_CHACHA20_POLY1305_SHA256` (0x1303).
    Chacha20Poly1305Sha256,
}

impl Suite {
    /// Identificador no fio.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Aes256GcmSha384 => 0x1302,
            Self::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    /// Suíte pelo identificador; `None` para as que não aceitamos.
    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Tamanho do hash da suíte.
    #[must_use]
    pub const fn hash_len(self) -> usize {
        match self {
            Self::Aes256GcmSha384 => 48,
            Self::Chacha20Poly1305Sha256 => 32,
        }
    }

    /// A suíte roda aqui? O AES-256-GCM pede AES-NI e PCLMULQDQ, que a
    /// imagem soft-float ainda não liga (ADR 0025); o ChaCha20-Poly1305
    /// roda sempre.
    #[must_use]
    pub fn available(self) -> bool {
        match self {
            Self::Chacha20Poly1305Sha256 => true,
            Self::Aes256GcmSha384 => optcrypt::aes_gcm::available(),
        }
    }
}

#[cfg(test)]
mod tests;
