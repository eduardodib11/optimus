//! `otls`: núcleo do TLS 1.3 do `tlsd` (ADR 0070; T-652).
//!
//! Aqui ficam a agenda de chaves ([`schedule`]), a camada de registro
//! protegida ([`record`]), as mensagens de handshake ([`msg`]) e o cliente
//! sem E/S ([`client`], T-653) e o verificador de assinaturas do `optcrypt`
//! ([`verifier`], T-651). Só TLS 1.3, só
//! as suítes `TLS_AES_256_GCM_SHA384` e `TLS_CHACHA20_POLY1305_SHA256`
//! (ADR 0070, item 3), sem PSK nem 0-RTT (item 5). Toda cripto vem do
//! `optcrypt`. Só o buffer de remontagem do cliente e os da [`session`]
//! usam a heap.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod client;
pub mod msg;
pub mod record;
pub mod schedule;
pub mod session;
pub mod verifier;

use ox509::ocsp::OcspError;
use ox509::verify::VerifyError;
use record::RecordError;

/// Erro de uma conexão. Todo erro é fatal; [`Error::alert`] diz o alerta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Mensagem mal formada (`decode_error`).
    Decode,
    /// Mensagem fora de ordem ou de tipo errado (`unexpected_message`).
    UnexpectedMessage,
    /// Valor inválido (`illegal_parameter`).
    IllegalParameter,
    /// Extensão que o cliente não ofereceu (`unsupported_extension`).
    UnsupportedExtension,
    /// Extensão obrigatória ausente (`missing_extension`).
    MissingExtension,
    /// Sem grupo ou suíte em comum (`handshake_failure`).
    HandshakeFailure,
    /// O servidor só fala TLS 1.2 ou anterior (`protocol_version`; ADR 0017).
    Tls12Only,
    /// Registro que não autentica (`bad_record_mac`).
    BadRecordMac,
    /// Registro grande demais (`record_overflow`).
    RecordOverflow,
    /// `Finished` ou `CertificateVerify` inválido (`decrypt_error`).
    DecryptError,
    /// Certificado ilegível ou chave fixada diferente (`bad_certificate`).
    BadCertificate,
    /// Chave fora da ADR 0071 (`unsupported_certificate`).
    UnsupportedCertificate,
    /// Cadeia recusada pela validação.
    Certificate(VerifyError),
    /// O emissor revogou o certificado (OCSP grampeado, T-655).
    Revoked,
    /// Resposta OCSP inválida e a política (ou o `must-staple`) exigia uma
    /// boa.
    Ocsp(OcspError),
    /// Certificado `must-staple` (ou política `Require`) sem resposta OCSP.
    StapleRequired,
    /// Mensagem de handshake maior que o buffer.
    TooLarge,
    /// Falha interna (`internal_error`).
    Internal,
    /// O servidor mandou um alerta fatal.
    PeerAlert(u8),
}

impl Error {
    /// Descrição do alerta a mandar; `None` se o erro veio do par.
    #[must_use]
    pub const fn alert(self) -> Option<u8> {
        Some(match self {
            Self::Decode => 50,
            Self::UnexpectedMessage => 10,
            Self::IllegalParameter => 47,
            Self::UnsupportedExtension => 110,
            Self::MissingExtension => 109,
            Self::HandshakeFailure => 40,
            Self::Tls12Only => 70,
            Self::BadRecordMac => 20,
            Self::RecordOverflow | Self::TooLarge => 22,
            Self::DecryptError => 51,
            Self::UnsupportedCertificate | Self::Certificate(VerifyError::UnsupportedSignature) => {
                43
            }
            Self::Certificate(VerifyError::Expired | VerifyError::NotYetValid) => 45,
            Self::Certificate(VerifyError::UnknownIssuer) => 48,
            Self::Revoked => 44,
            Self::Ocsp(_) => 113,
            Self::BadCertificate | Self::StapleRequired | Self::Certificate(_) => 42,
            Self::Internal => 80,
            Self::PeerAlert(_) => return None,
        })
    }
}

impl From<RecordError> for Error {
    fn from(e: RecordError) -> Self {
        match e {
            RecordError::Overflow => Self::RecordOverflow,
            RecordError::Malformed => Self::UnexpectedMessage,
            RecordError::BadRecordMac => Self::BadRecordMac,
            RecordError::SequenceExhausted | RecordError::BufferTooSmall => Self::Internal,
        }
    }
}

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
mod client_tests;
#[cfg(test)]
mod msg_tests;
#[cfg(test)]
mod tests;
