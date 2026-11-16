//! Camada de registro protegida do TLS 1.3 (RFC 8446, seção 5).
//!
//! O registro cifrado é `cabeçalho (5) ‖ AEAD(conteúdo ‖ tipo ‖ zeros)`,
//! com o cabeçalho como dado associado e o nonce `iv XOR seq`. Tudo é feito
//! no lugar, no buffer de quem chama, sem alocar. Falha de autenticação
//! vira um único erro ([`RecordError::BadRecordMac`]), sem detalhe (ADR
//! 0070, item 11).

use optcrypt::aead;
use optcrypt::poly1305::TAG_LEN;
use optcrypt::secret::{Secret, wipe};

use crate::Suite;

/// Tamanho do cabeçalho do registro.
pub const HEADER_LEN: usize = 5;
/// Maior texto claro de um registro (2^14).
pub const MAX_PLAINTEXT: usize = 1 << 14;
/// Maior conteúdo cifrado aceito (2^14 + 256, seção 5.2).
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
/// Maior registro inteiro, para dimensionar buffers.
pub const MAX_RECORD: usize = HEADER_LEN + MAX_CIPHERTEXT;

/// Tipos de conteúdo (seção 5.1).
pub mod content {
    /// `change_cipher_spec` (só o de compatibilidade, ignorado).
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    /// `alert`.
    pub const ALERT: u8 = 21;
    /// `handshake`.
    pub const HANDSHAKE: u8 = 22;
    /// `application_data` (também o tipo externo de todo registro cifrado).
    pub const APPLICATION_DATA: u8 = 23;
}

/// Erro da camada de registro, já com o alerta que ele pede.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Registro grande demais (`record_overflow`).
    Overflow,
    /// Tipo ou tamanho inválido (`unexpected_message` / `decode_error`).
    Malformed,
    /// Autenticação falhou (`bad_record_mac`).
    BadRecordMac,
    /// O número de sequência acabou: é preciso `KeyUpdate`.
    SequenceExhausted,
    /// Buffer pequeno demais para o registro.
    BufferTooSmall,
}

/// Cabeçalho lido: tipo externo e tamanho do conteúdo.
///
/// # Errors
///
/// `Malformed` para tipo desconhecido; `Overflow` acima de
/// [`MAX_CIPHERTEXT`]. A versão legada é ignorada (seção 5.1).
pub fn parse_header(h: &[u8; HEADER_LEN]) -> Result<(u8, usize), RecordError> {
    let len = usize::from(u16::from_be_bytes([h[3], h[4]]));
    if !(content::CHANGE_CIPHER_SPEC..=content::APPLICATION_DATA).contains(&h[0]) {
        return Err(RecordError::Malformed);
    }
    if len > MAX_CIPHERTEXT {
        return Err(RecordError::Overflow);
    }
    Ok((h[0], len))
}

// Sem alocação não há `Box`: o AES expandido vai por valor, um por sentido.
#[allow(clippy::large_enum_variant)]
enum Cipher {
    Chacha(Secret<32>),
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    Aes(optcrypt::aes_gcm::AesGcm),
}

/// Chaves de um sentido, com o número de sequência.
pub struct RecordKeys {
    cipher: Cipher,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKeys {
    /// Chaves de `suite`; zera `key`. `None` se a suíte não estiver
    /// disponível nesta CPU ou imagem ([`Suite::available`]).
    #[must_use]
    pub fn new(suite: Suite, key: &mut [u8; 32], iv: [u8; 12]) -> Option<Self> {
        let key = Secret::take(key);
        let cipher = match suite {
            Suite::Chacha20Poly1305Sha256 => Cipher::Chacha(key),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Suite::Aes256GcmSha384 => Cipher::Aes(optcrypt::aes_gcm::AesGcm::new(&key)?),
            #[cfg(not(all(target_arch = "x86_64", target_feature = "sse2")))]
            Suite::Aes256GcmSha384 => return None,
        };
        Some(Self { cipher, iv, seq: 0 })
    }

    fn nonce(&mut self) -> Result<[u8; 12], RecordError> {
        let seq = self.seq;
        self.seq = seq.checked_add(1).ok_or(RecordError::SequenceExhausted)?;
        let mut n = self.iv;
        for (b, s) in n[4..].iter_mut().zip(seq.to_be_bytes()) {
            *b ^= s;
        }
        Ok(n)
    }

    /// Protege um registro. `buf[HEADER_LEN..HEADER_LEN + len]` tem o texto
    /// claro; o resto de `buf` precisa caber tipo e tag. Grava o cabeçalho e
    /// devolve o tamanho do registro.
    ///
    /// # Errors
    ///
    /// `Overflow` acima de [`MAX_PLAINTEXT`], `BufferTooSmall` sem espaço,
    /// `SequenceExhausted` sem número de sequência.
    pub fn seal(
        &mut self,
        content_type: u8,
        buf: &mut [u8],
        len: usize,
    ) -> Result<usize, RecordError> {
        if len > MAX_PLAINTEXT {
            return Err(RecordError::Overflow);
        }
        let inner = len + 1;
        let total = HEADER_LEN + inner + TAG_LEN;
        if buf.len() < total {
            return Err(RecordError::BufferTooSmall);
        }
        let nonce = self.nonce()?;
        let (header, body) = buf.split_at_mut(HEADER_LEN);
        let ct_len = u16::try_from(inner + TAG_LEN).map_err(|_| RecordError::Overflow)?;
        header[0] = content::APPLICATION_DATA;
        header[1..3].copy_from_slice(&[0x03, 0x03]);
        header[3..5].copy_from_slice(&ct_len.to_be_bytes());
        body[len] = content_type;
        let (data, rest) = body.split_at_mut(inner);
        let tag = match &self.cipher {
            Cipher::Chacha(k) => aead::seal(k, &nonce, header, data),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Cipher::Aes(a) => a.seal(&nonce, header, data),
        };
        rest[..TAG_LEN].copy_from_slice(&tag);
        Ok(total)
    }

    /// Abre um registro inteiro (cabeçalho e conteúdo) no lugar. Devolve o
    /// tipo interno e o texto claro, que fica em `record[HEADER_LEN..]`.
    ///
    /// # Errors
    ///
    /// `Malformed` se o tipo externo não for `application_data`, o tamanho
    /// não bater ou o texto interno não tiver tipo; `BadRecordMac` se a
    /// autenticação falhar (o conteúdo fica zerado).
    pub fn open<'b>(&mut self, record: &'b mut [u8]) -> Result<(u8, &'b [u8]), RecordError> {
        let Some((header, body)) = record.split_first_chunk_mut::<HEADER_LEN>() else {
            return Err(RecordError::Malformed);
        };
        let (outer, len) = parse_header(header)?;
        if outer != content::APPLICATION_DATA || len != body.len() || len < TAG_LEN + 1 {
            return Err(RecordError::Malformed);
        }
        let nonce = self.nonce()?;
        let (data, tag) = body.split_at_mut(len - TAG_LEN);
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(tag);
        let ok = match &self.cipher {
            Cipher::Chacha(k) => aead::open(k, &nonce, header, data, &t),
            #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
            Cipher::Aes(a) => a.open(&nonce, header, data, &t),
        };
        if ok.is_err() {
            wipe(tag);
            return Err(RecordError::BadRecordMac);
        }
        // Tira o enchimento de zeros; o último byte não nulo é o tipo.
        let Some(end) = data.iter().rposition(|&b| b != 0) else {
            return Err(RecordError::Malformed);
        };
        let kind = data[end];
        if end > MAX_PLAINTEXT {
            return Err(RecordError::Overflow);
        }
        Ok((kind, &data[..end]))
    }

    /// Registros já usados nesta chave.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.seq
    }

    #[cfg(test)]
    pub(crate) fn set_sequence(&mut self, seq: u64) {
        self.seq = seq;
    }
}
