//! Chaveiro do volume (ADR 0053, itens 2 a 4; T-527): keyslots, derivação
//! das chaves do OptFS, MAC do cabeçalho, espera após senha errada e chave de
//! recuperação em base32. É lógica pura, sem E/S: o `keyd` lê o cabeçalho,
//! pede a senha no console e usa estas funções.
//!
//! A K_mestra só existe embrulhada em cada slot, pelo AEAD do volume com a
//! KEK do slot. O AAD (UUID ‖ índice ‖ tipo ‖ parâmetros) prende o slot ao
//! volume e à posição, então mexer nos parâmetros invalida o embrulho.

#![allow(
    clippy::doc_markdown,
    reason = "K_mestra, K_cab, K_meta e KEK são nomes da ADR 0053"
)]

use crate::aead::{self, AuthError};
use crate::argon2::{self, Block, Params};
use crate::chacha20::NONCE_LEN;
use crate::hkdf;
use crate::hmac;
use crate::poly1305::TAG_LEN;
use crate::secret::{Secret, ct_eq, wipe};

/// Bytes de uma chave.
pub const KEY_LEN: usize = 32;
/// Bytes do sal de um slot.
pub const SALT_LEN: usize = 32;
/// Bytes de um slot serializado: tipo, `m`, `t`, sal, nonce, K_mestra, tag.
pub const SLOT_LEN: usize = 1 + 4 + 4 + SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;
/// Bytes do UUID do volume.
pub const UUID_LEN: usize = 16;
/// Teto de `m` do Argon2id, em KiB (1 GiB): ADR 0053, item 3.
pub const MAX_M_KIB: u32 = 1 << 20;
/// Teto de `t` do Argon2id: ADR 0053, item 3.
pub const MAX_T: u32 = 10;
/// Tipo de slot: senha.
pub const KIND_PASSWORD: u8 = 1;
/// Tipo de slot: chave de recuperação.
pub const KIND_RECOVERY: u8 = 2;
/// Texto da chave de recuperação: 52 caracteres em 13 grupos de 4, com `-`.
pub const RECOVERY_TEXT_LEN: usize = 64;

const ALFABETO: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Erros do chaveiro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Tipo de slot desconhecido (o slot de TPM é reservado ao M10).
    BadKind,
    /// `m` ou `t` acima do teto, ou `m` abaixo do mínimo do Argon2id.
    Limits,
    /// Senha ou chave errada, ou slot adulterado: a tag não confere.
    Auth,
    /// A memória de trabalho do Argon2id é menor que a exigida.
    WorkTooSmall,
    /// Texto da chave de recuperação inválido.
    BadEncoding,
    /// O MAC do cabeçalho não confere.
    BadHeaderMac,
}

impl From<AuthError> for Error {
    fn from(_: AuthError) -> Self {
        Self::Auth
    }
}

/// Um keyslot (ADR 0053, item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    /// [`KIND_PASSWORD`] ou [`KIND_RECOVERY`].
    pub kind: u8,
    /// Memória do Argon2id em KiB (zero fora do tipo senha).
    pub m_kib: u32,
    /// Passadas do Argon2id (zero fora do tipo senha).
    pub t: u32,
    /// Sal da KEK.
    pub salt: [u8; SALT_LEN],
    /// Nonce do embrulho.
    pub nonce: [u8; NONCE_LEN],
    /// K_mestra cifrada.
    pub wrapped: [u8; KEY_LEN],
    /// Tag do embrulho.
    pub tag: [u8; TAG_LEN],
}

impl Slot {
    /// Serializa o slot (little-endian).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SLOT_LEN] {
        let mut o = [0u8; SLOT_LEN];
        o[0] = self.kind;
        o[1..5].copy_from_slice(&self.m_kib.to_le_bytes());
        o[5..9].copy_from_slice(&self.t.to_le_bytes());
        o[9..41].copy_from_slice(&self.salt);
        o[41..53].copy_from_slice(&self.nonce);
        o[53..85].copy_from_slice(&self.wrapped);
        o[85..101].copy_from_slice(&self.tag);
        o
    }

    /// Lê um slot e confere tipo e limites antes de qualquer custo.
    ///
    /// # Errors
    /// [`Error::BadKind`] ou [`Error::Limits`].
    pub fn from_bytes(b: &[u8; SLOT_LEN]) -> Result<Self, Error> {
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let mut s = Self {
            kind: b[0],
            m_kib: u32_at(1),
            t: u32_at(5),
            salt: [0; SALT_LEN],
            nonce: [0; NONCE_LEN],
            wrapped: [0; KEY_LEN],
            tag: [0; TAG_LEN],
        };
        s.salt.copy_from_slice(&b[9..41]);
        s.nonce.copy_from_slice(&b[41..53]);
        s.wrapped.copy_from_slice(&b[53..85]);
        s.tag.copy_from_slice(&b[85..101]);
        s.check()?;
        Ok(s)
    }

    /// Confere tipo e limites do slot (o `keyd` recusa o que passa do teto).
    ///
    /// # Errors
    /// [`Error::BadKind`] ou [`Error::Limits`].
    pub fn check(&self) -> Result<(), Error> {
        match self.kind {
            KIND_PASSWORD => {
                if self.m_kib > MAX_M_KIB || self.t > MAX_T || self.t == 0 || self.m_kib < 8 {
                    return Err(Error::Limits);
                }
                Ok(())
            }
            KIND_RECOVERY => Ok(()),
            _ => Err(Error::BadKind),
        }
    }

    /// Blocos de 1 KiB que a KEK por senha exige, ou zero fora desse tipo.
    #[must_use]
    pub fn work_blocks(&self) -> usize {
        if self.kind != KIND_PASSWORD {
            return 0;
        }
        Params {
            t: self.t,
            m_kib: self.m_kib,
            p: 1,
        }
        .work_blocks()
        .unwrap_or(0)
    }
}

/// AAD do embrulho: UUID ‖ índice ‖ tipo ‖ parâmetros.
fn aad(uuid: &[u8; UUID_LEN], index: u8, slot: &Slot) -> [u8; UUID_LEN + 2 + 8] {
    let mut a = [0u8; UUID_LEN + 2 + 8];
    a[..UUID_LEN].copy_from_slice(uuid);
    a[UUID_LEN] = index;
    a[UUID_LEN + 1] = slot.kind;
    a[UUID_LEN + 2..UUID_LEN + 6].copy_from_slice(&slot.m_kib.to_le_bytes());
    a[UUID_LEN + 6..].copy_from_slice(&slot.t.to_le_bytes());
    a
}

/// KEK de um slot de senha: Argon2id(senha, sal, m, t, p = 1).
///
/// # Errors
/// [`Error::BadKind`], [`Error::Limits`] ou [`Error::WorkTooSmall`].
pub fn kek_password(
    password: &[u8],
    slot: &Slot,
    work: &mut [Block],
) -> Result<Secret<KEY_LEN>, Error> {
    if slot.kind != KIND_PASSWORD {
        return Err(Error::BadKind);
    }
    slot.check()?;
    let params = Params {
        t: slot.t,
        m_kib: slot.m_kib,
        p: 1,
    };
    let mut kek = Secret::<KEY_LEN>::zeroed();
    argon2::argon2id(
        password,
        &slot.salt,
        &[],
        &[],
        params,
        work,
        kek.expose_mut(),
    )
    .map_err(|e| match e {
        argon2::Error::WorkTooSmall => Error::WorkTooSmall,
        _ => Error::Limits,
    })?;
    Ok(kek)
}

/// KEK de um slot de recuperação: HKDF(chave de recuperação, sal, `recuperação`).
#[must_use]
pub fn kek_recovery(recovery: &Secret<KEY_LEN>, salt: &[u8; SALT_LEN]) -> Secret<KEY_LEN> {
    let prk = hkdf::extract(salt, recovery.expose());
    let mut kek = Secret::<KEY_LEN>::zeroed();
    // 32 bytes cabem sempre num HKDF-Expand.
    let _ = hkdf::expand(&prk, "recuperação".as_bytes(), kek.expose_mut());
    kek
}

/// Embrulha a K_mestra com `kek` num slot novo. O chamador dá o `nonce` e o
/// `salt` aleatórios do gerador do `keyd` (ADR 0054) e nunca repete um nonce
/// para a mesma KEK.
///
/// # Errors
/// [`Error::BadKind`] ou [`Error::Limits`].
#[allow(clippy::too_many_arguments, reason = "campos do slot da ADR 0053")]
pub fn wrap(
    master: &Secret<KEY_LEN>,
    kek: &Secret<KEY_LEN>,
    uuid: &[u8; UUID_LEN],
    index: u8,
    kind: u8,
    m_kib: u32,
    t: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<Slot, Error> {
    let mut slot = Slot {
        kind,
        m_kib,
        t,
        salt,
        nonce,
        wrapped: *master.expose(),
        tag: [0; TAG_LEN],
    };
    slot.check()?;
    let a = aad(uuid, index, &slot);
    slot.tag = aead::seal(kek, &nonce, &a, &mut slot.wrapped);
    Ok(slot)
}

/// Abre o slot com `kek` e devolve a K_mestra.
///
/// # Errors
/// [`Error::Auth`] se a KEK está errada ou o slot, o UUID ou o índice mudaram.
pub fn unwrap(
    slot: &Slot,
    kek: &Secret<KEY_LEN>,
    uuid: &[u8; UUID_LEN],
    index: u8,
) -> Result<Secret<KEY_LEN>, Error> {
    slot.check()?;
    let a = aad(uuid, index, slot);
    let mut buf = slot.wrapped;
    aead::open(kek, &slot.nonce, &a, &mut buf, &slot.tag)?;
    Ok(Secret::take(&mut buf))
}

/// Chaves que o `keyd` entrega ao `optfs` (ADR 0053, item 2).
pub struct VolumeKeys {
    /// K_cab: MAC do cabeçalho e dos superblocos.
    pub cab: Secret<KEY_LEN>,
    /// K_meta: nós das árvores.
    pub meta: Secret<KEY_LEN>,
    /// K_nome: hash dos nomes de diretório.
    pub nome: Secret<KEY_LEN>,
}

fn derive(prk: &Secret<KEY_LEN>, label: &[u8], id: Option<u32>) -> Secret<KEY_LEN> {
    let mut info = [0u8; 40];
    info[..label.len()].copy_from_slice(label);
    let mut n = label.len();
    if let Some(id) = id {
        info[n..n + 4].copy_from_slice(&id.to_le_bytes());
        n += 4;
    }
    let mut k = Secret::<KEY_LEN>::zeroed();
    // 32 bytes cabem sempre num HKDF-Expand.
    let _ = hkdf::expand(prk, &info[..n], k.expose_mut());
    k
}

impl VolumeKeys {
    /// Deriva K_cab, K_meta e K_nome de `master`: PRK = HKDF-Extract(UUID,
    /// K_mestra) e HKDF-Expand com rótulos `optimus/optfs/v1/…`.
    #[must_use]
    pub fn derive(master: &Secret<KEY_LEN>, uuid: &[u8; UUID_LEN]) -> Self {
        let prk = hkdf::extract(uuid, master.expose());
        Self {
            cab: derive(&prk, b"optimus/optfs/v1/cab", None),
            meta: derive(&prk, b"optimus/optfs/v1/meta", None),
            nome: derive(&prk, b"optimus/optfs/v1/nome", None),
        }
    }
}

/// K_ds(id): chave dos dados de um dataset.
#[must_use]
pub fn dataset_key(master: &Secret<KEY_LEN>, uuid: &[u8; UUID_LEN], id: u32) -> Secret<KEY_LEN> {
    let prk = hkdf::extract(uuid, master.expose());
    derive(&prk, b"optimus/optfs/v1/ds", Some(id))
}

/// HMAC-SHA-256 com K_cab sobre o cabeçalho (sem o campo do MAC).
#[must_use]
pub fn header_mac(cab: &Secret<KEY_LEN>, header: &[u8]) -> [u8; 32] {
    hmac::hmac_sha256(cab.expose(), header)
}

/// Confere o MAC do cabeçalho em tempo constante.
///
/// # Errors
/// [`Error::BadHeaderMac`] se não confere: o volume não monta.
pub fn header_verify(cab: &Secret<KEY_LEN>, header: &[u8], mac: &[u8; 32]) -> Result<(), Error> {
    if hmac::verify(cab.expose(), header, mac) {
        Ok(())
    } else {
        Err(Error::BadHeaderMac)
    }
}

/// Espera, em segundos, antes da próxima tentativa depois de `failures`
/// senhas erradas seguidas: 0, 1, 2, 4, … até 60 (ADR 0053, item 4).
#[must_use]
pub const fn retry_delay_secs(failures: u32) -> u32 {
    if failures == 0 {
        0
    } else if failures > 6 {
        60
    } else {
        let d = 1u32 << (failures - 1);
        if d > 60 { 60 } else { d }
    }
}

/// Chave de recuperação em base32, 52 caracteres em grupos de 4 separados
/// por `-`. O texto é segredo: quem chama zera o resultado.
#[must_use]
pub fn recovery_encode(key: &Secret<KEY_LEN>) -> Secret<RECOVERY_TEXT_LEN> {
    let mut out = Secret::<RECOVERY_TEXT_LEN>::zeroed();
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    let o = out.expose_mut();
    let mut put = |c: u8, n: &mut usize| {
        if *n % 5 == 4 {
            o[*n] = b'-';
            *n += 1;
        }
        o[*n] = c;
        *n += 1;
    };
    for &b in key.expose() {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            put(ALFABETO[((acc >> bits) & 31) as usize], &mut n);
        }
    }
    if bits > 0 {
        put(ALFABETO[((acc << (5 - bits)) & 31) as usize], &mut n);
    }
    wipe_u32(&mut acc);
    out
}

fn wipe_u32(v: &mut u32) {
    let mut b = v.to_le_bytes();
    wipe(&mut b);
    *v = 0;
}

/// Lê a chave de recuperação digitada: ignora `-` e espaços, aceita
/// minúsculas e recusa tamanho errado, símbolo fora do alfabeto e bits
/// finais não nulos.
///
/// # Errors
/// [`Error::BadEncoding`].
pub fn recovery_decode(text: &[u8]) -> Result<Secret<KEY_LEN>, Error> {
    let mut key = Secret::<KEY_LEN>::zeroed();
    let (mut acc, mut bits, mut chars, mut out) = (0u32, 0u32, 0usize, 0usize);
    for &c in text {
        if c == b'-' || c == b' ' {
            continue;
        }
        let c = c.to_ascii_uppercase();
        let v = ALFABETO
            .iter()
            .position(|&a| a == c)
            .and_then(|i| u32::try_from(i).ok())
            .ok_or(Error::BadEncoding)?;
        chars += 1;
        if chars > 52 {
            return Err(Error::BadEncoding);
        }
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out >= KEY_LEN {
                return Err(Error::BadEncoding);
            }
            key.expose_mut()[out] = ((acc >> bits) & 0xff) as u8;
            out += 1;
        }
    }
    let sobra = acc & ((1 << bits) - 1);
    wipe_u32(&mut acc);
    if chars != 52 || out != KEY_LEN || sobra != 0 {
        return Err(Error::BadEncoding);
    }
    Ok(key)
}

/// Compara duas chaves de recuperação em tempo constante (conferência da
/// digitação pedida na criação do volume).
#[must_use]
pub fn recovery_eq(a: &Secret<KEY_LEN>, b: &Secret<KEY_LEN>) -> bool {
    ct_eq(a.expose(), b.expose())
}

#[cfg(test)]
mod tests;
