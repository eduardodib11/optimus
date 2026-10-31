//! Anel SPSC em `MemoryObject` compartilhado (T-339; ADR 0036, item 1): um
//! [`Producer`] e um [`Consumer`], em processos (ou espaços) distintos, sem
//! alocação no caminho de dados. O consumidor cria o anel ([`Consumer::create`])
//! e dá ao produtor o objeto e uma capability `SIGNAL` da sua `Notification`;
//! o produtor o abre com [`Producer::open`].
//!
//! Layout (ADR 0036): página 0 é o cabeçalho (`magic`, `version`, `kind`,
//! `data_len`, `flags`; `tail`, `dropped` e `shed` do produtor a partir do
//! byte 64; `head` e `waiting` do consumidor a partir do 128); as páginas
//! seguintes são os dados (`data_len` bytes, potência de 2). Cada registro é
//! `len: u32`, `kind: u16`, `flags: u16` e a carga útil, arredondado a 8
//! bytes, e **nunca atravessa** o fim do vetor: o que sobra vira um registro
//! de enchimento (`kind` 0), que o consumidor pula.
//!
//! **Cheio:** a política única da v1 é "descartar novos": [`Producer::push`]
//! sem espaço incrementa `dropped` e devolve [`PushError::Full`].
//!
//! **Despertar:** o produtor publica `tail` (`Release`), faz um fence
//! `SeqCst` e, se `waiting == 1`, sinaliza a `Notification`. O consumidor
//! que vai dormir faz `waiting = 1`, fence `SeqCst` e relê `tail`: o par de
//! fences (Dekker) impede o despertar perdido ([`Consumer::wait`]).
//!
//! **Desconfiança:** cada lado trata os campos do outro como não
//! confiáveis. `tail` ou `head` fora de `[0, data_len]` de folga, e
//! registro com tamanho impossível, tornam o anel inválido
//! ([`PushError::Corrupt`], [`PopError::Corrupt`]); nada disso afeta o
//! kernel nem outro anel.
//!
//! # Unsafe
//!
//! Só o acesso à memória compartilhada: os campos do cabeçalho como
//! atômicos e a cópia da carga útil de e para o vetor de dados, tudo atrás
//! de [`Producer`] e [`Consumer`] (nenhuma API exporta ponteiros). O teto
//! está em `unsafe-allowlist.toml`.

#![allow(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    reason = "x86-64: `usize` tem 64 bits"
)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

use kabi::vm::{PAGE_SIZE, WRITE};
use kabi::{Error, Handle};

use crate::cap::{ntfy_signal, ntfy_wait};
use crate::vm::Mapping;

/// `"ORNG"`, little-endian.
const MAGIC: u32 = u32::from_le_bytes(*b"ORNG");
const VERSION: u16 = 1;
/// Bytes do cabeçalho (a página 0).
const HEADER_BYTES: u64 = PAGE_SIZE;
/// Maior `data_len`.
pub const MAX_DATA_LEN: u32 = 16 << 20;
/// Maior carga útil de um registro (a ADR 0036 diz 4096 − 8).
pub const MAX_PAYLOAD: usize = 4096 - RECORD_HEAD;
/// Registro de enchimento (não chega ao consumidor).
const KIND_PAD: u16 = 0;
const RECORD_HEAD: usize = 8;

// Posições no cabeçalho.
const OFF_MAGIC: usize = 0;
const OFF_VERSION_KIND: usize = 4;
const OFF_DATA_LEN: usize = 8;
const OFF_FLAGS: usize = 12;
const OFF_TAIL: usize = 64;
const OFF_DROPPED: usize = 72;
const OFF_HEAD: usize = 128;
const OFF_WAITING: usize = 136;

/// Bytes do `MemoryObject` de um anel de `data_len` bytes de dados.
#[must_use]
pub const fn object_bytes(data_len: u32) -> u64 {
    HEADER_BYTES + data_len as u64
}

/// `data_len` aceito: potência de 2, múltiplo de uma página, até 16 MiB.
const fn valid_data_len(n: u32) -> bool {
    n.is_power_of_two() && n as u64 >= PAGE_SIZE && n <= MAX_DATA_LEN
}

/// Tamanho do registro com `len` bytes de carga útil.
const fn record_size(len: usize) -> u64 {
    (RECORD_HEAD + len).next_multiple_of(8) as u64
}

/// Por que um `push` não gravou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushError {
    /// Sem espaço: o registro foi descartado e contado em `dropped`.
    Full,
    /// Carga útil maior que [`MAX_PAYLOAD`], ou `kind` 0 (reservado).
    Invalid,
    /// O consumidor corrompeu `head`: o anel não serve mais.
    Corrupt,
    /// A sinalização do consumidor falhou (o registro foi gravado).
    Signal(Error),
}

/// Por que um `pop` não devolveu um registro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PopError {
    /// O buffer é menor que a carga útil (o registro continua no anel).
    BufferTooSmall(usize),
    /// O produtor corrompeu `tail` ou um registro: o anel foi esvaziado e
    /// não serve mais.
    Corrupt,
}

/// Mapeamento do anel e acesso ao cabeçalho e aos dados. Guarda o endereço
/// como inteiro: o ponteiro sai de [`Mapping::addr`] a cada uso.
#[derive(Debug)]
struct Shared {
    map: Mapping,
    data_len: u64,
}

impl Shared {
    fn base(&self) -> usize {
        self.map.addr()
    }

    fn u64_at(&self, off: usize) -> &AtomicU64 {
        let ptr = core::ptr::with_exposed_provenance::<AtomicU64>(self.base() + off);
        // SAFETY: `off` é uma das posições alinhadas a 8 dentro da página 0,
        // que `map` cobre (conferido em `new`) até desmapear no `Drop`, depois
        // de todo empréstimo; `AtomicU64` aceita qualquer padrão de bits e a
        // concorrência com o par é o que o tipo atômico existe para tratar.
        unsafe { &*ptr }
    }

    fn u32_at(&self, off: usize) -> &AtomicU32 {
        let ptr = core::ptr::with_exposed_provenance::<AtomicU32>(self.base() + off);
        // SAFETY: como em `u64_at`, com posições alinhadas a 4.
        unsafe { &*ptr }
    }

    /// Cópia de `src` para os dados em `pos` (já reduzida a `data_len`).
    fn write(&self, pos: u64, src: &[u8]) {
        debug_assert!(pos + src.len() as u64 <= self.data_len);
        let dst = core::ptr::with_exposed_provenance_mut::<u8>(
            self.base() + HEADER_BYTES as usize + pos as usize,
        );
        // SAFETY: a faixa `[pos, pos + len)` está dentro dos dados que `map`
        // cobre e, pelo protocolo, é espaço livre do produtor: o consumidor só
        // lê abaixo de `tail`, que ainda não foi publicado. `src` é um
        // empréstimo do chamador, sem sobreposição com o mapeamento.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) }
    }

    /// Cópia dos dados em `pos` para `dst`.
    fn read(&self, pos: u64, dst: &mut [u8]) {
        debug_assert!(pos + dst.len() as u64 <= self.data_len);
        let src = core::ptr::with_exposed_provenance::<u8>(
            self.base() + HEADER_BYTES as usize + pos as usize,
        );
        // SAFETY: a faixa está dentro dos dados mapeados e abaixo de `tail`
        // (lido com `Acquire`), que o produtor não reescreve até `head`
        // passar dela; `dst` é um empréstimo exclusivo do chamador.
        unsafe { core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), dst.len()) }
    }

    fn pos(&self, counter: u64) -> u64 {
        counter & (self.data_len - 1)
    }
}

fn map(object: Handle, va: u64, data_len: u32, flags: u64) -> Result<Mapping, Error> {
    if !valid_data_len(data_len) {
        return Err(Error::InvalidArgument);
    }
    Mapping::new(
        crate::vm::SELF,
        object,
        va,
        object_bytes(data_len),
        flags | WRITE,
    )
}

/// Lado do consumidor.
#[derive(Debug)]
pub struct Consumer {
    shared: Shared,
    ntfy: Handle,
    head: u64,
    tail: u64,
    corrupt: bool,
}

impl Consumer {
    /// Cria o anel em `object` (um `MemoryObject` novo de
    /// [`object_bytes`]`(data_len)` bytes, zerado) mapeando-o em `va` do
    /// espaço do próprio processo. `ntfy` é a `Notification` (com `WAIT`)
    /// em que [`wait`](Self::wait) dorme.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` para `data_len` inválido; os de `vm_map`.
    pub fn create(
        object: Handle,
        va: u64,
        data_len: u32,
        kind: u16,
        ntfy: Handle,
    ) -> Result<Self, Error> {
        let shared = Shared {
            map: map(object, va, data_len, 0)?,
            data_len: u64::from(data_len),
        };
        shared.u32_at(OFF_MAGIC).store(MAGIC, Ordering::Relaxed);
        let vk = u32::from(VERSION) | u32::from(kind) << 16;
        shared.u32_at(OFF_VERSION_KIND).store(vk, Ordering::Relaxed);
        shared
            .u32_at(OFF_DATA_LEN)
            .store(data_len, Ordering::Relaxed);
        shared.u32_at(OFF_FLAGS).store(1, Ordering::Release);
        Ok(Self {
            shared,
            ntfy,
            head: 0,
            tail: 0,
            corrupt: false,
        })
    }

    /// Tira o próximo registro: copia a carga útil para o início de `buf` e
    /// devolve `(kind, bytes)`; `None` se o anel está vazio.
    ///
    /// # Errors
    ///
    /// [`PopError::BufferTooSmall`] ou [`PopError::Corrupt`].
    pub fn pop(&mut self, buf: &mut [u8]) -> Result<Option<(u16, usize)>, PopError> {
        if self.corrupt {
            return Err(PopError::Corrupt);
        }
        loop {
            if self.head == self.tail {
                self.tail = self.shared.u64_at(OFF_TAIL).load(Ordering::Acquire);
                if self.tail.wrapping_sub(self.head) > self.shared.data_len {
                    return Err(self.poison());
                }
                if self.head == self.tail {
                    return Ok(None);
                }
            }
            let avail = self.tail - self.head;
            let pos = self.shared.pos(self.head);
            let mut head = [0u8; RECORD_HEAD];
            // Um registro começa alinhado a 8 e o vetor é múltiplo de 8:
            // sempre cabem os 8 bytes do cabeçalho do registro.
            if avail < RECORD_HEAD as u64 {
                return Err(self.poison());
            }
            self.shared.read(pos, &mut head);
            let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
            let kind = u16::from_le_bytes([head[4], head[5]]);
            let size = record_size(len);
            let pad = kind == KIND_PAD;
            if len > MAX_PAYLOAD && !pad || size > avail || pos + size > self.shared.data_len {
                return Err(self.poison());
            }
            if !pad {
                if len > buf.len() {
                    return Err(PopError::BufferTooSmall(len));
                }
                self.shared.read(pos + RECORD_HEAD as u64, &mut buf[..len]);
            }
            self.head += size;
            self.shared
                .u64_at(OFF_HEAD)
                .store(self.head, Ordering::Release);
            if !pad {
                return Ok(Some((kind, len)));
            }
        }
    }

    /// Descarta tudo até o último `tail` lido e marca o anel como inválido.
    fn poison(&mut self) -> PopError {
        self.corrupt = true;
        self.head = self.tail;
        self.shared
            .u64_at(OFF_HEAD)
            .store(self.head, Ordering::Release);
        PopError::Corrupt
    }

    /// Dorme até o produtor gravar algo; volta na hora (com 0) se já há
    /// registro. Devolve os bits que a `Notification` trazia, de onde o
    /// chamador tira outros eventos ligados a ela (como a morte do
    /// produtor). Pode voltar sem registro (bits velhos): o chamador tenta
    /// [`pop`](Self::pop) de novo.
    ///
    /// # Errors
    ///
    /// Os de `ntfy_wait`.
    pub fn wait(&mut self) -> Result<u64, Error> {
        let waiting = self.shared.u32_at(OFF_WAITING);
        waiting.store(1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        let tail = self.shared.u64_at(OFF_TAIL).load(Ordering::Acquire);
        let result = if tail == self.head {
            ntfy_wait(self.ntfy)
        } else {
            Ok(0)
        };
        waiting.store(0, Ordering::Relaxed);
        result
    }

    /// Registros que o produtor descartou por falta de espaço.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.u64_at(OFF_DROPPED).load(Ordering::Relaxed)
    }
}

/// Lado do produtor.
#[derive(Debug)]
pub struct Producer {
    shared: Shared,
    ntfy: Handle,
    bits: u64,
    tail: u64,
    head: u64,
}

impl Producer {
    /// Abre o anel de `object` (mapeando-o em `va` do próprio espaço).
    /// `ntfy` é a capability `SIGNAL` da `Notification` do consumidor e
    /// `bits` o que sinalizar (use o bit deste anel).
    ///
    /// # Errors
    ///
    /// `InvalidArgument` se o cabeçalho não for um anel v1 consistente com
    /// o tamanho de `data_len`; os de `vm_map`.
    pub fn open(
        object: Handle,
        va: u64,
        data_len: u32,
        ntfy: Handle,
        bits: u64,
    ) -> Result<Self, Error> {
        let shared = Shared {
            map: map(object, va, data_len, 0)?,
            data_len: u64::from(data_len),
        };
        let vk = shared.u32_at(OFF_VERSION_KIND).load(Ordering::Relaxed);
        if shared.u32_at(OFF_MAGIC).load(Ordering::Acquire) != MAGIC
            || vk & 0xffff != u32::from(VERSION)
            || shared.u32_at(OFF_DATA_LEN).load(Ordering::Relaxed) != data_len
        {
            return Err(Error::InvalidArgument);
        }
        let tail = shared.u64_at(OFF_TAIL).load(Ordering::Acquire);
        Ok(Self {
            shared,
            ntfy,
            bits,
            tail,
            head: 0,
        })
    }

    /// Grava um registro de `kind` (não zero) com `payload`.
    ///
    /// # Errors
    ///
    /// [`PushError`].
    pub fn push(&mut self, kind: u16, payload: &[u8]) -> Result<(), PushError> {
        if kind == KIND_PAD || payload.len() > MAX_PAYLOAD {
            return Err(PushError::Invalid);
        }
        let size = record_size(payload.len());
        let data_len = self.shared.data_len;
        let pos = self.shared.pos(self.tail);
        let pad = if pos + size > data_len {
            data_len - pos
        } else {
            0
        };
        let need = pad + size;
        if data_len - self.tail.wrapping_sub(self.head) < need {
            self.head = self.shared.u64_at(OFF_HEAD).load(Ordering::Acquire);
            if self.head > self.tail || self.tail - self.head > data_len {
                return Err(PushError::Corrupt);
            }
            if data_len - (self.tail - self.head) < need {
                self.shared
                    .u64_at(OFF_DROPPED)
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PushError::Full);
            }
        }
        let mut at = pos;
        if pad > 0 {
            self.record_head(at, (pad as usize) - RECORD_HEAD, KIND_PAD);
            at = 0;
        }
        self.record_head(at, payload.len(), kind);
        self.shared.write(at + RECORD_HEAD as u64, payload);
        self.tail += need;
        self.shared
            .u64_at(OFF_TAIL)
            .store(self.tail, Ordering::Release);
        fence(Ordering::SeqCst);
        if self.shared.u32_at(OFF_WAITING).load(Ordering::Relaxed) == 1 {
            ntfy_signal(self.ntfy, self.bits).map_err(PushError::Signal)?;
        }
        Ok(())
    }

    #[allow(clippy::cast_possible_truncation, reason = "len ≤ MAX_PAYLOAD")]
    fn record_head(&self, at: u64, len: usize, kind: u16) {
        let mut head = [0u8; RECORD_HEAD];
        head[..4].copy_from_slice(&(len as u32).to_le_bytes());
        head[4..6].copy_from_slice(&kind.to_le_bytes());
        self.shared.write(at, &head);
    }

    /// Registros descartados (por falta de espaço) até agora.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.u64_at(OFF_DROPPED).load(Ordering::Relaxed)
    }
}
