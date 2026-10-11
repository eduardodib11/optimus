//! Formato das mensagens de IPC no x86-64 (SDD v1.0, seção 6.7; ADR 0027).
//!
//! `ipc_call`, `ipc_send`, `ipc_recv` e `ipc_reply_recv` usam:
//!
//! | Registrador | Entrada | Saída |
//! |---|---|---|
//! | `rax` | número da syscall | status |
//! | `rdi` | handle do endpoint ou reply | badge do remetente |
//! | `rsi` | rótulo | rótulo |
//! | `rdx` | [`MsgInfo`] | [`MsgInfo`] |
//! | `r10` | prazo em ns monotônicos (0 = sem prazo) | não usado |
//! | `r8`, `r9`, `r12`–`r15` | palavras 0 a 5 | palavras 0 a 5 |
//!
//! `ipc_recv` e `ipc_reply_recv` recebem dois handles em `rdi`
//! ([`recv_target`]): o endpoint nos 32 bits baixos e o `Reply` onde guardar
//! quem chamou nos 32 altos (definido aqui; a ADR só diz "endpoint ou
//! reply"). `ipc_send` sobre um `Reply` responde sem receber.
//!
//! Os handles das capabilities transferidas e as palavras longas ficam no
//! buffer de IPC da thread ([`IpcBuffer`]).

use crate::{
    Handle, IPC_BUFFER_BYTES, IPC_BUFFER_WORDS, MSG_MAX_CAPS, MSG_REG_WORDS, UnknownValue,
};

/// Bits de [`MsgInfo`] com a quantidade de palavras em registradores.
const WORDS_BITS: u32 = 3;
/// Deslocamento da quantidade de capabilities.
const CAPS_SHIFT: u32 = 3;
/// Bits da quantidade de capabilities.
const CAPS_BITS: u32 = 3;
/// Deslocamento das flags.
const FLAGS_SHIFT: u32 = 6;
/// Bits das flags.
const FLAGS_BITS: u32 = 10;
/// Deslocamento da quantidade de palavras no buffer de IPC.
const BUFFER_SHIFT: u32 = 16;
/// Bits da quantidade de palavras no buffer de IPC.
const BUFFER_BITS: u32 = 9;

const fn mask(bits: u32) -> u64 {
    (1 << bits) - 1
}

/// Flag de [`MsgInfo`]: não bloquear; sem par pronto, a syscall devolve
/// `WouldBlock`.
pub const FLAG_NONBLOCK: u16 = 1;
/// Flags definidas; as demais são recusadas.
pub const ALL_FLAGS: u16 = FLAG_NONBLOCK;

/// Campo `info` de uma mensagem (`rdx`).
///
/// Layout em `u64` (ADR 0027; posições definidas aqui): bits 0–2 palavras
/// em registradores (até [`MSG_REG_WORDS`]), 3–5 capabilities (até
/// [`MSG_MAX_CAPS`]), 6–15 flags e 16–24 palavras no buffer de IPC (até
/// [`IPC_BUFFER_WORDS`]); o resto é zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MsgInfo {
    /// Palavras em registradores (`r8`, `r9`, `r12`–`r15`).
    pub words: u8,
    /// Capabilities cujos handles estão no cabeçalho do buffer.
    pub caps: u8,
    /// Flags ([`FLAG_NONBLOCK`]).
    pub flags: u16,
    /// Palavras em [`IpcBuffer::words`].
    pub buffer_words: u16,
}

impl MsgInfo {
    /// Mensagem com `words` palavras em registradores, sem mais nada.
    #[must_use]
    pub const fn words(words: u8) -> Self {
        Self {
            words,
            caps: 0,
            flags: 0,
            buffer_words: 0,
        }
    }

    /// Valor para `rdx`.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        (self.words as u64 & mask(WORDS_BITS))
            | ((self.caps as u64 & mask(CAPS_BITS)) << CAPS_SHIFT)
            | ((self.flags as u64 & mask(FLAGS_BITS)) << FLAGS_SHIFT)
            | ((self.buffer_words as u64 & mask(BUFFER_BITS)) << BUFFER_SHIFT)
    }

    /// Verdadeiro se tudo cabe em registradores: sem capabilities nem buffer.
    #[must_use]
    pub const fn registers_only(self) -> bool {
        self.caps == 0 && self.buffer_words == 0
    }
}

impl TryFrom<u64> for MsgInfo {
    type Error = UnknownValue;

    /// Recusa contagens acima dos limites, flags desconhecidas e bits altos.
    fn try_from(raw: u64) -> Result<Self, UnknownValue> {
        #[allow(clippy::cast_possible_truncation, reason = "campos mascarados")]
        let info = Self {
            words: (raw & mask(WORDS_BITS)) as u8,
            caps: ((raw >> CAPS_SHIFT) & mask(CAPS_BITS)) as u8,
            flags: ((raw >> FLAGS_SHIFT) & mask(FLAGS_BITS)) as u16,
            buffer_words: ((raw >> BUFFER_SHIFT) & mask(BUFFER_BITS)) as u16,
        };
        let ok = usize::from(info.words) <= MSG_REG_WORDS
            && usize::from(info.caps) <= MSG_MAX_CAPS
            && info.flags & !ALL_FLAGS == 0
            && usize::from(info.buffer_words) <= IPC_BUFFER_WORDS
            && info.to_raw() == raw;
        if ok { Ok(info) } else { Err(UnknownValue(raw)) }
    }
}

/// `rdi` de `ipc_recv`/`ipc_reply_recv`: endpoint nos 32 bits baixos,
/// `Reply` nos 32 altos.
#[must_use]
pub const fn recv_target(endpoint: Handle, reply: Handle) -> u64 {
    endpoint.raw() as u64 | ((reply.raw() as u64) << 32)
}

/// Desfaz [`recv_target`]: `(endpoint, reply)`.
#[must_use]
pub const fn split_recv_target(raw: u64) -> (Handle, Handle) {
    #[allow(clippy::cast_possible_truncation, reason = "metades de 32 bits")]
    (
        Handle::from_raw(raw as u32),
        Handle::from_raw((raw >> 32) as u32),
    )
}

/// Bytes do cabeçalho do buffer de IPC.
pub const HEADER_BYTES: usize = IPC_BUFFER_BYTES - IPC_BUFFER_WORDS * 8;

/// Buffer de IPC de uma thread: uma página alinhada no espaço dela.
///
/// Ao enviar, `caps` traz os handles (no `CapSpace` do remetente) das
/// capabilities a transferir; ao receber, o kernel grava ali os handles
/// novos no `CapSpace` do receptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(4096))]
pub struct IpcBuffer {
    /// Handles crus das capabilities da mensagem.
    pub caps: [u32; MSG_MAX_CAPS],
    /// Reservado, zero.
    pub reserved: [u64; 6],
    /// Palavras longas da mensagem.
    pub words: [u64; IPC_BUFFER_WORDS],
}

impl IpcBuffer {
    /// Buffer zerado.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            caps: [0; MSG_MAX_CAPS],
            reserved: [0; 6],
            words: [0; IPC_BUFFER_WORDS],
        }
    }

    /// Índice, em palavras de 64 bits desde o início do buffer, da primeira
    /// palavra longa.
    pub const WORDS_OFFSET: usize = HEADER_BYTES / 8;
}

impl Default for IpcBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn layout_do_buffer() {
        assert_eq!(size_of::<IpcBuffer>(), IPC_BUFFER_BYTES);
        assert_eq!(HEADER_BYTES, 64);
        assert_eq!(offset_of!(IpcBuffer, words), 64);
        assert_eq!(IpcBuffer::WORDS_OFFSET, 8);
        assert_eq!(IpcBuffer::default(), IpcBuffer::new());
    }

    #[test]
    fn info_ida_e_volta() {
        let info = MsgInfo {
            words: 6,
            caps: 4,
            flags: FLAG_NONBLOCK,
            buffer_words: 504,
        };
        assert_eq!(info.to_raw(), 6 | (4 << 3) | (1 << 6) | (504 << 16));
        assert_eq!(MsgInfo::try_from(info.to_raw()), Ok(info));
        assert!(!info.registers_only());
        assert!(MsgInfo::words(3).registers_only());
        assert_eq!(MsgInfo::try_from(0), Ok(MsgInfo::default()));
    }

    #[test]
    fn info_recusa_fora_dos_limites() {
        for raw in [7, 5 << 3, 2 << 6, 505 << 16, 1 << 25, 1 << 63] {
            assert_eq!(MsgInfo::try_from(raw), Err(UnknownValue(raw)), "{raw:#x}");
        }
    }

    #[test]
    fn dois_handles_em_rdi() {
        let (ep, reply) = (Handle::new(5, 1).unwrap(), Handle::new(9, 2).unwrap());
        let raw = recv_target(ep, reply);
        assert_eq!(raw, 0x0200_0009_0100_0005);
        assert_eq!(split_recv_target(raw), (ep, reply));
    }
}
