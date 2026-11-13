//! Fio de `optimus.input.Sink@1` (T-406; ADR 0042, item 4): o que um driver
//! de entrada (o `i8042d` hoje, o `virtio-input` na T-413) manda ao
//! `inputd`. Um evento cabe nas palavras da mensagem, sem corpo.
//!
//! `event` (método 0) leva `[tipo, a, b, c]`: tecla (`tipo` 0) com o código
//! e apertada ou solta; ponteiro (`tipo` 1) com `dx`, `dy` e os botões. O
//! código da tecla é o do conjunto 1 de scancodes, com as extensões de
//! [`Event::Key`]. A resposta não tem palavras.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// Palavras de um pedido `event`.
pub const EVENT_WORDS: usize = 4;

/// Evento de entrada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Tecla: código do conjunto 1 (estendidas somam 0x100; Pause é 0x200).
    Key {
        /// Código da tecla.
        code: u16,
        /// Apertada (`true`) ou solta.
        pressed: bool,
    },
    /// Movimento relativo do ponteiro e estado dos botões.
    Pointer {
        /// Deslocamento horizontal (positivo à direita).
        dx: i16,
        /// Deslocamento vertical (positivo para cima).
        dy: i16,
        /// Bit 0 esquerdo, bit 1 direito, bit 2 do meio.
        buttons: u8,
    },
}

/// `interface_id` de `optimus.input.Sink@1` (ADR 0033).
#[must_use]
pub fn interface_id() -> u32 {
    let h = optcrypt::blake3::hash(b"optimus.input.Sink@1");
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Rótulo do pedido `event` (método 0, `minor_min` 0).
#[must_use]
pub fn label() -> u64 {
    u64::from(interface_id()) << 32
}

/// O rótulo é um pedido `event` desta interface.
#[must_use]
pub fn is_event(label: u64) -> bool {
    label == self::label()
}

/// Palavras do pedido `event`.
#[must_use]
pub fn encode(e: Event) -> [u64; EVENT_WORDS] {
    match e {
        Event::Key { code, pressed } => [0, u64::from(code), u64::from(pressed), 0],
        Event::Pointer { dx, dy, buttons } => [
            1,
            u64::from(dx.cast_unsigned()),
            u64::from(dy.cast_unsigned()),
            u64::from(buttons),
        ],
    }
}

/// Lê as palavras de um pedido `event`; `None` se o tipo ou algum campo não
/// couber (quem manda é um driver isolado, não se confia nele).
#[must_use]
pub fn decode(words: &[u64]) -> Option<Event> {
    let &[kind, a, b, c] = words else { return None };
    match kind {
        0 if b <= 1 && c == 0 => Some(Event::Key {
            code: u16::try_from(a).ok()?,
            pressed: b == 1,
        }),
        1 => Some(Event::Pointer {
            dx: u16::try_from(a).ok()?.cast_signed(),
            dy: u16::try_from(b).ok()?.cast_signed(),
            buttons: u8::try_from(c).ok().filter(|v| v & !7 == 0)?,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ida_e_volta() {
        for e in [
            Event::Key {
                code: 0x1E,
                pressed: true,
            },
            Event::Key {
                code: 0x200,
                pressed: false,
            },
            Event::Pointer {
                dx: -3,
                dy: 255,
                buttons: 5,
            },
            Event::Pointer {
                dx: i16::MIN,
                dy: i16::MAX,
                buttons: 0,
            },
        ] {
            assert_eq!(decode(&encode(e)), Some(e));
        }
    }

    #[test]
    fn recusa_o_que_nao_cabe() {
        assert_eq!(decode(&[0, 0x1E, 1]), None);
        assert_eq!(decode(&[2, 0, 0, 0]), None);
        assert_eq!(decode(&[0, 0x1_0000, 1, 0]), None);
        assert_eq!(decode(&[0, 0x1E, 2, 0]), None);
        assert_eq!(decode(&[0, 0x1E, 1, 9]), None);
        assert_eq!(decode(&[1, 0x1_0000, 0, 0]), None);
        assert_eq!(decode(&[1, 0, 0, 8]), None);
    }

    #[test]
    fn rotulo_so_do_metodo_zero() {
        assert!(is_event(label()));
        assert!(!is_event(label() | 1));
        assert!(!is_event(label() | 1 << 16));
        assert!(!is_event(0));
    }
}
