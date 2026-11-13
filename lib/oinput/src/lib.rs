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

/// Tradução dos eventos `evdev` que o `virtio-input` entrega (`type`,
/// `code`, `value`) para [`Event`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Evdev {
    dx: i32,
    dy: i32,
    buttons: u8,
    changed: bool,
}

impl Evdev {
    const EV_SYN: u16 = 0;
    const EV_KEY: u16 = 1;
    const EV_REL: u16 = 2;
    const BTN_LEFT: u16 = 0x110;
    const BTN_MIDDLE: u16 = 0x112;

    /// Código do conjunto 1 de scancodes da tecla `evdev` `code`; `None` se
    /// não há equivalente.
    #[must_use]
    pub fn scancode(code: u16) -> Option<u16> {
        match code {
            1..=88 => Some(code),
            96 => Some(0x11c),
            97 => Some(0x11d),
            98 => Some(0x135),
            100 => Some(0x138),
            102 => Some(0x147),
            103 => Some(0x148),
            104 => Some(0x149),
            105 => Some(0x14b),
            106 => Some(0x14d),
            107 => Some(0x14f),
            108 => Some(0x150),
            109 => Some(0x151),
            110 => Some(0x152),
            111 => Some(0x153),
            125 => Some(0x15b),
            126 => Some(0x15c),
            _ => None,
        }
    }

    /// Consome um evento do dispositivo. Teclas saem na hora; o movimento do
    /// ponteiro e os botões saem no `EV_SYN` que fecha o grupo.
    pub fn feed(&mut self, kind: u16, code: u16, value: u32) -> Option<Event> {
        match kind {
            Self::EV_KEY if (Self::BTN_LEFT..=Self::BTN_MIDDLE).contains(&code) => {
                let bit = 1u8 << (code - Self::BTN_LEFT);
                if value == 0 {
                    self.buttons &= !bit;
                } else {
                    self.buttons |= bit;
                }
                self.changed = true;
                None
            }
            Self::EV_KEY => Some(Event::Key {
                code: Self::scancode(code)?,
                pressed: value != 0,
            }),
            Self::EV_REL => {
                // No evdev, Y positivo é para baixo; no `Sink`, para cima.
                match code {
                    0 => self.dx = self.dx.saturating_add(value.cast_signed()),
                    1 => self.dy = self.dy.saturating_sub(value.cast_signed()),
                    _ => return None,
                }
                self.changed = true;
                None
            }
            Self::EV_SYN if self.changed => {
                let clamp =
                    |v: i32| i16::try_from(v).unwrap_or(if v < 0 { i16::MIN } else { i16::MAX });
                let e = Event::Pointer {
                    dx: clamp(self.dx),
                    dy: clamp(self.dy),
                    buttons: self.buttons,
                };
                (self.dx, self.dy, self.changed) = (0, 0, false);
                Some(e)
            }
            _ => None,
        }
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

    #[test]
    fn evdev_tecla_e_ponteiro() {
        let mut t = Evdev::default();
        assert_eq!(
            t.feed(1, 30, 1),
            Some(Event::Key {
                code: 0x1e,
                pressed: true
            })
        );
        assert_eq!(
            t.feed(1, 103, 0),
            Some(Event::Key {
                code: 0x148,
                pressed: false
            })
        );
        assert_eq!(t.feed(1, 0x300, 1), None);
        assert_eq!(t.feed(2, 0, 5), None);
        assert_eq!(t.feed(2, 1, 3), None);
        assert_eq!(t.feed(1, 0x110, 1), None);
        assert_eq!(
            t.feed(0, 0, 0),
            Some(Event::Pointer {
                dx: 5,
                dy: -3,
                buttons: 1
            })
        );
        assert_eq!(t.feed(0, 0, 0), None);
        assert_eq!(t.feed(2, 0, (-7i32).cast_unsigned()), None);
        assert_eq!(
            t.feed(0, 0, 0),
            Some(Event::Pointer {
                dx: -7,
                dy: 0,
                buttons: 1
            })
        );
    }
}
