//! Teclado e mouse PS/2 (controlador `i8042`: dados em 0x60, status e
//! comandos em 0x64).

/// Porta de dados.
pub const DATA_PORT: u16 = 0x60;
/// Porta de status (leitura) e de comando (escrita).
pub const STATUS_PORT: u16 = 0x64;

/// Origem de um byte de dados, pelo registrador de status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Sem byte à espera (bit 0 zerado).
    None,
    /// Teclado.
    Keyboard,
    /// Mouse (bit 5, "auxiliar").
    Mouse,
}

/// Quem produziu o byte esperando na porta 0x60.
#[must_use]
pub fn source(status: u8) -> Source {
    match (status & 1 != 0, status & 0x20 != 0) {
        (false, _) => Source::None,
        (true, false) => Source::Keyboard,
        (true, true) => Source::Mouse,
    }
}

/// Evento de tecla.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    /// Código do conjunto 1 do teclado; teclas estendidas (prefixo `E0`) somam
    /// [`Key::EXTENDED`].
    pub code: u16,
    /// Tecla apertada (`true`) ou solta.
    pub pressed: bool,
}

impl Key {
    /// Soma-se ao código das teclas com prefixo `E0`.
    pub const EXTENDED: u16 = 0x100;
    /// Código da tecla Pause (a sequência `E1 1D 45 E1 9D C5`).
    pub const PAUSE: u16 = 0x200;
}

/// Decodificador do conjunto de scancodes 1 (o `i8042` traduz o conjunto 2
/// para este por padrão). Mantém só o prefixo pendente.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keyboard {
    /// 0: nenhum; 1: após `E0`; 2 a 6: dentro da sequência do Pause.
    state: u8,
}

impl Keyboard {
    /// Alimenta um byte; devolve a tecla quando a sequência fecha.
    pub fn feed(&mut self, b: u8) -> Option<Key> {
        match (self.state, b) {
            (0, 0xE0) => self.state = 1,
            (0, 0xE1) => self.state = 2,
            // Respostas do controlador (ACK, auto-teste, erro, reenvio).
            (0, 0xFA | 0xAA | 0xFE | 0x00 | 0xFC | 0xFD | 0xFF) | (1, 0xE0) => {}
            (0, _) => return Some(Self::key(0, b)),
            (1, _) => {
                self.state = 0;
                return Some(Self::key(Key::EXTENDED, b));
            }
            // Pause: E1 1D 45 E1 9D C5; só o último byte fecha.
            (6, _) => {
                self.state = 0;
                return Some(Key {
                    code: Key::PAUSE,
                    pressed: true,
                });
            }
            (s, _) => self.state = s + 1,
        }
        None
    }

    fn key(base: u16, b: u8) -> Key {
        Key {
            code: base | u16::from(b & 0x7F),
            pressed: b & 0x80 == 0,
        }
    }
}

/// Pacote do mouse padrão de 3 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mouse {
    /// Deslocamento horizontal (positivo à direita).
    pub dx: i16,
    /// Deslocamento vertical (positivo para cima, como no hardware).
    pub dy: i16,
    /// Botões: bit 0 esquerdo, bit 1 direito, bit 2 do meio.
    pub buttons: u8,
}

/// Decodificador de pacotes do mouse; ressincroniza se o primeiro byte não
/// tiver o bit 3 ligado.
#[derive(Clone, Copy, Debug, Default)]
pub struct MouseDecoder {
    buf: [u8; 3],
    n: usize,
}

impl MouseDecoder {
    /// Alimenta um byte; devolve o pacote quando completa 3 bytes. Pacotes com
    /// estouro de deslocamento (bits 6 e 7) são descartados.
    pub fn feed(&mut self, b: u8) -> Option<Mouse> {
        if self.n == 0 && b & 8 == 0 {
            return None;
        }
        self.buf[self.n] = b;
        self.n += 1;
        if self.n < 3 {
            return None;
        }
        self.n = 0;
        let [s, x, y] = self.buf;
        if s & 0xC0 != 0 {
            return None;
        }
        let ext = |v: u8, neg: bool| i16::from(v) - if neg { 256 } else { 0 };
        Some(Mouse {
            dx: ext(x, s & 0x10 != 0),
            dy: ext(y, s & 0x20 != 0),
            buttons: s & 7,
        })
    }
}
