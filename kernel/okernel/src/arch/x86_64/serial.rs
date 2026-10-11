//! UART 16550 em COM1 (porta 0x3f8), 115200 8N1, sem interrupções.

use super::{inb, outb};

/// Porta base da COM1.
const COM1: u16 = 0x3f8;
/// Line Status Register: bit 5 = registrador de transmissão vazio.
const LSR_THR_EMPTY: u8 = 1 << 5;

/// Porta serial COM1. Só existe uma; o logger guarda o acesso exclusivo.
pub struct Serial(());

impl Serial {
    /// Programa a COM1: interrupções desligadas, divisor 1 (115200), 8N1 e
    /// FIFO ligada.
    pub fn init() -> Self {
        let regs: [(u16, u8); 7] = [
            (1, 0x00), // IER: sem interrupções
            (3, 0x80), // LCR: DLAB para escrever o divisor
            (0, 0x01), // DLL: divisor 1 = 115200 baud
            (1, 0x00), // DLM
            (3, 0x03), // LCR: 8 bits, sem paridade, 1 stop, DLAB desligado
            (2, 0xc7), // FCR: liga e limpa as FIFOs
            (4, 0x03), // MCR: DTR e RTS
        ];
        for (offset, value) in regs {
            // SAFETY: registradores documentados do 16550 na COM1, que o
            // kernel usa sozinho (o firmware já saiu de cena).
            unsafe { outb(COM1 + offset, value) };
        }
        Self(())
    }

    /// Acesso à COM1 já programada. Só o logger chama, sob a sua trava (ou em
    /// emergência, quando nada mais roda).
    pub fn com1() -> Self {
        Self(())
    }

    #[allow(
        clippy::unused_self,
        reason = "`&mut self` é a prova de acesso exclusivo"
    )]
    fn put(&mut self, byte: u8) {
        // SAFETY: ler o LSR não tem efeito colateral; escrever no THR envia
        // um byte. `&mut self` garante um escritor por vez.
        unsafe {
            while inb(COM1 + 5) & LSR_THR_EMPTY == 0 {
                core::hint::spin_loop();
            }
            outb(COM1, byte);
        }
    }
}

impl core::fmt::Write for Serial {
    /// Envia o texto convertendo `\n` em `\r\n`.
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.bytes() {
            if byte == b'\n' {
                self.put(b'\r');
            }
            self.put(byte);
        }
        Ok(())
    }
}
