//! `i8042d` (T-406; ADR 0042 e 0049): driver do teclado PS/2 em processo
//! isolado. O `devmgr` o parte quando o `acpid` publica o nó `PNP0303`, com
//! a porta de dados (`io0`, 0x60), a de status e comando (`io1`, 0x64) e a
//! IRQ 1 (`irq0`). Os bytes passam pelo decodificador de [`olegacy::ps2`] e
//! cada tecla vai ao `inputd` por `optimus.input.Sink@1`.
//!
//! A IRQ é de borda: o driver esvazia o controlador, confirma a IRQ e
//! esvazia de novo, para não perder o byte que chegar entre as duas coisas.
//! O controlador também é do mouse (T-516; ADR 0059): o `init` liga a IRQ 12
//! e o relógio do mouse, mas os bytes do mouse ficam para o `ps2mouse`, que
//! o `devmgr` parte pelo nó `PNP0F13`. O status diz de quem é cada byte (bit
//! 5), e cada driver só lê os seus.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use oinput::Event;
use olegacy::ps2::{self, Keyboard, Source};
use ostd::ipc::{self, Message};
use ostd::kabi::{Handle, ObjectType};
use ostd::port::Ports;
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// `kind` de uma capability de serviço no descritor (ADR 0034).
const KIND_SVC: u8 = 1;
/// `kind` de um recurso de dispositivo.
const KIND_DEV: u8 = 3;
/// `kind` das capabilities de origem do kernel.
const KIND_KERNEL: u8 = 5;
/// Comandos do controlador: ler e gravar o byte de configuração.
const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
/// Comando: liga a porta do mouse.
const CMD_ENABLE_AUX: u8 = 0xA8;
/// Byte de configuração: IRQ 1 e IRQ 12 ligadas, relógio do mouse ligado e
/// tradução para o conjunto 1.
const CONFIG_KBD_IRQ: u8 = 1 << 0;
const CONFIG_AUX_IRQ: u8 = 1 << 1;
const CONFIG_AUX_CLOCK_OFF: u8 = 1 << 5;
const CONFIG_TRANSLATE: u8 = 1 << 6;
/// Status: há byte para ler; o controlador ainda não leu o último escrito.
const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;
/// Voltas de espera pelo controlador (ele responde em microssegundos).
const SPIN: u32 = 100_000;
/// Prazo de cada evento no `inputd`.
const SEND_NS: u64 = 100_000_000;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// O controlador: dados em 0x60, status e comando em 0x64.
struct Chip {
    data: Ports,
    ctl: Ports,
}

impl Chip {
    fn status(&self) -> u8 {
        self.ctl.read8(0)
    }

    /// Espera o controlador aceitar outro byte.
    fn wait_write(&self) -> Result<(), &'static str> {
        for _ in 0..SPIN {
            if self.status() & STATUS_INPUT_FULL == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("o controlador não aceita comando")
    }

    /// Espera a resposta de um comando (um byte que não é do mouse: o
    /// `ps2mouse` pode estar ligando o mouse na mesma hora).
    fn wait_read(&self) -> Result<u8, &'static str> {
        for _ in 0..SPIN {
            if ps2::source(self.status()) == Source::Keyboard {
                return Ok(self.data.read8(0));
            }
            core::hint::spin_loop();
        }
        Err("o controlador não respondeu")
    }

    /// Descarta o que o firmware deixou e liga a IRQ 1 com tradução.
    fn init(&self) -> Result<(), &'static str> {
        while self.status() & STATUS_OUTPUT_FULL != 0 {
            let _ = self.data.read8(0);
        }
        self.wait_write()?;
        self.ctl.write8(0, CMD_READ_CONFIG);
        let config = (self.wait_read()? | CONFIG_KBD_IRQ | CONFIG_AUX_IRQ | CONFIG_TRANSLATE)
            & !CONFIG_AUX_CLOCK_OFF;
        self.wait_write()?;
        self.ctl.write8(0, CMD_WRITE_CONFIG);
        self.wait_write()?;
        self.data.write8(0, config);
        self.wait_write()?;
        self.ctl.write8(0, CMD_ENABLE_AUX);
        Ok(())
    }
}

struct Driver {
    chip: Chip,
    sink: Handle,
    keyboard: Keyboard,
}

impl Driver {
    /// Lê todos os bytes à espera; `false` quando o `inputd` se foi.
    fn drain(&mut self) -> bool {
        loop {
            // Byte do mouse fica no controlador para o `ps2mouse`.
            if ps2::source(self.chip.status()) != Source::Keyboard {
                return true;
            }
            let byte = self.chip.data.read8(0);
            let Some(key) = self.keyboard.feed(byte) else {
                continue;
            };
            let words = oinput::encode(Event::Key {
                code: key.code,
                pressed: key.pressed,
            });
            let deadline = ostd::time::now_ns().saturating_add(SEND_NS);
            let msg = Message::new(oinput::label(), &words);
            match ipc::call(self.sink, &msg, deadline) {
                Ok(_) | Err(ostd::kabi::Error::TimedOut) => {}
                Err(_) => return false,
            }
        }
    }
}

fn run(s: &Session) -> Result<(), &'static str> {
    let cap = |kind: u8, name: u32| {
        s.boot
            .caps()
            .iter()
            .find(|c| c.kind == kind && c.name_hash == name)
            .map(|c| Handle::from_raw(c.handle))
    };
    let dev = |name: &[u8]| cap(KIND_DEV, hash(name));
    let (Some(io0), Some(io1), Some(irq)) = (dev(b"io0"), dev(b"io1"), dev(b"irq0")) else {
        return Err("faltou io0, io1 ou irq0");
    };
    let sink = cap(KIND_SVC, oinput::interface_id()).ok_or("sem o Sink do inputd")?;
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    ostd::port::bind(io0).map_err(|_| "ligar a porta de dados")?;
    ostd::port::bind(io1).map_err(|_| "ligar a porta de status")?;
    let ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).map_err(|_| "notificação")?;
    ostd::cap::bind_notify(irq, ntfy, 0).map_err(|_| "ligar a IRQ 1")?;
    let mut d = Driver {
        chip: Chip {
            data: Ports::new(ps2::DATA_PORT, 1),
            ctl: Ports::new(ps2::STATUS_PORT, 1),
        },
        sink,
        keyboard: Keyboard::default(),
    };
    d.chip.init()?;
    ostd::debug::print("i8042d: teclado pronto");
    loop {
        if !d.drain() {
            return Err("o inputd se foi");
        }
        ostd::dev::irq_ack(irq).map_err(|_| "confirmar a IRQ")?;
        if !d.drain() {
            return Err("o inputd se foi");
        }
        ostd::cap::ntfy_wait(ntfy).map_err(|_| "esperar a IRQ")?;
    }
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
    if let Some(c) = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_KERNEL && c.name_hash == hash(b"debug"))
    {
        ostd::debug::set_log(Handle::from_raw(c.handle));
    }
    let _ = s.ready();
    if let Err(e) = run(&s) {
        ostd::debug::print_fmt(format_args!("i8042d: encerrado: {e}"));
    }
    ostd::thread::exit()
}
