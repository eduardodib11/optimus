//! `ps2mouse` (T-516; ADR 0059): driver do mouse PS/2 em processo isolado.
//! O `devmgr` o parte quando o `acpid` publica o nó `PNP0F13`, com a porta
//! de dados (`io0`, 0x60), a de status e comando (`io1`, 0x64) e a IRQ 12
//! (`irq0`). Os pacotes de 3 bytes passam por [`ps2::MouseDecoder`] e cada
//! movimento vai ao `inputd` por `optimus.input.Sink@1`.
//!
//! O controlador 8042 é um só e o `i8042d` é o dono dele: configura o byte
//! de comando (IRQ 12 ligada, relógio do mouse ligado) e fica com o teclado.
//! Este driver só manda o `Enable Streaming` ao mouse e lê os bytes que o
//! status marca como do mouse (bit 5); nunca lê um byte de teclado, nem o
//! `i8042d` um do mouse, então os dois dividem a porta de dados sem se
//! atrapalhar.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use oinput::Event;
use olegacy::ps2::{self, MouseDecoder, Source};
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
/// Comando do controlador: o próximo byte de dados vai ao mouse.
const CMD_TO_MOUSE: u8 = 0xD4;
/// Comando do mouse: liga o envio de pacotes.
const MOUSE_ENABLE_STREAMING: u8 = 0xF4;
/// Resposta do mouse a um comando aceito.
const MOUSE_ACK: u8 = 0xFA;
/// Status: o controlador ainda não leu o último byte escrito.
const STATUS_INPUT_FULL: u8 = 1 << 1;
/// Voltas de espera pelo controlador e pelo mouse.
const SPIN: u32 = 1_000_000;
/// Tentativas do `Enable Streaming` (o `i8042d` pode estar configurando o
/// controlador na mesma hora).
const TRIES: u32 = 3;
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
    fn wait_write(&self) -> bool {
        for _ in 0..SPIN {
            if self.status() & STATUS_INPUT_FULL == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Espera um byte do mouse (os do teclado ficam para o `i8042d`).
    fn wait_mouse(&self) -> Option<u8> {
        for _ in 0..SPIN {
            if ps2::source(self.status()) == Source::Mouse {
                return Some(self.data.read8(0));
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Liga o envio de pacotes do mouse e espera o `ACK`.
    fn enable_streaming(&self) -> Result<(), &'static str> {
        for _ in 0..TRIES {
            if !self.wait_write() {
                continue;
            }
            self.ctl.write8(0, CMD_TO_MOUSE);
            if !self.wait_write() {
                continue;
            }
            self.data.write8(0, MOUSE_ENABLE_STREAMING);
            if self.wait_mouse() == Some(MOUSE_ACK) {
                return Ok(());
            }
        }
        Err("o mouse não respondeu ao Enable Streaming")
    }
}

struct Driver {
    chip: Chip,
    sink: Handle,
    decoder: MouseDecoder,
}

impl Driver {
    /// Lê os bytes do mouse à espera; `false` quando o `inputd` se foi.
    fn drain(&mut self) -> bool {
        while ps2::source(self.chip.status()) == Source::Mouse {
            let byte = self.chip.data.read8(0);
            let Some(m) = self.decoder.feed(byte) else {
                continue;
            };
            let words = oinput::encode(Event::Pointer {
                dx: m.dx,
                dy: m.dy,
                buttons: m.buttons,
            });
            let deadline = ostd::time::now_ns().saturating_add(SEND_NS);
            let msg = Message::new(oinput::label(), &words);
            match ipc::call(self.sink, &msg, deadline) {
                Ok(_) | Err(ostd::kabi::Error::TimedOut) => {}
                Err(_) => return false,
            }
        }
        true
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
    ostd::cap::bind_notify(irq, ntfy, 0).map_err(|_| "ligar a IRQ 12")?;
    let mut d = Driver {
        chip: Chip {
            data: Ports::new(ps2::DATA_PORT, 1),
            ctl: Ports::new(ps2::STATUS_PORT, 1),
        },
        sink,
        decoder: MouseDecoder::default(),
    };
    d.chip.enable_streaming()?;
    ostd::debug::print("ps2mouse: mouse pronto");
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
        ostd::debug::print_fmt(format_args!("ps2mouse: encerrado: {e}"));
    }
    ostd::thread::exit()
}
