//! `rtcd` (T-406; ADR 0042 e 0049): driver do RTC CMOS em processo isolado.
//! O `devmgr` o parte quando o `acpid` publica o nó `PNP0B00`, com a faixa
//! de portas do nó (`io0`, 0x70 em diante). O driver liga a faixa à própria
//! thread e lê a data e a hora com [`olegacy::rtc`], que espera o chip
//! estabilizar; a hora (UTC, ADR 0037) vai para o log.
//!
//! Só lê: não grava no CMOS nem usa a IRQ 8. Entregar a hora ao `timed`
//! (que hoje parte da hora lida pelo `optboot`) fica para o `Admin.set`.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use olegacy::rtc::{self, Cmos};
use ostd::kabi::Handle;
use ostd::port::Ports;
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// `kind` de um recurso de dispositivo.
const KIND_DEV: u8 = 3;
/// Porta de índice do CMOS; a de dados é a seguinte.
const CMOS_BASE: u16 = 0x70;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// O CMOS pelas portas 0x70 (índice) e 0x71 (dados). O bit 7 do índice
/// desliga a NMI; fica zerado, como o firmware deixou.
struct Chip(Ports);

impl Cmos for Chip {
    fn read(&mut self, reg: u8) -> u8 {
        self.0.write8(0, reg & 0x7F);
        self.0.read8(1)
    }
}

fn run(s: &Session) -> Result<i64, &'static str> {
    let io = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_DEV && c.name_hash == hash(b"io0"))
        .map(|c| Handle::from_raw(c.handle))
        .ok_or("faltou io0")?;
    ostd::port::bind(io).map_err(|_| "ligar as portas")?;
    let mut chip = Chip(Ports::new(CMOS_BASE, 2));
    rtc::read_unix(&mut chip, rtc::CENTURY_DEFAULT).ok_or("CMOS instável ou inválido")
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
    match run(&s) {
        Ok(unix) => ostd::debug::print_fmt(format_args!("rtcd: RTC em {unix} s Unix")),
        Err(e) => ostd::debug::print_fmt(format_args!("rtcd: falhou: {e}")),
    }
    ostd::thread::exit()
}
