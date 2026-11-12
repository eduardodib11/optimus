//! `drvteste` (ADR 0042; T-401): driver de teste do `devmgr`, casado com o
//! dispositivo `edu` do QEMU pelo `[match]` do manifesto. Por enquanto só
//! se anuncia; os recursos do dispositivo chegam com a partida pelo
//! `devmgr`.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::kabi::Handle;
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
    let h = optcrypt::blake3::hash(b"debug");
    let debug = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
    if let Some(c) = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_KERNEL && c.name_hash == debug)
    {
        ostd::debug::set_log(Handle::from_raw(c.handle));
    }
    ostd::debug::print("drvteste: partiu");
    let _ = s.ready();
    ostd::thread::exit()
}
