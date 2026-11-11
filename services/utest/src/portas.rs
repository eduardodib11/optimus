//! `IoPortRange` (ADR 0049): criação só com a cota de dispositivo, portas
//! do kernel recusadas, `in`/`out` na faixa ligada e `#GP` numa thread que
//! não a ligou.

use ostd::kabi::Error;
use ostd::kabi::exit::CAUSE_FAULTED;
use ostd::port::{self, Ports};

use crate::Ctx;

/// `#GP`.
const GP_VECTOR: u64 = 13;

pub fn portas_de_es(ctx: &Ctx) -> Result<(), &'static str> {
    let device = ctx.device.ok_or("sem cota de dispositivo")?;
    if port::create(ctx.quota, 0x70, 2) != Err(Error::AccessDenied) {
        return Err("a cota comum criou portas");
    }
    for (base, count) in [(0x3f8, 8), (0x20, 1), (0xcf8, 8), (0x70, 0), (0xffff, 2)] {
        if port::create(device, base, count) != Err(Error::InvalidArgument) {
            return Err("faixa do kernel ou inválida aceita");
        }
    }
    let cmos = port::create(device, 0x70, 2).map_err(|_| "criar 0x70")?;
    port::bind(cmos).map_err(|_| "ligar 0x70")?;
    // Registrador A do RTC: o QEMU usa o divisor de 32,768 kHz (010).
    let rtc = Ports::new(0x70, 2);
    rtc.write8(0, 0x0a);
    let status_a = rtc.read8(1);
    // Outra thread do mesmo processo não herda as portas.
    let denied = ostd::thread::spawn(|| Ports::new(0x70, 2).read8(1)).join_status();
    let held = (0..3).map(|_| port::create(device, 0x80, 1));
    let mut extra = alloc::vec::Vec::new();
    for h in held {
        let h = h.map_err(|_| "criar 0x80")?;
        port::bind(h).map_err(|_| "ligar até 4")?;
        extra.push(h);
    }
    let fifth = port::create(device, 0x80, 1).map_err(|_| "criar 0x80")?;
    let busy = port::bind(fifth);
    let cleared = port::unbind_all();
    for h in extra.into_iter().chain([cmos, fifth]) {
        let _ = ostd::cap::delete(h);
    }
    if status_a & 0x70 != 0x20 {
        return Err("registrador A do RTC inesperado");
    }
    match denied {
        Err(d) if d.cause == CAUSE_FAULTED && d.code == GP_VECTOR => {}
        _ => return Err("a outra thread devia faltar com #GP"),
    }
    if busy != Err(Error::Busy) || cleared.is_err() {
        return Err("a quinta faixa devia dar Busy");
    }
    Ok(())
}
