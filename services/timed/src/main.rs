//! `timed` como serviço (T-358; ADR 0037): sobe pelo `svcmgr`, pega o
//! endpoint de `optimus.time.Clock@1` no descritor, avisa `ready` e atende
//! `now()` com a hora do boot ([`timed::Clock::from_boot`]).
//!
//! `now()` (método 0) responde as palavras `[unix_ns, mono_ns,
//! uncertainty_ns, synced]`. O `set()` e o `Admin@1` vêm com o `connect`
//! dos clientes.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// `interface_id("optimus.time.Clock", 1)`.
fn clock_id() -> u32 {
    let h = optcrypt::blake3::hash(b"optimus.time.Clock@1");
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

fn serve(ep: Handle, quota: Handle, clock: &timed::Clock) -> Result<(), Error> {
    let reply = ostd::cap::create(quota, ObjectType::Reply, 0)?;
    let iid = u64::from(clock_id());
    loop {
        let r = ipc::recv(ep, reply, 0)?;
        let answer = if r.msg.label >> 32 == iid && r.msg.label.trailing_zeros() >= 16 {
            match clock.now(ostd::time::now_ns()) {
                Ok(t) => Message::new(
                    osvc::REPLY_OK,
                    &[
                        t.unix_ns.cast_unsigned(),
                        t.mono_ns,
                        t.uncertainty_ns,
                        u64::from(t.synced),
                    ],
                ),
                Err(_) => Message::new(osvc::REPLY_ERR, &[0]),
            }
        } else {
            Message::new(osvc::REPLY_UNKNOWN_METHOD, &[])
        };
        let _ = ipc::send(reply, &answer, 0);
    }
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let Some(ep) = s.boot.provided(clock_id()).map(Handle::from_raw) else {
        ostd::thread::exit()
    };
    let clock = match ostd::time::boot_wall() {
        Ok(Some((wall, at))) => timed::Clock::from_boot(wall, at, true),
        _ => timed::Clock::from_boot(0, 0, false),
    };
    if s.ready().is_ok() {
        let _ = serve(ep, quota, &clock);
    }
    ostd::thread::exit()
}
