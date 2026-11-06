//! `memd` como serviço (T-361; ADR 0038): sobe pelo `svcmgr`, pega o
//! endpoint de `optimus.mem.Mem@1` no descritor, avisa `ready` e atende as
//! faltas que chegam nele ([`memd::serve`]). Quando o `svcmgr` revoga o
//! endpoint, o `memd` sai e relata o que atendeu.
//!
//! Ficam para depois: o `manage` remoto (com a transferência do objeto) e
//! o aviso ao `svcmgr` ao negar uma falta.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::kabi::{Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
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
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let Some(ep) = s
        .boot
        .provided(hash(b"optimus.mem.Mem@1"))
        .map(Handle::from_raw)
    else {
        ostd::debug::print("memd: descritor sem o endpoint de Mem@1");
        ostd::thread::exit()
    };
    let Ok(reply) = ostd::cap::create(quota, ObjectType::Reply, 0) else {
        ostd::thread::exit()
    };
    if s.ready().is_ok() {
        let mut pager = memd::Pager::new();
        let end = memd::serve(&mut pager, ep, reply, 0, |_| false);
        ostd::debug::print_fmt(format_args!(
            "memd: encerrado ({:?}); {} faltas atendidas, {} negadas",
            end.err(),
            pager.served,
            pager.denied
        ));
    }
    ostd::thread::exit()
}
