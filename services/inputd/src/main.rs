//! `inputd` (T-406; ADR 0042, item 4): o destino dos eventos de entrada.
//! Sobe pelo `svcmgr`, pega o endpoint de `optimus.input.Sink@1` no
//! descritor e atende `event` dos drivers (o `i8042d`; o `virtio-input` na
//! T-413), que rodam isolados e não são de confiança: evento que não
//! decodifica é recusado.
//!
//! Por ora conta os eventos e registra as teclas no log; a fila para os
//! clientes (o `displayd` e o foco de janela) vem com eles.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use oinput::Event;
use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

fn serve(ep: Handle, quota: Handle) -> Error {
    let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let (mut keys, mut moves) = (0u64, 0u64);
    loop {
        let r = match ipc::recv(ep, reply, 0) {
            Ok(r) => r,
            Err(e) => {
                // Uma linha só: o `svcmgr` apaga o processo logo depois de
                // revogar o endpoint.
                ostd::debug::print_fmt(format_args!(
                    "inputd: encerrado ({e:?}); {keys} teclas e {moves} movimentos"
                ));
                return e;
            }
        };
        let label = if oinput::is_event(r.msg.label) {
            match oinput::decode(r.msg.payload()) {
                Some(Event::Key { code, pressed }) => {
                    keys += 1;
                    let what = if pressed { "apertada" } else { "solta" };
                    ostd::debug::print_fmt(format_args!("inputd: tecla {code:#x} {what}"));
                    osvc::REPLY_OK
                }
                Some(Event::Pointer { .. }) => {
                    moves += 1;
                    osvc::REPLY_OK
                }
                None => osvc::REPLY_BAD_MESSAGE,
            }
        } else {
            osvc::REPLY_UNKNOWN_METHOD
        };
        let _ = ipc::send(reply, &Message::new(label, &[]), 0);
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
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let Some(ep) = s
        .boot
        .provided(oinput::interface_id())
        .map(Handle::from_raw)
    else {
        ostd::debug::print("inputd: descritor sem o endpoint do Sink");
        ostd::thread::exit()
    };
    if s.ready().is_ok() {
        let _ = serve(ep, quota);
    }
    ostd::thread::exit()
}
