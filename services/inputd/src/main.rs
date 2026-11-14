//! `inputd` (T-406; ADR 0042, item 4): o destino dos eventos de entrada.
//! Sobe pelo `svcmgr`, pega o endpoint de `optimus.input.Sink@1` no
//! descritor e atende `event` dos drivers (o `i8042d`; o `virtio-input` na
//! T-413), que rodam isolados e não são de confiança: evento que não
//! decodifica é recusado.
//!
//! Os eventos entram numa fila com limite ([`oinput::EventQueue`], T-517):
//! o driver nunca espera o cliente, e o que não cabe é descartado e contado.
//! O cliente (o `displayd` e o foco de janela, depois) tira da fila com
//! `poll` ([`oinput::poll_label`]) e recebe também as perdas.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use oinput::{Event, EventQueue};
use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;

/// Eventos que a fila guarda.
const QUEUE: usize = 256;
/// Quantos movimentos do ponteiro vão ao log (os primeiros).
const POINTER_LOG: u64 = 8;

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
    let mut queue = EventQueue::<QUEUE>::new();
    let mut lost_total = 0u64;
    loop {
        let r = match ipc::recv(ep, reply, 0) {
            Ok(r) => r,
            Err(e) => {
                // Uma linha só: o `svcmgr` apaga o processo logo depois de
                // revogar o endpoint.
                ostd::debug::print_fmt(format_args!(
                    "inputd: encerrado ({e:?}); {keys} teclas e {moves} movimentos; {} perdidos",
                    lost_total + queue.take_lost()
                ));
                return e;
            }
        };
        let mut words = [0u64; 5];
        let mut len = 0;
        let label = if oinput::is_event(r.msg.label) {
            match oinput::decode(r.msg.payload()) {
                Some(e) => {
                    match e {
                        Event::Key { code, pressed } => {
                            keys += 1;
                            let what = if pressed { "apertada" } else { "solta" };
                            ostd::debug::print_fmt(format_args!("inputd: tecla {code:#x} {what}"));
                        }
                        Event::Pointer { dx, dy, buttons } => {
                            moves += 1;
                            if moves <= POINTER_LOG {
                                ostd::debug::print_fmt(format_args!(
                                    "inputd: ponteiro dx={dx} dy={dy} botões={buttons:#x}"
                                ));
                            }
                        }
                    }
                    // Cheia: o evento é descartado e contado; o driver não espera.
                    queue.push(e);
                    osvc::REPLY_OK
                }
                None => osvc::REPLY_BAD_MESSAGE,
            }
        } else if oinput::is_poll(r.msg.label) {
            let lost = queue.take_lost();
            lost_total += lost;
            if let Some(e) = queue.pop() {
                let [kind, x, y, z] = oinput::encode(e);
                (words, len) = ([kind, x, y, z, lost], 5);
            } else {
                (words[0], len) = (lost, 1);
            }
            osvc::REPLY_OK
        } else {
            osvc::REPLY_UNKNOWN_METHOD
        };
        let _ = ipc::send(reply, &Message::new(label, &words[..len]), 0);
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
