//! `logd` como serviço (T-357; ADR 0036, itens 4 e 6): sobe pelo `svcmgr`,
//! mapeia só para leitura o anel do log do kernel (`kernel:log`) e guarda
//! as linhas no [`ologd::Store`], com o serviço [`ologd::KERNEL`].
//!
//! O despertar pelo `obj_bind_notify` da `DebugLog` ainda não existe: o
//! `logd` olha o anel a cada [`TICK_NS`], esperando no próprio endpoint
//! (`optimus.log.Log@1`, cujos métodos vêm com o `register` dos anéis dos
//! serviços). Quando o `svcmgr` revoga o endpoint, o `logd` sai.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::ring::{Watched, Watcher};
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// De quanto em quanto o `logd` olha o anel do kernel, em ns.
const TICK_NS: u64 = 20_000_000;
/// Onde o anel do kernel é mapeado.
const RING_VA: u64 = 0x2000_0000;
/// Linhas guardadas (todas as fontes).
const CAPACITY: usize = 4096;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Lê tudo o que há no anel; devolve as linhas guardadas.
fn drain(w: &mut Watcher, store: &mut ologd::Store, buf: &mut [u8]) -> u64 {
    let mut n = 0;
    loop {
        match w.next(buf) {
            Watched::Empty => return n,
            Watched::Lost(bytes) => {
                let _ = store.count_lost(ologd::KERNEL, bytes.div_ceil(8));
            }
            Watched::Record(kind, len) if kind == ologd::record::KIND_LOG => {
                if let Ok(r) = ologd::record::decode(&buf[..len])
                    && store
                        .ingest_at(ologd::KERNEL, r.level, r.ts_ns, r.msg)
                        .is_ok()
                {
                    n += 1;
                }
            }
            Watched::Record(..) => {}
        }
    }
}

fn serve(ep: Handle, quota: Handle, mut w: Watcher) -> Result<(), Error> {
    let reply = ostd::cap::create(quota, ObjectType::Reply, 0)?;
    let mut store = ologd::Store::new(CAPACITY);
    let mut buf = [0u8; ologd::record::MAX_PAYLOAD];
    let first = drain(&mut w, &mut store, &mut buf);
    ostd::debug::print_fmt(format_args!(
        "logd: {first} linhas do kernel guardadas na partida"
    ));
    let mut total = first;
    let end = loop {
        let deadline = ostd::time::now_ns().saturating_add(TICK_NS);
        match ipc::recv(ep, reply, deadline) {
            Ok(_) => {
                let _ = ipc::send(reply, &Message::new(osvc::REPLY_UNKNOWN_METHOD, &[]), 0);
            }
            Err(Error::TimedOut) => {}
            Err(e) => break e,
        }
        total += drain(&mut w, &mut store, &mut buf);
    };
    total += drain(&mut w, &mut store, &mut buf);
    ostd::debug::print_fmt(format_args!(
        "logd: encerrado ({end:?}); {total} linhas do kernel, {} bytes perdidos",
        w.lost()
    ));
    Ok(())
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let kernel_cap = |name: &[u8]| {
        s.boot
            .caps()
            .iter()
            .find(|c| c.kind == KIND_KERNEL && c.name_hash == hash(name))
            .map(|c| Handle::from_raw(c.handle))
    };
    if let Some(log) = kernel_cap(b"debug") {
        ostd::debug::set_log(log);
    }
    let ring = kernel_cap(b"log");
    let ep = s
        .boot
        .provided(hash(b"optimus.log.Log@1"))
        .map(Handle::from_raw);
    let (Some(ep), Some(ring)) = (ep, ring) else {
        ostd::debug::print("logd: descritor sem endpoint ou sem kernel:log");
        ostd::thread::exit()
    };
    let w = match Watcher::open(ring, RING_VA, true) {
        Ok(w) => w,
        Err(e) => {
            ostd::debug::print_fmt(format_args!("logd: anel do kernel inválido: {e:?}"));
            ostd::thread::exit()
        }
    };
    if s.ready().is_ok() {
        let _ = serve(ep, quota, w);
    }
    ostd::thread::exit()
}

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
