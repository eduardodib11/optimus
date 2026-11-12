//! `devmgr` (ADR 0042; T-401): serviço de usuário, filho do `svcmgr`, dono
//! dos nós de dispositivo. Atende `optimus.dev.DeviceBus@1`: guarda cada
//! nó publicado no [`odev::Registry`] e escreve no log o nó e o driver que
//! casa com ele.
//!
//! Os drivers ainda não chegam ao `devmgr` (a lista vem do `svcmgr` na
//! próxima etapa da T-401), então todo nó sai "sem driver". Quando o
//! `svcmgr` revoga o endpoint no desligamento, o `devmgr` sai.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use odev::wire::{self, DevError, Method};
use odev::{Bus, Node, Outcome, Registry};
use ostd::ipc::{self, Buffer};
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Teto de nós guardados.
const MAX_NODES: usize = 256;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Escreve o nó e o resultado do casamento.
fn log(node: &Node, res: &wire::Resources, outcome: &Outcome<'_>) {
    let driver = match outcome {
        Outcome::None => "sem driver",
        Outcome::Driver(d) => d.name.as_str(),
        Outcome::Tie(..) => "empate entre drivers",
    };
    let (v, d) = node.pci_id.unwrap_or((0, 0));
    match (node.bus, res.bdf) {
        (Bus::Pci, Some(bdf)) => ostd::debug::print_fmt(format_args!(
            "devmgr: nó {:02x}:{:02x}.{} {v:04x}:{d:04x} {} BARs: {driver}",
            bdf >> 8,
            (bdf >> 3) & 0x1f,
            bdf & 7,
            res.bars.iter().flatten().count()
        )),
        _ => ostd::debug::print_fmt(format_args!(
            "devmgr: nó {:#x} {:?}: {driver}",
            node.id, node.compatible
        )),
    }
}

/// Atende um `publish`; devolve o rótulo e o corpo da resposta.
fn publish(reg: &mut Registry, req: &[u8], out: &mut [u8]) -> (u64, usize) {
    let Ok((node, res)) = wire::decode_publish(req) else {
        return (osvc::REPLY_BAD_MESSAGE, 0);
    };
    let err =
        |e: DevError, out: &mut [u8]| (osvc::REPLY_ERR, wire::encode_error(e, out).unwrap_or(0));
    match reg.publish(node, res) {
        Ok(node) => {
            log(node, &res, &odev::best_match(&[], node));
            (osvc::REPLY_OK, 0)
        }
        Err(e) => err(e, out),
    }
}

fn serve(ep: Handle, quota: Handle, buffer: &mut Buffer) -> Error {
    let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let mut reg = Registry::new(MAX_NODES);
    let mut req = [0u8; wire::MAX_PUBLISH_BYTES];
    let mut out = [0u8; 8];
    loop {
        let r = match ipc::recv_corpo(ep, reply, buffer, &mut req, 0) {
            Ok(r) => r,
            Err(Error::InvalidArgument) => {
                let _ = ipc::send(reply, &ipc::Message::new(osvc::REPLY_BAD_MESSAGE, &[]), 0);
                continue;
            }
            Err(e) => return e,
        };
        let (label, n) = match wire::method_of(r.rotulo) {
            Some(Method::Publish) => publish(&mut reg, &req[..r.corpo], &mut out),
            None => (osvc::REPLY_UNKNOWN_METHOD, 0),
        };
        let _ = ipc::responde_corpo(reply, buffer, label, &out[..n], 0);
    }
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    if let Some(log) = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_KERNEL && c.name_hash == hash(b"debug"))
    {
        ostd::debug::set_log(Handle::from_raw(log.handle));
    }
    let Some(ep) = s.boot.provided(wire::interface_id()).map(Handle::from_raw) else {
        ostd::debug::print("devmgr: descritor sem o endpoint do DeviceBus");
        ostd::thread::exit()
    };
    if s.ready().is_ok() {
        let end = serve(ep, quota, &mut s.buffer);
        ostd::debug::print_fmt(format_args!("devmgr: encerrado ({end:?})"));
    }
    ostd::thread::exit()
}
