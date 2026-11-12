//! `devmgr` (ADR 0042; T-401): serviço de usuário, filho do `svcmgr`, dono
//! dos nós de dispositivo. Atende `optimus.dev.DeviceBus@1`: guarda cada
//! nó publicado no [`odev::Registry`] e escreve no log o nó e o driver que
//! casa com ele.
//!
//! Na partida, o `devmgr` lê do `svcmgr` a lista de drivers do conjunto
//! compilado, com as regras de `[match]` (`Supervisor.driver`, 1.1), e casa
//! cada nó com o mais específico (ADR 0042, item 3). Depois de responder a
//! quem publicou, parte o driver casado com os recursos do nó
//! ([`bind`]). Quando o `svcmgr` revoga o endpoint no desligamento, o
//! `devmgr` sai.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use odev::wire::{self, Method, Resources};
use odev::{Bus, Driver, Node, Outcome, Registry, Rule};
use ostd::ipc;
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;

mod bind;

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

/// Os drivers do conjunto compilado, pela ordem do `svcmgr`, com o id de
/// cada um. Uma regra ilegível fica de fora (o `mkmanifest` já as confere).
fn drivers(s: &mut Session) -> (Vec<Driver>, Vec<u32>) {
    let (mut out, mut ids) = (Vec::new(), Vec::new());
    let mut buf = [0u8; osvc::MAX_DRIVER_BYTES];
    let mut index = 0u16;
    while let Ok(info) = s.driver(index, &mut buf) {
        out.push(Driver {
            name: String::from(info.name),
            rules: info.rules().iter().filter_map(|r| Rule::parse(r)).collect(),
        });
        ids.push(info.id);
        index += 1;
        if index >= info.total {
            break;
        }
    }
    (out, ids)
}

/// O `devmgr` em serviço.
struct Devmgr {
    s: Session,
    /// Cota de dispositivo (`kernel:device`) e janela ECAM (`kernel:ecam`).
    device: Option<Handle>,
    ecam: Option<Handle>,
    drivers: Vec<Driver>,
    ids: Vec<u32>,
    reg: Registry,
    bound: Vec<bind::Bound>,
}

impl Devmgr {
    /// Atende um `publish`: o rótulo e o corpo da resposta e, se casou, o
    /// driver a partir com os recursos do nó.
    fn publish(&mut self, req: &[u8], out: &mut [u8]) -> ((u64, usize), Option<(u32, Resources)>) {
        let Ok((node, res)) = wire::decode_publish(req) else {
            return ((osvc::REPLY_BAD_MESSAGE, 0), None);
        };
        match self.reg.publish(node, res) {
            Ok(node) => {
                let outcome = odev::best_match(&self.drivers, node);
                log(node, &res, &outcome);
                let id = match outcome {
                    Outcome::Driver(d) => self
                        .drivers
                        .iter()
                        .position(|x| core::ptr::eq(x, d))
                        .and_then(|i| self.ids.get(i).copied()),
                    _ => None,
                };
                ((osvc::REPLY_OK, 0), id.map(|id| (id, res)))
            }
            Err(e) => (
                (osvc::REPLY_ERR, wire::encode_error(e, out).unwrap_or(0)),
                None,
            ),
        }
    }

    /// Parte o driver `id` com os recursos do nó (depois de responder a
    /// quem publicou).
    fn start(&mut self, id: u32, res: &Resources) {
        let (Some(device), Some(ecam)) = (self.device, self.ecam) else {
            ostd::debug::print("devmgr: sem kernel:device ou kernel:ecam, driver não parte");
            return;
        };
        if self.bound.iter().any(|b| b.driver == id) {
            ostd::debug::print("devmgr: driver já ligado a outro nó");
            return;
        }
        match bind::start(&mut self.s, device, ecam, id, res) {
            Ok(b) => {
                ostd::debug::print_fmt(format_args!(
                    "devmgr: driver partiu com {} recursos",
                    b.originals.len()
                ));
                self.bound.push(b);
            }
            Err(e) => ostd::debug::print_fmt(format_args!("devmgr: driver não partiu: {e:?}")),
        }
    }

    fn serve(&mut self, ep: Handle, quota: Handle) -> Error {
        let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let mut req = [0u8; wire::MAX_PUBLISH_BYTES];
        let mut out = [0u8; 8];
        loop {
            let r = match ipc::recv_corpo(ep, reply, &mut self.s.buffer, &mut req, 0) {
                Ok(r) => r,
                Err(Error::InvalidArgument) => {
                    let _ = ipc::send(reply, &ipc::Message::new(osvc::REPLY_BAD_MESSAGE, &[]), 0);
                    continue;
                }
                Err(e) => return e,
            };
            let ((label, n), start) = match wire::method_of(r.rotulo) {
                Some(Method::Publish) => self.publish(&req[..r.corpo], &mut out),
                None => ((osvc::REPLY_UNKNOWN_METHOD, 0), None),
            };
            let _ = ipc::responde_corpo(reply, &mut self.s.buffer, label, &out[..n], 0);
            if let Some((id, res)) = start {
                self.start(id, &res);
            }
        }
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
    let kernel_cap = |name: &[u8]| {
        s.boot
            .caps()
            .iter()
            .find(|c| c.kind == KIND_KERNEL && c.name_hash == hash(name))
            .map(|c| Handle::from_raw(c.handle))
    };
    let (device, ecam) = (kernel_cap(b"device"), kernel_cap(b"ecam"));
    let (drivers, ids) = drivers(&mut s);
    ostd::debug::print_fmt(format_args!(
        "devmgr: {} drivers no conjunto",
        drivers.len()
    ));
    if s.ready().is_ok() {
        let mut d = Devmgr {
            s,
            device,
            ecam,
            drivers,
            ids,
            reg: Registry::new(MAX_NODES),
            bound: Vec::new(),
        };
        let end = d.serve(ep, quota);
        ostd::debug::print_fmt(format_args!("devmgr: encerrado ({end:?})"));
    }
    ostd::thread::exit()
}
