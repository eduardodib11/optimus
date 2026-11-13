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
/// Quanto o laço espera um pedido antes de olhar as faltas de DMA (ADR
/// 0051, item 6: sem segunda thread, só o endpoint e a notificação).
const POLL_NS: u64 = 50_000_000;
/// Faltas de DMA de um mesmo driver aceitas na janela [`FAULT_WINDOW_NS`];
/// a seguinte o deixa parado (ADR 0051, item 4).
const MAX_FAULTS: usize = 3;
const FAULT_WINDOW_NS: u64 = 60_000_000_000;

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
    /// Notificação das faltas de DMA (um bit por driver).
    faults: Handle,
    /// Instantes das faltas recentes de cada driver.
    history: Vec<(u32, Vec<u64>)>,
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
        let _ = self.start_gen(id, res, 0);
    }

    /// [`start`](Self::start) com o número da partida (ADR 0051, item 5).
    fn start_gen(&mut self, id: u32, res: &Resources, generation: u32) -> bool {
        let Some(device) = self.device else {
            ostd::debug::print("devmgr: sem kernel:device, driver não parte");
            return false;
        };
        let ecam = self.ecam;
        if self.bound.iter().any(|b| b.driver == id) {
            ostd::debug::print("devmgr: driver já ligado a outro nó");
            return false;
        }
        match bind::start(&mut self.s, device, ecam, self.faults, id, res, generation) {
            Ok(b) => {
                ostd::debug::print_fmt(format_args!(
                    "devmgr: driver partiu com {} recursos",
                    b.originals.len()
                ));
                self.bound.push(b);
                true
            }
            Err(e) => {
                ostd::debug::print_fmt(format_args!("devmgr: driver não partiu: {e:?}"));
                false
            }
        }
    }

    /// Nome do driver `id`, para o log.
    fn driver_name(&self, id: u32) -> &str {
        self.ids
            .iter()
            .position(|&x| x == id)
            .and_then(|i| self.drivers.get(i))
            .map_or("?", |d| d.name.as_str())
    }

    /// Olha as faltas de DMA sinaladas e trata cada driver que faltou.
    fn faulted(&mut self) {
        let bits = ostd::cap::ntfy_poll(self.faults).unwrap_or(0);
        if bits == 0 {
            return;
        }
        let hit: Vec<u32> = self
            .bound
            .iter()
            .filter(|b| bits & bind::fault_bit(b.driver) != 0)
            .map(|b| b.driver)
            .collect();
        for id in hit {
            self.contain(id);
        }
    }

    /// Contém o driver `id` que fez DMA fora do domínio (ADR 0051, itens 3
    /// e 4): o `svcmgr` o para, os recursos dele saem (o domínio morre e a
    /// IOMMU passa a barrar o dispositivo) e, dentro do teto de faltas, o
    /// driver parte de novo com recursos novos.
    fn contain(&mut self, id: u32) {
        let Some(i) = self.bound.iter().position(|b| b.driver == id) else {
            return;
        };
        let b = self.bound.swap_remove(i);
        let name = String::from(self.driver_name(id));
        ostd::debug::print_fmt(format_args!(
            "devmgr: falta de DMA do driver {name}: contido"
        ));
        if let Err(e) = self.s.driver_stop(id) {
            ostd::debug::print_fmt(format_args!("devmgr: driver {name} não parou: {e:?}"));
        }
        // O dispositivo sai do domínio já: sem ele a IOMMU barra todo DMA,
        // mesmo que alguma cópia do domínio ainda não tenha morrido.
        if let (Some(domain), Some(bdf)) = (b.domain, b.res.bdf) {
            let _ = ostd::dev::dma_bind(domain, bdf, false);
        }
        for h in b.originals {
            let _ = ostd::cap::delete(h);
        }
        let now = ostd::time::now_ns();
        let k = self
            .history
            .iter()
            .position(|h| h.0 == id)
            .unwrap_or_else(|| {
                self.history.push((id, Vec::new()));
                self.history.len() - 1
            });
        let times = &mut self.history[k].1;
        times.retain(|&t| now.saturating_sub(t) < FAULT_WINDOW_NS);
        times.push(now);
        if times.len() > MAX_FAULTS {
            ostd::debug::print_fmt(format_args!(
                "devmgr: driver {name} isolado após {} faltas",
                times.len()
            ));
            return;
        }
        if self.start_gen(id, &b.res, b.generation + 1) {
            ostd::debug::print_fmt(format_args!("devmgr: driver {name} reiniciado"));
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
            let deadline = ostd::time::now_ns().saturating_add(POLL_NS);
            let r = match ipc::recv_corpo(ep, reply, &mut self.s.buffer, &mut req, deadline) {
                Ok(r) => r,
                Err(Error::TimedOut) => {
                    self.faulted();
                    continue;
                }
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
            self.faulted();
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
    let Ok(faults) = ostd::cap::create(quota, ObjectType::Notification, 0) else {
        ostd::debug::print("devmgr: sem notificação de faltas de DMA");
        ostd::thread::exit()
    };
    if s.ready().is_ok() {
        let mut d = Devmgr {
            s,
            device,
            ecam,
            drivers,
            ids,
            reg: Registry::new(MAX_NODES),
            bound: Vec::new(),
            faults,
            history: Vec::new(),
        };
        let end = d.serve(ep, quota);
        ostd::debug::print_fmt(format_args!("devmgr: encerrado ({end:?})"));
    }
    ostd::thread::exit()
}
