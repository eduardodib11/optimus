//! `pcid` (ADR 0043; T-402): processo de usuário que só tem a janela ECAM
//! (`kernel:ecam`). Mapeia um barramento por vez (1 MiB), varre tudo com
//! [`opci::scan`] e escreve cada função no log no formato do `lspci -n`.
//!
//! Não liga bus master (item 4) e não cria objetos de MMIO: cada função vai
//! como nó ao `devmgr` pelo `optimus.dev.DeviceBus@1` (ADR 0042, item 1),
//! e é ele que entrega os BARs ao driver casado.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use odev::wire::{self, Bar, Resources};
use odev::{Bus, Class, Node};
use ostd::ipc::{self, Buffer};
use ostd::kabi::Handle;
use ostd::kabi::vm::WRITE;
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// `kind` de um `svc:` no descritor.
const KIND_SVC: u8 = 1;
/// Quanto esperar o `devmgr` em cada `publish`, em ns.
const PUBLISH_NS: u64 = 1_000_000_000;
/// Onde o barramento atual fica mapeado.
const BUS_VA: u64 = 0x20_0000_0000;
/// Bytes de configuração de um barramento (32 dispositivos × 8 funções ×
/// 4 KiB).
const BUS_BYTES: u64 = 1 << 20;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// A janela ECAM, com um barramento mapeado de cada vez.
struct Ecam {
    object: Handle,
    /// Barramento mapeado; `(bus, None)` lembra que ele não mapeia.
    current: Option<(u8, Option<Mapping>)>,
}

impl Ecam {
    /// O mapeamento do barramento `bus`, trocando o anterior.
    fn bus(&mut self, bus: u8) -> Option<&mut Mapping> {
        if self.current.as_ref().is_none_or(|(b, _)| *b != bus) {
            self.current = None;
            let offset = u64::from(bus) * BUS_BYTES;
            let map = Mapping::new_at(SELF, self.object, BUS_VA, offset, BUS_BYTES, WRITE).ok();
            self.current = Some((bus, map));
        }
        self.current.as_mut().and_then(|(_, m)| m.as_mut())
    }
}

/// Deslocamento de `offset` da função `bdf` dentro do barramento dela.
fn at(bdf: opci::Bdf, offset: u16) -> usize {
    let within = bdf.ecam_offset() & (BUS_BYTES - 1);
    usize::try_from(within).unwrap_or(usize::MAX) + usize::from(offset & 0xFFC)
}

impl opci::Config for Ecam {
    fn read(&mut self, bdf: opci::Bdf, offset: u16) -> u32 {
        self.bus(bdf.bus)
            .and_then(|m| m.read32(at(bdf, offset)))
            .unwrap_or(u32::MAX)
    }

    fn write(&mut self, bdf: opci::Bdf, offset: u16, value: u32) {
        if let Some(m) = self.bus(bdf.bus) {
            m.write32(at(bdf, offset), value);
        }
    }
}

/// Varre os barramentos que a janela cobre (um barramento fora dela não
/// mapeia e lê como ausente) e entrega cada função a `found`, na hora,
/// sem guardar a lista (o `pcid` não usa heap).
fn run(ecam: Handle, mut found: impl FnMut(&opci::Function)) {
    let mut cfg = Ecam {
        object: ecam,
        current: None,
    };
    opci::scan(&mut cfg, u8::MAX, |f| {
        ostd::debug::print_fmt(format_args!("pcid: {f}"));
        found(f);
    });
}

/// O nó de dispositivo de uma função (ADR 0043, item 3): o id estável é o
/// próprio endereço no grupo de segmentos 0.
fn node(f: &opci::Function) -> (Node, Resources) {
    let bdf = u16::from(f.bdf.bus) << 8 | u16::from(f.bdf.dev) << 3 | u16::from(f.bdf.func);
    let (class, subclass, prog_if) = f.class;
    let bars = f.bars.map(|b| match b {
        opci::Bar::None => None,
        opci::Bar::Memory {
            base,
            size,
            prefetch,
            ..
        } => Some(Bar {
            io: false,
            prefetch,
            base,
            size,
        }),
        opci::Bar::Io { base, size } => Some(Bar {
            io: true,
            prefetch: false,
            base: base.into(),
            size: size.into(),
        }),
    });
    let node = Node {
        id: u32::from(bdf),
        bus: Bus::Pci,
        pci_id: Some((f.vendor, f.device)),
        class: Some(Class {
            class,
            subclass,
            prog_if,
        }),
        compatible: alloc::vec::Vec::new(),
    };
    let res = Resources {
        bdf: Some(bdf),
        bars,
        msi: f.caps.msi.is_some(),
        msix: f.caps.msix.map_or(0, |m| m.entries),
    };
    (node, res)
}

/// O `DeviceBus` do `devmgr`, para publicar as funções.
struct Publisher<'a> {
    bus: Handle,
    buffer: &'a mut Buffer,
    accepted: usize,
}

impl Publisher<'_> {
    /// Publica a função ao `devmgr`.
    fn publish(&mut self, f: &opci::Function) {
        let mut req = [0u8; wire::MAX_PUBLISH_BYTES];
        let mut out = [0u8; 8];
        let (node, res) = node(f);
        let Ok(n) = wire::encode_publish(&node, &res, &mut req) else {
            return;
        };
        let deadline = ostd::time::now_ns().saturating_add(PUBLISH_NS);
        let label = wire::label(wire::Method::Publish);
        match ipc::call_corpo(self.bus, self.buffer, label, &req[..n], &mut out, deadline) {
            Ok((osvc::REPLY_OK, _)) => self.accepted += 1,
            Ok((_, m)) => ostd::debug::print_fmt(format_args!(
                "pcid: devmgr recusou {}: {:?}",
                f.bdf,
                wire::decode_error(&out[..m])
            )),
            Err(e) => ostd::debug::print_fmt(format_args!("pcid: publish falhou: {e:?}")),
        }
    }
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
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
    let Some(ecam) = kernel_cap(b"ecam") else {
        ostd::debug::print("pcid: sem kernel:ecam");
        ostd::thread::exit()
    };
    let bus = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_SVC && c.name_hash == wire::interface_id())
        .map(|c| Handle::from_raw(c.handle));
    if bus.is_none() {
        ostd::debug::print("pcid: sem o DeviceBus do devmgr");
    }
    let mut publisher = bus.map(|bus| Publisher {
        bus,
        buffer: &mut s.buffer,
        accepted: 0,
    });
    let mut count = 0;
    run(ecam, |f| {
        count += 1;
        if let Some(p) = publisher.as_mut() {
            p.publish(f);
        }
    });
    ostd::debug::print_fmt(format_args!("pcid: {count} funções"));
    if let Some(p) = publisher {
        let n = p.accepted;
        ostd::debug::print_fmt(format_args!("pcid: {n} nós publicados ao devmgr"));
    }
    // Publicou tudo: avisa `ready` e sai (`restart = "never"`). Esperar
    // numa notificação da própria tabela prenderia o processo num ciclo
    // thread ↔ `CapSpace` depois do fim.
    let _ = s.ready();
    ostd::thread::exit()
}
