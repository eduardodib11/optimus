//! `acpid` como serviço (T-405; ADR 0045): recebe do kernel uma cópia só
//! de leitura da DSDT (`kernel:acpi`), percorre o AML com os limites de
//! [`acpid::Limits`] e publica ao `devmgr`, pelo `DeviceBus`, cada
//! dispositivo com `_HID` e recursos legados (portas ou IRQ) no `_CRS`.
//! `compatible` sai de `_HID` e `_CID` (item 4).
//!
//! Não toca em hardware: sem portas, sem MMIO e sem cota de dispositivo.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use acpid::{Device, Id, Limits, Resource};
use odev::wire::{self, Ports, Resources};
use odev::{Bus, Node};
use ostd::ipc::{self, Buffer};
use ostd::kabi::Handle;
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
/// Onde a DSDT fica mapeada.
const DSDT_VA: u64 = 0x20_0000_0000;
/// Maior DSDT que o kernel entrega.
const MAX_DSDT: u64 = 64 << 10;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Mapeia a tabela inteira: primeiro só o cabeçalho, para saber o tamanho.
fn map_table(object: Handle) -> Option<Mapping> {
    let len = {
        let head = Mapping::new(SELF, object, DSDT_VA, 4096, 0).ok()?;
        u64::from(head.read32(4)?)
    };
    if !(acpid::HEADER_LEN as u64..=MAX_DSDT).contains(&len) {
        return None;
    }
    Mapping::new(SELF, object, DSDT_VA, len.next_multiple_of(4096), 0).ok()
}

/// O nó de um `Device`, se ele tiver `_HID` e portas ou IRQ. O id estável
/// é o hash do caminho, com o bit 31 ligado para não colidir com os BDFs.
fn node(d: &Device<'_>) -> Option<(Node, [Option<Id>; 2], Resources)> {
    let hid = d.hid?;
    let mut res = Resources::default();
    let (mut np, mut ni) = (0, 0);
    for r in d.resources() {
        match r {
            Resource::Io { base, len } if np < wire::MAX_LEGACY && len > 0 => {
                res.ports[np] = Some(Ports { base, count: len });
                np += 1;
            }
            Resource::Irq { mask } => {
                for irq in (0u8..16).filter(|i| mask & (1 << i) != 0) {
                    if ni < wire::MAX_LEGACY {
                        res.irqs[ni] = Some(irq);
                        ni += 1;
                    }
                }
            }
            _ => {}
        }
    }
    if np == 0 && ni == 0 {
        return None;
    }
    let node = Node {
        id: hash(d.path[..d.depth].as_flattened()) | 0x8000_0000,
        bus: Bus::Acpi,
        pci_id: None,
        class: None,
        // Sem heap: as strings vão por `encode_publish_names`.
        compatible: alloc::vec::Vec::new(),
    };
    Some((node, [Some(hid), d.cid], res))
}

fn publish(bus: Handle, buffer: &mut Buffer, node: &Node, names: &[&str], res: &Resources) -> bool {
    let mut req = [0u8; wire::MAX_PUBLISH_BYTES];
    let mut out = [0u8; 8];
    let Ok(n) = wire::encode_publish_names(node, names, res, &mut req) else {
        return false;
    };
    let deadline = ostd::time::now_ns().saturating_add(PUBLISH_NS);
    let label = wire::label(wire::Method::Publish);
    matches!(
        ipc::call_corpo(bus, buffer, label, &req[..n], &mut out, deadline),
        Ok((osvc::REPLY_OK, _))
    )
}

fn run(s: &mut Session) -> Result<(), &'static str> {
    let cap = |kind: u8, name: u32| {
        s.boot
            .caps()
            .iter()
            .find(|c| c.kind == kind && c.name_hash == name)
            .map(|c| Handle::from_raw(c.handle))
    };
    let dsdt = cap(KIND_KERNEL, hash(b"acpi")).ok_or("sem kernel:acpi")?;
    let bus = cap(KIND_SVC, wire::interface_id());
    let table = map_table(dsdt).ok_or("DSDT não mapeia")?;
    let (header, aml) = acpid::table_body(table.bytes()).map_err(|_| "DSDT inválida")?;
    let (mut found, mut sent) = (0u32, 0u32);
    let result = acpid::scan(aml, Limits::default(), |d| {
        found += 1;
        let Some((node, ids, res)) = node(d) else {
            return;
        };
        let mut names = [""; 2];
        let mut n = 0;
        for id in ids.iter().flatten() {
            if let Ok(s) = core::str::from_utf8(id.as_bytes()) {
                names[n] = s;
                n += 1;
            }
        }
        let name = names[0];
        let ports = res.ports.iter().flatten().count();
        let irqs = res.irqs.iter().flatten().count();
        ostd::debug::print_fmt(format_args!("acpid: {name}: {ports} portas, {irqs} IRQs"));
        if bus.is_some_and(|b| publish(b, &mut s.buffer, &node, &names[..n], &res)) {
            sent += 1;
        }
    });
    let bytes = header.length;
    ostd::debug::print_fmt(format_args!(
        "acpid: DSDT de {bytes} bytes, {found} dispositivos"
    ));
    ostd::debug::print_fmt(format_args!("acpid: {sent} nós publicados ao devmgr"));
    if let Err(e) = result {
        // O que já saiu continua válido (ADR 0045, item 2).
        ostd::debug::print_fmt(format_args!("acpid: varredura parou: {e:?}"));
    }
    Ok(())
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
    if let Err(e) = run(&mut s) {
        ostd::debug::print_fmt(format_args!("acpid: {e}"));
    }
    // Como o `pcid`: publica, avisa `ready` e sai.
    let _ = s.ready();
    ostd::thread::exit()
}
