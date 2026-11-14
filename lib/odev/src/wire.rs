//! `optimus.dev.DeviceBus@1` no fio do OIDL (ADR 0033; ADR 0042, item 1):
//! o `pcid` e o `acpid` publicam nós ao `devmgr`. A especificação está em
//! `idl/optimus/dev.oidl`; este código à mão vale até os stubs gerados.
//!
//! Cabeça de `publish(node: Node)`, na ordem da declaração: `id: u32`,
//! `bus: u8`, `flags: u8`, `vendor: u16`, `device: u16`, `class: u8`,
//! `subclass: u8`, `prog_if: u8`, `bdf: u16`, `msix: u16`,
//! `bars: vec<Bar, 6>`, `ports: vec<Ports, 4>`, `irqs: vec<u8, 4>` e
//! `compatible: vec<string<63>, 8>`.

use alloc::string::String;
use alloc::vec::Vec;

use oidl_rt::{Error, Reader, Result, Writer};

use crate::{Bus, Class, Node};

/// Métodos de `DeviceBus`, pelo ordinal da declaração.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Method {
    /// `publish(node) -> result<(), DevError>`.
    Publish = 0,
    /// `publish_routes(routes) -> result<(), DevError>`.
    PublishRoutes = 1,
}

/// `DevError` no fio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DevError {
    /// Já existe um nó com esse id.
    Duplicate = 0,
    /// O `devmgr` não guarda mais nós.
    Full = 1,
}

impl DevError {
    /// Do byte do fio.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Duplicate,
            1 => Self::Full,
            _ => return None,
        })
    }
}

/// `interface_id` de `optimus.dev.DeviceBus@1` (ADR 0033).
#[must_use]
pub fn interface_id() -> u32 {
    let h = optcrypt::blake3::hash(b"optimus.dev.DeviceBus@1");
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Rótulo do pedido de `m` (`minor_min` 0).
#[must_use]
pub fn label(m: Method) -> u64 {
    (u64::from(interface_id()) << 32) | m as u64
}

/// Método de um rótulo de pedido, se for desta interface.
#[must_use]
pub fn method_of(label: u64) -> Option<Method> {
    if label >> 32 != u64::from(interface_id()) || (label >> 16) & 0xFFFF != 0 {
        return None;
    }
    match label & 0xFFFF {
        0 => Some(Method::Publish),
        1 => Some(Method::PublishRoutes),
        _ => None,
    }
}

/// Uma rota `INTx` do `_PRT`: o pino `pin` (0 é INTA) do dispositivo
/// `device` da ponte PCI chega ao `gsi` (T-513).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrqRoute {
    /// Dispositivo PCI no barramento.
    pub device: u16,
    /// Pino: 0 é INTA, 3 é INTD.
    pub pin: u8,
    /// GSI do IOAPIC.
    pub gsi: u32,
}

/// Teto de rotas num `publish_routes` (o q35 tem 32 dispositivos × 4 pinos).
pub const MAX_ROUTES: usize = 128;
/// Bytes de uma `IrqRoute` no fio.
const ROUTE_BYTES: usize = 8;
/// Maior corpo de `publish_routes`.
pub const MAX_ROUTES_BYTES: usize = 8 + MAX_ROUTES * ROUTE_BYTES;

/// Codifica o pedido de `publish_routes`.
///
/// # Errors
/// [`Error::TooLarge`] acima de [`MAX_ROUTES`] ou sem espaço em `out`.
pub fn encode_routes(routes: &[IrqRoute], out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out, 8)?;
    let at = w.vec(routes.len(), ROUTE_BYTES, MAX_ROUTES)?;
    for (k, r) in routes.iter().enumerate() {
        w.seek(at + k * ROUTE_BYTES);
        w.u16(r.device)?;
        w.u8(r.pin)?;
        w.u32(r.gsi)?;
    }
    Ok(w.finish())
}

/// Decodifica o pedido de `publish_routes`.
///
/// # Errors
/// [`Error::BadMessage`] para corpo fora do formato ou pino acima de 3.
pub fn decode_routes(body: &[u8]) -> Result<Vec<IrqRoute>> {
    let mut r = Reader::new(body, 8)?;
    let elems = r.vec(MAX_ROUTES, ROUTE_BYTES)?;
    let mut out = Vec::with_capacity(elems.count());
    for i in 0..elems.count() {
        r.seek(elems.off() + i * ROUTE_BYTES);
        let route = IrqRoute {
            device: r.u16()?,
            pin: r.u8()?,
            gsi: r.u32()?,
        };
        if route.pin > 3 {
            return Err(Error::BadMessage);
        }
        out.push(route);
    }
    r.finish()?;
    Ok(out)
}

/// Um BAR do nó.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bar {
    /// Faixa de portas de E/S (senão, janela de memória).
    pub io: bool,
    /// Prefetchable.
    pub prefetch: bool,
    /// Endereço físico ou primeira porta.
    pub base: u64,
    /// Tamanho em bytes ou em portas.
    pub size: u64,
}

/// Uma faixa de portas de E/S do nó (ADR 0049, item 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    /// Primeira porta.
    pub base: u16,
    /// Quantidade de portas.
    pub count: u16,
}

/// Recursos do nó (ADR 0042, item 2) e o que o `devmgr` precisa para
/// montar as capabilities do driver. Não aloca, para o `pcid` publicar
/// sem heap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Resources {
    /// Endereço PCI (`bus << 8 | dev << 3 | fn`), quando houver.
    pub bdf: Option<u16>,
    /// BARs presentes, pelo índice do registrador.
    pub bars: [Option<Bar>; MAX_BARS],
    /// Tem a capability MSI.
    pub msi: bool,
    /// Entradas da tabela MSI-X (0 = sem MSI-X).
    pub msix: u16,
    /// Faixas de portas de E/S (nós legados), sem buracos.
    pub ports: [Option<Ports>; MAX_LEGACY],
    /// IRQs ISA (nós legados), sem buracos.
    pub irqs: [Option<u8>; MAX_LEGACY],
}

/// Teto de faixas de portas e de IRQs ISA.
pub const MAX_LEGACY: usize = 4;

/// Teto de BARs.
pub const MAX_BARS: usize = 6;
/// Teto de strings `compatible`.
pub const MAX_COMPATIBLE: usize = 8;
/// Teto de cada string `compatible`.
pub const MAX_NAME: usize = 63;
/// Cabeça de `Node`.
const NODE_HEAD: usize = 52;
/// Bytes de um `Bar` no fio.
const BAR_BYTES: usize = 24;
/// Maior corpo de `publish`.
pub const MAX_PUBLISH_BYTES: usize =
    56 + MAX_BARS * BAR_BYTES + MAX_LEGACY * 4 + 8 + MAX_COMPATIBLE * (8 + 64);

const HAS_PCI_ID: u8 = 1;
const HAS_CLASS: u8 = 2;
const HAS_MSI: u8 = 4;
const HAS_BDF: u8 = 8;
const FLAGS: u8 = HAS_PCI_ID | HAS_CLASS | HAS_MSI | HAS_BDF;

/// Codifica o pedido de `publish`.
///
/// # Errors
/// [`Error::TooLarge`] acima dos tetos ou sem espaço em `out`.
pub fn encode_publish(node: &Node, res: &Resources, out: &mut [u8]) -> Result<usize> {
    let mut names = [""; MAX_COMPATIBLE];
    let n = node.compatible.len();
    if n > MAX_COMPATIBLE {
        return Err(Error::TooLarge);
    }
    for (slot, c) in names.iter_mut().zip(&node.compatible) {
        *slot = c;
    }
    encode_publish_names(node, &names[..n], res, out)
}

/// Como [`encode_publish`], com as strings `compatible` em `compatible`
/// no lugar das de `node` (que são ignoradas): quem publica sem heap, como
/// o `acpid`, deixa `node.compatible` vazio.
///
/// # Errors
/// Os de [`encode_publish`].
pub fn encode_publish_names(
    node: &Node,
    compatible: &[&str],
    res: &Resources,
    out: &mut [u8],
) -> Result<usize> {
    let mut w = Writer::new(out, NODE_HEAD)?;
    let (vendor, device) = node.pci_id.unwrap_or((0, 0));
    let class = node.class.unwrap_or(Class {
        class: 0,
        subclass: 0,
        prog_if: 0,
    });
    let flags = if node.pci_id.is_some() { HAS_PCI_ID } else { 0 }
        | if node.class.is_some() { HAS_CLASS } else { 0 }
        | if res.msi { HAS_MSI } else { 0 }
        | if res.bdf.is_some() { HAS_BDF } else { 0 };
    w.u32(node.id)?;
    w.u8(match node.bus {
        Bus::Pci => 0,
        Bus::Acpi => 1,
    })?;
    w.u8(flags)?;
    w.u16(vendor)?;
    w.u16(device)?;
    w.u8(class.class)?;
    w.u8(class.subclass)?;
    w.u8(class.prog_if)?;
    w.u16(res.bdf.unwrap_or(0))?;
    w.u16(res.msix)?;
    let present = res.bars.iter().flatten().count();
    let bars = w.vec(present, BAR_BYTES, MAX_BARS)?;
    let ports = w.vec(res.ports.iter().flatten().count(), 4, MAX_LEGACY)?;
    let irqs = w.vec(res.irqs.iter().flatten().count(), 1, MAX_LEGACY)?;
    let names = w.vec(compatible.len(), 8, MAX_COMPATIBLE)?;
    let indexed = (0u8..).zip(res.bars).filter_map(|(i, b)| Some((i, b?)));
    for (k, (index, b)) in indexed.enumerate() {
        w.seek(bars + k * BAR_BYTES);
        w.u8(index)?;
        w.bool(b.io)?;
        w.bool(b.prefetch)?;
        w.u64(b.base)?;
        w.u64(b.size)?;
    }
    for (k, p) in res.ports.iter().flatten().enumerate() {
        w.seek(ports + k * 4);
        w.u16(p.base)?;
        w.u16(p.count)?;
    }
    for (k, irq) in res.irqs.iter().flatten().enumerate() {
        w.seek(irqs + k);
        w.u8(*irq)?;
    }
    for (i, c) in compatible.iter().enumerate() {
        w.seek(names + i * 8);
        w.string(c, MAX_NAME)?;
    }
    Ok(w.finish())
}

/// Decodifica o pedido de `publish`.
///
/// # Errors
/// [`Error::BadMessage`] para corpo fora do formato: barramento ou bits de
/// `flags` desconhecidos, BAR com índice acima de 5 ou repetido.
pub fn decode_publish(body: &[u8]) -> Result<(Node, Resources)> {
    let mut r = Reader::new(body, NODE_HEAD)?;
    let id = r.u32()?;
    let bus = match r.u8()? {
        0 => Bus::Pci,
        1 => Bus::Acpi,
        _ => return Err(Error::BadMessage),
    };
    let flags = r.u8()?;
    if flags & !FLAGS != 0 {
        return Err(Error::BadMessage);
    }
    let (vendor, device) = (r.u16()?, r.u16()?);
    let (class, subclass, prog_if) = (r.u8()?, r.u8()?, r.u8()?);
    let (bdf, msix) = (r.u16()?, r.u16()?);
    let bar_elems = r.vec(MAX_BARS, BAR_BYTES)?;
    let port_elems = r.vec(MAX_LEGACY, 4)?;
    let irq_elems = r.vec(MAX_LEGACY, 1)?;
    let name_elems = r.vec(MAX_COMPATIBLE, 8)?;
    let mut bars = [None; MAX_BARS];
    for i in 0..bar_elems.count() {
        r.seek(bar_elems.off() + i * BAR_BYTES);
        let slot = bars
            .get_mut(usize::from(r.u8()?))
            .filter(|b| b.is_none())
            .ok_or(Error::BadMessage)?;
        *slot = Some(Bar {
            io: r.bool()?,
            prefetch: r.bool()?,
            base: r.u64()?,
            size: r.u64()?,
        });
    }
    let mut ports = [None; MAX_LEGACY];
    for (i, slot) in ports.iter_mut().enumerate().take(port_elems.count()) {
        r.seek(port_elems.off() + i * 4);
        *slot = Some(Ports {
            base: r.u16()?,
            count: r.u16()?,
        });
    }
    let mut irqs = [None; MAX_LEGACY];
    for (i, slot) in irqs.iter_mut().enumerate().take(irq_elems.count()) {
        r.seek(irq_elems.off() + i);
        *slot = Some(r.u8()?);
    }
    let mut compatible = Vec::with_capacity(name_elems.count());
    for i in 0..name_elems.count() {
        r.seek(name_elems.off() + i * 8);
        compatible.push(String::from(r.string(MAX_NAME)?));
    }
    r.finish()?;
    let node = Node {
        id,
        bus,
        pci_id: (flags & HAS_PCI_ID != 0).then_some((vendor, device)),
        class: (flags & HAS_CLASS != 0).then_some(Class {
            class,
            subclass,
            prog_if,
        }),
        compatible,
    };
    let res = Resources {
        bdf: (flags & HAS_BDF != 0).then_some(bdf),
        bars,
        msi: flags & HAS_MSI != 0,
        msix,
        ports,
        irqs,
    };
    Ok((node, res))
}

/// Codifica um `DevError` (corpo de uma resposta `Err`).
///
/// # Errors
/// [`Error::TooLarge`] sem espaço em `out`.
pub fn encode_error(e: DevError, out: &mut [u8]) -> Result<usize> {
    let mut w = Writer::new(out, 1)?;
    w.u8(e as u8)?;
    Ok(w.finish())
}

/// Decodifica o corpo de uma resposta `Err`.
///
/// # Errors
/// [`Error::BadMessage`] para corpo fora do formato.
pub fn decode_error(body: &[u8]) -> Result<DevError> {
    let mut r = Reader::new(body, 1)?;
    let v = r.u8()?;
    r.finish()?;
    DevError::from_u8(v).ok_or(Error::BadMessage)
}

#[cfg(test)]
mod tests;
