//! Partida de um driver casado (ADR 0042, item 4; ADR 0043, item 4; ADR
//! 0044, item 3): o `devmgr` cria os recursos do nó com a cota de
//! dispositivo, programa o que só o espaço de configuração faz (MSI, bus
//! master) e os manda ao `svcmgr`, que os entrega ao driver.
//!
//! O driver recebe, no descritor, com `kind` 3 e o hash do nome:
//!
//! - `barN`: o `MemoryObject` de MMIO de cada BAR de memória;
//! - `irq0`...: um `Interrupt` por vetor, já programado na função: até
//!   [`MAX_VECTORS`] entradas de MSI-X, quando existe, senão o vetor MSI;
//! - `dma`: uma cópia só com `MAP` do `DmaDomain` ligado ao BDF.
//!
//! O `devmgr` fica com as originais (o domínio com `BIND`). Revogá-las tira
//! os recursos do driver (item 5).

use alloc::format;
use alloc::vec::Vec;

use odev::wire::Resources;
use ostd::kabi::vm::WRITE;
use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};

/// Onde o espaço de configuração da função fica mapeado.
const CONFIG_VA: u64 = 0x20_0000_0000;
/// Onde a tabela de MSI-X fica mapeada enquanto o `devmgr` a programa.
const TABLE_VA: u64 = 0x20_0010_0000;
/// Vetores de MSI-X por função.
const MAX_VECTORS: usize = 8;
/// Registrador de comando: memória, bus master e `INTx` desligado.
const COMMAND: u16 = 0x04;
const MEMORY_ENABLE: u32 = 1 << 1;
const BUS_MASTER: u32 = 1 << 2;
const INTX_DISABLE: u32 = 1 << 10;

/// Hash de um nome de recurso (o mesmo do descritor).
pub fn name_hash(text: &str) -> u32 {
    let h = optcrypt::blake3::hash(text.as_bytes());
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// O espaço de configuração de uma função só, pela janela ECAM.
struct Function {
    bdf: opci::Bdf,
    map: Mapping,
}

impl Function {
    fn open(ecam: Handle, bdf: u16) -> Result<Self, Error> {
        let [bus, devfn] = bdf.to_be_bytes();
        let bdf = opci::Bdf {
            bus,
            dev: devfn >> 3,
            func: devfn & 7,
        };
        let map = Mapping::new_at(SELF, ecam, CONFIG_VA, bdf.ecam_offset(), 4096, WRITE)?;
        Ok(Self { bdf, map })
    }
}

impl opci::Config for Function {
    fn read(&mut self, bdf: opci::Bdf, offset: u16) -> u32 {
        if bdf != self.bdf {
            return u32::MAX;
        }
        self.map
            .read32(usize::from(offset & 0xFFC))
            .unwrap_or(u32::MAX)
    }

    fn write(&mut self, bdf: opci::Bdf, offset: u16, value: u32) {
        if bdf == self.bdf {
            self.map.write32(usize::from(offset & 0xFFC), value);
        }
    }
}

/// Programa a capability MSI em `at` com um vetor (sem múltiplas
/// mensagens) e a liga.
#[allow(
    clippy::cast_possible_truncation,
    reason = "o endereço vai em duas metades de 32 bits"
)]
fn program_msi(f: &mut Function, at: u16, address: u64, data: u32) {
    use opci::Config;
    let bdf = f.bdf;
    let head = f.read(bdf, at);
    let control = head >> 16;
    let wide = control & (1 << 7) != 0;
    f.write(bdf, at + 4, address as u32);
    let data_at = if wide {
        f.write(bdf, at + 8, (address >> 32) as u32);
        at + 12
    } else {
        at + 8
    };
    f.write(bdf, data_at, data & 0xFFFF);
    // Enable (bit 0) e MME = 0 (um vetor).
    let control = (control & !0x70) | 1;
    f.write(bdf, at, (head & 0xFFFF) | control << 16);
}

/// Liga o MSI-X com a função mascarada, escreve uma entrada da tabela por
/// vetor (desmascarada) e tira a máscara da função. As entradas além de
/// `vectors` ficam mascaradas, como o reset as deixa.
#[allow(
    clippy::cast_possible_truncation,
    reason = "o endereço vai em duas metades de 32 bits"
)]
fn program_msix(
    f: &mut Function,
    x: opci::Msix,
    table: Handle,
    vectors: &[ostd::dev::Msi],
) -> Result<(), Error> {
    use opci::Config;
    let bdf = f.bdf;
    let head = f.read(bdf, x.at);
    let enable_masked = (head & 0xFFFF) | (1 << 31) | (1 << 30);
    f.write(bdf, x.at, enable_masked);
    let start = u64::from(x.table.offset);
    let page = start & !0xFFF;
    let end = start + 16 * vectors.len() as u64;
    let len = (end - page).next_multiple_of(4096);
    let mut map = Mapping::new_at(SELF, table, TABLE_VA, page, len, WRITE)?;
    let base = usize::try_from(start - page).map_err(|_| Error::InvalidArgument)?;
    for (i, m) in vectors.iter().enumerate() {
        let at = base + i * 16;
        map.write32(at, m.address as u32);
        map.write32(at + 4, (m.address >> 32) as u32);
        map.write32(at + 8, m.data);
        map.write32(at + 12, 0);
    }
    drop(map);
    f.write(bdf, x.at, (head & 0xFFFF) | (1 << 31));
    Ok(())
}

/// Os recursos de um driver em vida: as capabilities originais do
/// `devmgr`.
pub struct Bound {
    /// Id do driver no `svcmgr`.
    pub driver: u32,
    /// Originais (revogar tira as cópias do driver).
    pub originals: Vec<Handle>,
}

/// Cria os recursos do nó, liga a função e parte o driver `driver`.
///
/// # Errors
///
/// Os do kernel; `InvalidArgument` para nó sem BDF. Os recursos já
/// criados são apagados.
pub fn start(
    s: &mut Session,
    device: Handle,
    ecam: Handle,
    driver: u32,
    res: &Resources,
) -> Result<Bound, Error> {
    let bdf = res.bdf.ok_or(Error::InvalidArgument)?;
    let mut originals = Vec::new();
    let r = build(s, device, ecam, driver, bdf, res, &mut originals);
    match r {
        Ok(()) => Ok(Bound { driver, originals }),
        Err(e) => {
            for h in originals {
                let _ = ostd::cap::delete(h);
            }
            Err(e)
        }
    }
}

fn build(
    s: &mut Session,
    device: Handle,
    ecam: Handle,
    driver: u32,
    bdf: u16,
    res: &Resources,
    originals: &mut Vec<Handle>,
) -> Result<(), Error> {
    let mut give: Vec<(Handle, u32)> = Vec::new();
    let mut bars = [None; 6];
    for (i, bar) in res.bars.iter().enumerate() {
        if let Some(b) = bar.filter(|b| !b.io) {
            let h = ostd::dev::mmio(device, b.base, b.size)?;
            originals.push(h);
            bars[i] = Some(h);
            give.push((h, name_hash(&format!("bar{i}"))));
        }
    }
    let domain = ostd::cap::create(device, ObjectType::DmaDomain, 0)?;
    originals.push(domain);
    ostd::dev::dma_bind(domain, bdf, true)?;
    let map_only = ostd::cap::mint(domain, Rights::MAP, 0, None)?;
    originals.push(map_only);
    give.push((map_only, name_hash("dma")));
    let mut f = Function::open(ecam, bdf)?;
    let fbdf = f.bdf;
    let caps = opci::probe(&mut f, fbdf)
        .map(|p| p.caps)
        .unwrap_or_default();
    let mut command = MEMORY_ENABLE | BUS_MASTER;
    if let Some(x) = caps.msix {
        // MSI-X primeiro, quando existe (virtio moderno só tem ele).
        let table = bars
            .get(usize::from(x.table.bar))
            .copied()
            .flatten()
            .ok_or(Error::InvalidArgument)?;
        let count = usize::from(x.entries).min(MAX_VECTORS);
        let mut vectors = Vec::with_capacity(count);
        for _ in 0..count {
            let m = ostd::dev::msi(device)?;
            originals.push(m.irq);
            vectors.push(m);
        }
        program_msix(&mut f, x, table, &vectors)?;
        for (i, m) in vectors.iter().enumerate() {
            give.push((m.irq, name_hash(&format!("irq{i}"))));
        }
        command |= INTX_DISABLE;
    } else if let Some(at) = caps.msi.filter(|_| res.msi) {
        let m = ostd::dev::msi(device)?;
        originals.push(m.irq);
        program_msi(&mut f, at, m.address, m.data);
        give.push((m.irq, name_hash("irq0")));
        command |= INTX_DISABLE;
    }
    // Bus master só agora, com o domínio já ligado (ADR 0043, item 4).
    let old = opci::Config::read(&mut f, fbdf, COMMAND);
    opci::Config::write(&mut f, fbdf, COMMAND, (old & 0xFFFF) | command);
    for chunk in give.chunks(osvc::MAX_MSG_CAPS) {
        s.driver_give(driver, chunk)?;
    }
    s.driver_start(driver)
}
