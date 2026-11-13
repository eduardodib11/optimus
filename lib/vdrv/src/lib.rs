//! `vdrv`: o que todo driver virtio em processo de usuário repete (ADR 0046).
//!
//! O driver só tem o que o `devmgr` deu (ADR 0050): `cfg`, `barN`, `irqN` e
//! `dma`. Aqui ficam a busca desses recursos pelo nome, as regiões de
//! registradores e de DMA como [`Mmio`] e [`DmaBuf`] sobre o [`Mapping`] do
//! `ostd`, a leitura das capabilities do virtio no `cfg` e a espera de uma
//! interrupção com prazo.

#![no_std]
#![forbid(unsafe_code)]
// Os casts truncam de propósito: as metades de 32 bits de endereços de 64.
#![allow(clippy::cast_possible_truncation)]

use core::cell::RefCell;

use ostd::kabi::{Handle, timer};
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};
use virtio_core::{DmaBuf, Mmio, cap};

/// `kind` de um recurso de dispositivo no descritor.
const KIND_DEV: u8 = 3;
/// Bits da notificação: a interrupção e o prazo.
const IRQ_BIT: u64 = 1;
const TIMEOUT_BIT: u64 = 2;

/// Hash de um nome de recurso (o mesmo do descritor).
#[must_use]
pub fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// O recurso de dispositivo `name` do descritor (`cfg`, `bar4`, `irq0`...).
#[must_use]
pub fn resource(s: &Session, name: &[u8]) -> Option<Handle> {
    s.boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_DEV && c.name_hash == hash(name))
        .map(|c| Handle::from_raw(c.handle))
}

/// Lê as regiões do virtio do recurso `cfg`, mapeado em `va`.
///
/// # Errors
/// Texto curto para o registro de depuração.
pub fn read_caps(s: &Session, va: u64) -> Result<cap::Caps, &'static str> {
    let cfg = resource(s, b"cfg").ok_or("faltou o cfg")?;
    let mut config = [0u8; 256];
    let map = Mapping::new(SELF, cfg, va, 4096, 0).map_err(|_| "mapear o cfg")?;
    config.copy_from_slice(&map.bytes()[..256]);
    cap::find(&config).map_err(|_| "capabilities do virtio")
}

/// Mapeia em `va` o BAR que guarda as regiões `regions` (todas no mesmo BAR,
/// com o nome `barN`).
///
/// # Errors
/// Texto curto para o registro de depuração.
pub fn map_bar(
    s: &Session,
    va: u64,
    regions: &[cap::Region],
) -> Result<RefCell<Mapping>, &'static str> {
    let bar = regions.first().ok_or("sem regiões")?.bar;
    if regions.iter().any(|r| r.bar != bar) {
        return Err("regiões em BARs diferentes");
    }
    let end = regions
        .iter()
        .map(|r| u64::from(r.offset) + u64::from(r.length))
        .max()
        .unwrap_or(0);
    let handle = resource(s, &[b'b', b'a', b'r', b'0' + bar]).ok_or("faltou o BAR")?;
    Mapping::new(
        SELF,
        handle,
        va,
        end.next_multiple_of(4096),
        ostd::kabi::vm::WRITE,
    )
    .map(RefCell::new)
    .map_err(|_| "mapear o BAR")
}

/// Uma região de registradores dentro do BAR mapeado.
pub struct Regs<'a> {
    map: &'a RefCell<Mapping>,
    base: usize,
}

impl<'a> Regs<'a> {
    /// A região que começa em `base` no BAR.
    #[must_use]
    pub const fn new(map: &'a RefCell<Mapping>, base: usize) -> Self {
        Self { map, base }
    }
}

impl Mmio for Regs<'_> {
    fn read8(&self, off: usize) -> u8 {
        self.map.borrow().read8(self.base + off).unwrap_or(0xFF)
    }
    fn read16(&self, off: usize) -> u16 {
        self.map.borrow().read16(self.base + off).unwrap_or(0xFFFF)
    }
    fn read32(&self, off: usize) -> u32 {
        self.map
            .borrow()
            .read32(self.base + off)
            .unwrap_or(u32::MAX)
    }
    fn write8(&self, off: usize, v: u8) {
        self.map.borrow_mut().write8(self.base + off, v);
    }
    fn write16(&self, off: usize, v: u16) {
        self.map.borrow_mut().write16(self.base + off, v);
    }
    fn write32(&self, off: usize, v: u32) {
        self.map.borrow_mut().write32(self.base + off, v);
    }
}

/// A memória da fila, compartilhada com o dispositivo (uma página).
pub struct Dma<'a> {
    map: &'a RefCell<Mapping>,
    addr: u64,
}

impl<'a> Dma<'a> {
    /// `map` é a página; `addr` o endereço que o dispositivo usa.
    #[must_use]
    pub const fn new(map: &'a RefCell<Mapping>, addr: u64) -> Self {
        Self { map, addr }
    }
}

impl DmaBuf for Dma<'_> {
    fn len(&self) -> usize {
        4096
    }
    fn device_addr(&self) -> u64 {
        self.addr
    }
    fn read16(&self, off: usize) -> u16 {
        self.map.borrow().read16(off).unwrap_or(0)
    }
    fn read32(&self, off: usize) -> u32 {
        self.map.borrow().read32(off).unwrap_or(0)
    }
    fn write16(&self, off: usize, v: u16) {
        self.map.borrow_mut().write16(off, v);
    }
    fn write32(&self, off: usize, v: u32) {
        self.map.borrow_mut().write32(off, v);
    }
    fn write64(&self, off: usize, v: u64) {
        let mut m = self.map.borrow_mut();
        m.write32(off, v as u32);
        m.write32(off + 4, (v >> 32) as u32);
    }
    fn barrier(&self) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// A interrupção do driver: o `Interrupt`, a notificação e o timer do prazo.
#[derive(Clone, Copy)]
pub struct Irq {
    /// O `Interrupt` (`irq0`).
    pub irq: Handle,
    /// A notificação a que ele está ligado.
    pub ntfy: Handle,
    /// O timer do prazo.
    pub timer: Handle,
}

impl Irq {
    /// Liga `irq` a uma notificação nova e cria o timer, com `quota`.
    ///
    /// # Errors
    /// Texto curto para o registro de depuração.
    pub fn new(quota: Handle, irq: Handle) -> Result<Self, &'static str> {
        let ntfy = ostd::cap::create(quota, ostd::kabi::ObjectType::Notification, 0)
            .map_err(|_| "notificação")?;
        let timer =
            ostd::cap::create(quota, ostd::kabi::ObjectType::Timer, 0).map_err(|_| "timer")?;
        ostd::cap::bind_notify(irq, ntfy, 0).map_err(|_| "ligar a interrupção")?;
        Ok(Self { irq, ntfy, timer })
    }

    /// Espera a interrupção por até `timeout_ns` e a confirma.
    ///
    /// # Errors
    /// Texto curto; "a interrupção não chegou antes do prazo" se vencer.
    pub fn wait(&self, timeout_ns: u64) -> Result<(), &'static str> {
        ostd::cap::arm_timer(
            self.timer,
            self.ntfy,
            TIMEOUT_BIT,
            timeout_ns,
            0,
            timer::RELATIVE,
        )
        .map_err(|_| "armar o prazo")?;
        let bits = ostd::cap::ntfy_wait(self.ntfy).map_err(|_| "esperar a interrupção")?;
        ostd::cap::disarm_timer(self.timer, self.ntfy).map_err(|_| "desarmar o prazo")?;
        ostd::dev::irq_ack(self.irq).map_err(|_| "irq_ack")?;
        if bits & IRQ_BIT == 0 {
            return Err("a interrupção não chegou antes do prazo");
        }
        Ok(())
    }
}
