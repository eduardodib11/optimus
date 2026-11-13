//! `virtio-blk` (T-411; ADR 0042 e 0046): driver de disco virtio moderno
//! em processo de usuário. Só tem o que o `devmgr` deu (`cfg`, o BAR das
//! capabilities, `irq0` e `dma`) e com isso
//!
//! 1. acha as regiões do virtio no `cfg` e mapeia o BAR;
//! 2. negocia as features e monta a fila 0 em memória do `dma`;
//! 3. escreve um setor, lê de volta e confere o BLAKE3 (aceite da T-411).
//!
//! A entrega do `BlockDevice` por IPC vem a seguir.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

use core::cell::RefCell;

use ostd::kabi::vm::WRITE;
use ostd::kabi::{Handle, ObjectType, timer};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};
use virtio_core::{DmaBuf, F_ACCESS_PLATFORM, Mmio, Queue, Seg, Transport, cap};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// `kind` de um recurso de dispositivo.
const KIND_DEV: u8 = 3;
/// Onde o `cfg`, o BAR e as páginas de DMA ficam mapeados.
const CFG_VA: u64 = 0x20_0000_0000;
const BAR_VA: u64 = 0x20_0010_0000;
const QUEUE_VA: u64 = 0x20_0020_0000;
const REQ_VA: u64 = 0x20_0030_0000;
/// IOVAs das páginas da fila e das requisições.
const QUEUE_IOVA: u64 = 0x10_0000;
const REQ_IOVA: u64 = 0x10_1000;
/// Descritores da fila 0.
const QUEUE_SIZE: usize = 8;
/// Na página de requisições: cabeçalho, dados e status.
const HDR_AT: usize = 0;
const DATA_AT: usize = 512;
const STATUS_AT: usize = 1024;
/// Tamanho do setor.
const SECTOR: usize = 512;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
/// Bits da notificação: a MSI-X e o prazo.
const IRQ_BIT: u64 = 1;
const TIMEOUT_BIT: u64 = 2;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Uma região de registradores dentro do BAR mapeado.
struct Regs<'a> {
    map: &'a RefCell<Mapping>,
    base: usize,
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

/// A página da fila, compartilhada com o dispositivo.
struct Dma<'a> {
    map: &'a RefCell<Mapping>,
    addr: u64,
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

/// O disco em uso.
struct Disk<'a> {
    queue: Queue<Dma<'a>, QUEUE_SIZE>,
    notify: Regs<'a>,
    notify_at: usize,
    req: Mapping,
    req_iova: u64,
    irq: Handle,
    ntfy: Handle,
    timer: Handle,
}

impl Disk<'_> {
    /// Uma requisição de um setor; `data` é a origem (escrita) ou o
    /// destino (leitura).
    fn request(&mut self, kind: u32, sector: u64) -> Result<(), &'static str> {
        let Some(bytes) = self.req.bytes_mut() else {
            return Err("página de requisições só de leitura");
        };
        bytes[HDR_AT..HDR_AT + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[HDR_AT + 4..HDR_AT + 8].fill(0);
        bytes[HDR_AT + 8..HDR_AT + 16].copy_from_slice(&sector.to_le_bytes());
        bytes[STATUS_AT] = 0xFF;
        let at = |off: usize| self.req_iova + off as u64;
        let segs = [
            Seg {
                addr: at(HDR_AT),
                len: 16,
                write: false,
            },
            Seg {
                addr: at(DATA_AT),
                len: SECTOR as u32,
                write: kind == T_IN,
            },
            Seg {
                addr: at(STATUS_AT),
                len: 1,
                write: true,
            },
        ];
        self.queue.push(&segs).map_err(|_| "push na fila")?;
        self.notify.write16(self.notify_at, 0);
        ostd::cap::arm_timer(
            self.timer,
            self.ntfy,
            TIMEOUT_BIT,
            1_000_000_000,
            0,
            timer::RELATIVE,
        )
        .map_err(|_| "armar o prazo")?;
        let bits = ostd::cap::ntfy_wait(self.ntfy).map_err(|_| "esperar a MSI-X")?;
        ostd::cap::disarm_timer(self.timer, self.ntfy).map_err(|_| "desarmar o prazo")?;
        ostd::dev::irq_ack(self.irq).map_err(|_| "irq_ack")?;
        if bits & IRQ_BIT == 0 {
            return Err("a MSI-X não chegou antes do prazo");
        }
        match self.queue.pop() {
            Ok(Some(_)) => {}
            Ok(None) => return Err("fila sem cadeia usada"),
            Err(_) => return Err("dispositivo devolveu cadeia inválida"),
        }
        if self.req.bytes()[STATUS_AT] != 0 {
            return Err("status de erro do dispositivo");
        }
        Ok(())
    }
}

/// Escreve o setor 1, lê de volta e confere o BLAKE3 (aceite da T-411).
fn self_test(disk: &mut Disk<'_>) -> Result<(), &'static str> {
    let mut sent = [0u8; SECTOR];
    for (i, b) in sent.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11) ^ 0xa5;
    }
    {
        let Some(bytes) = disk.req.bytes_mut() else {
            return Err("página de requisições só de leitura");
        };
        bytes[DATA_AT..DATA_AT + SECTOR].copy_from_slice(&sent);
    }
    disk.request(T_OUT, 1)?;
    disk.req.bytes_mut().ok_or("página só de leitura")?[DATA_AT..DATA_AT + SECTOR].fill(0);
    disk.request(T_IN, 1)?;
    let got = &disk.req.bytes()[DATA_AT..DATA_AT + SECTOR];
    if optcrypt::blake3::hash(got) != optcrypt::blake3::hash(&sent) {
        return Err("o setor lido difere do escrito");
    }
    Ok(())
}

fn run(s: &Session, quota: Handle) -> Result<(), &'static str> {
    let dev = |name: &[u8]| {
        s.boot
            .caps()
            .iter()
            .find(|c| c.kind == KIND_DEV && c.name_hash == hash(name))
            .map(|c| Handle::from_raw(c.handle))
    };
    let (Some(cfg), Some(irq), Some(domain)) = (dev(b"cfg"), dev(b"irq0"), dev(b"dma")) else {
        return Err("faltou cfg, irq0 ou dma");
    };
    // 1. As regiões do virtio, pelo espaço de configuração.
    let mut config = [0u8; 256];
    {
        let map = Mapping::new(SELF, cfg, CFG_VA, 4096, 0).map_err(|_| "mapear o cfg")?;
        config.copy_from_slice(&map.bytes()[..256]);
    }
    let caps = cap::find(&config).map_err(|_| "capabilities do virtio")?;
    let device_cfg = caps.device.ok_or("sem configuração de dispositivo")?;
    let regions = [caps.common, caps.notify, caps.isr, device_cfg];
    if regions.iter().any(|r| r.bar != caps.common.bar) {
        return Err("regiões em BARs diferentes");
    }
    let end = regions
        .iter()
        .map(|r| u64::from(r.offset) + u64::from(r.length))
        .max()
        .unwrap_or(0);
    let bar_name = [b'b', b'a', b'r', b'0' + caps.common.bar];
    let bar = dev(&bar_name).ok_or("faltou o BAR das capabilities")?;
    let bar_map = Mapping::new(SELF, bar, BAR_VA, end.next_multiple_of(4096), WRITE)
        .map_err(|_| "mapear o BAR")?;
    let bar_map = RefCell::new(bar_map);
    // 2. Memória de DMA: a fila e as requisições.
    let queue_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página da fila")?;
    let req_obj = ostd::cap::create(quota, ObjectType::MemoryObject, 4096)
        .map_err(|_| "página de requisições")?;
    let queue_map = RefCell::new(
        Mapping::new(SELF, queue_obj, QUEUE_VA, 4096, WRITE).map_err(|_| "mapear a fila")?,
    );
    let req = Mapping::new(SELF, req_obj, REQ_VA, 4096, WRITE).map_err(|_| "mapear requisições")?;
    let queue_at = ostd::dev::dma_map(domain, queue_obj, QUEUE_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map da fila")?;
    let req_at = ostd::dev::dma_map(domain, req_obj, REQ_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map de requisições")?;
    // Com IOMMU o `dma_map` devolve a IOVA; sem ela, o físico. Com IOMMU o
    // dispositivo precisa de `ACCESS_PLATFORM` para endereçar por IOVA.
    let required = if queue_at == QUEUE_IOVA {
        F_ACCESS_PLATFORM
    } else {
        0
    };
    // 3. Negociação, fila e `DRIVER_OK`.
    let mut transport = Transport::new(Regs {
        map: &bar_map,
        base: caps.common.offset as usize,
    });
    transport
        .negotiate(F_ACCESS_PLATFORM, required)
        .map_err(|_| "negociar as features")?;
    let dma = Dma {
        map: &queue_map,
        addr: queue_at,
    };
    let (queue, notify_off) = transport
        .setup_queue::<_, QUEUE_SIZE>(0, dma, 0)
        .map_err(|_| "montar a fila 0")?;
    let ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).map_err(|_| "notificação")?;
    let timer = ostd::cap::create(quota, ObjectType::Timer, 0).map_err(|_| "timer")?;
    ostd::cap::bind_notify(irq, ntfy, 0).map_err(|_| "ligar a MSI-X")?;
    transport.driver_ok();
    let device = Regs {
        map: &bar_map,
        base: device_cfg.offset as usize,
    };
    let sectors = u64::from(device.read32(0)) | u64::from(device.read32(4)) << 32;
    ostd::debug::print_fmt(format_args!(
        "virtio-blk: {sectors} setores, features {:#x}",
        transport.features()
    ));
    if sectors < 2 {
        return Err("disco pequeno demais");
    }
    let notify_at =
        caps.notify.offset as usize + usize::from(notify_off) * caps.notify_multiplier as usize;
    let mut disk = Disk {
        queue,
        notify: Regs {
            map: &bar_map,
            base: 0,
        },
        notify_at,
        req,
        req_iova: req_at,
        irq,
        ntfy,
        timer,
    };
    self_test(&mut disk)?;
    ostd::debug::print("virtio-blk: setor escrito e lido com BLAKE3 igual");
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
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let _ = s.ready();
    if let Err(e) = run(&s, quota) {
        ostd::debug::print_fmt(format_args!("virtio-blk: falhou: {e}"));
    }
    ostd::thread::exit()
}
