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

use ostd::kabi::{Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};
use vdrv::{Dma, Irq, Regs};
use virtio_core::{F_ACCESS_PLATFORM, Mmio, Queue, Seg, Transport};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
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
/// Prazo de uma requisição.
const TIMEOUT_NS: u64 = 1_000_000_000;

/// O disco em uso.
struct Disk<'a> {
    queue: Queue<Dma<'a>, QUEUE_SIZE>,
    notify: Regs<'a>,
    notify_at: usize,
    req: Mapping,
    req_iova: u64,
    irq: Irq,
}

impl Disk<'_> {
    /// Uma requisição de um setor; os dados ficam em [`DATA_AT`].
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
        self.irq.wait(TIMEOUT_NS)?;
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
    let Some(bytes) = disk.req.bytes_mut() else {
        return Err("página de requisições só de leitura");
    };
    bytes[DATA_AT..DATA_AT + SECTOR].copy_from_slice(&sent);
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
    let (Some(irq), Some(domain)) = (vdrv::resource(s, b"irq0"), vdrv::resource(s, b"dma")) else {
        return Err("faltou irq0 ou dma");
    };
    // 1. As regiões do virtio, pelo espaço de configuração.
    let caps = vdrv::read_caps(s, CFG_VA)?;
    let device_cfg = caps.device.ok_or("sem configuração de dispositivo")?;
    let bar_map = vdrv::map_bar(s, BAR_VA, &[caps.common, caps.notify, caps.isr, device_cfg])?;
    // 2. Memória de DMA: a fila e as requisições.
    let queue_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página da fila")?;
    let req_obj = ostd::cap::create(quota, ObjectType::MemoryObject, 4096)
        .map_err(|_| "página de requisições")?;
    let queue_map = RefCell::new(
        Mapping::new(SELF, queue_obj, QUEUE_VA, 4096, ostd::kabi::vm::WRITE)
            .map_err(|_| "mapear a fila")?,
    );
    let req = Mapping::new(SELF, req_obj, REQ_VA, 4096, ostd::kabi::vm::WRITE)
        .map_err(|_| "mapear requisições")?;
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
    let mut transport = Transport::new(Regs::new(&bar_map, caps.common.offset as usize));
    transport
        .negotiate(F_ACCESS_PLATFORM, required)
        .map_err(|_| "negociar as features")?;
    let (queue, notify_off) = transport
        .setup_queue::<_, QUEUE_SIZE>(0, Dma::new(&queue_map, queue_at), 0)
        .map_err(|_| "montar a fila 0")?;
    let irq = Irq::new(quota, irq)?;
    transport.driver_ok();
    let device = Regs::new(&bar_map, device_cfg.offset as usize);
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
        notify: Regs::new(&bar_map, 0),
        notify_at,
        req,
        req_iova: req_at,
        irq,
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
        .find(|c| c.kind == KIND_KERNEL && c.name_hash == vdrv::hash(b"debug"))
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
