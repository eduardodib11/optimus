//! `virtio-rng` (T-414; ADR 0042 e 0046): driver de entropia virtio moderno
//! em processo de usuário. Só tem o que o `devmgr` deu (`cfg`, o BAR das
//! capabilities, `irq0` e `dma`) e com isso negocia o transporte, monta a
//! fila 0 e lê bytes do dispositivo.
//!
//! Os bytes do dispositivo são uma fonte a mais, nunca a única: não
//! substituem a entropia do kernel (`optboot` e `krand`), só se somam a ela.
//! Por isso o driver confere que o dispositivo responde com bytes que variam
//! antes de entregá-los; a entrega ao gerador de semente do sistema vem a
//! seguir.

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
use virtio_core::{F_ACCESS_PLATFORM, Queue, Seg, Transport};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Onde o `cfg`, o BAR e as páginas de DMA ficam mapeados.
const CFG_VA: u64 = 0x20_0000_0000;
const BAR_VA: u64 = 0x20_0010_0000;
const QUEUE_VA: u64 = 0x20_0020_0000;
const BUF_VA: u64 = 0x20_0030_0000;
/// IOVAs das páginas da fila e do buffer.
const QUEUE_IOVA: u64 = 0x10_0000;
const BUF_IOVA: u64 = 0x10_1000;
/// Descritores da fila 0.
const QUEUE_SIZE: usize = 8;
/// Bytes pedidos a cada leitura.
const CHUNK: usize = 64;
/// Prazo de uma leitura.
const TIMEOUT_NS: u64 = 1_000_000_000;

/// O dispositivo de entropia em uso.
struct Rng<'a> {
    queue: Queue<Dma<'a>, QUEUE_SIZE>,
    notify: Regs<'a>,
    notify_at: usize,
    buf: Mapping,
    buf_iova: u64,
    irq: Irq,
}

impl Rng<'_> {
    /// Lê até [`CHUNK`] bytes do dispositivo em `out`; devolve quantos.
    fn read(&mut self, out: &mut [u8; CHUNK]) -> Result<usize, &'static str> {
        let seg = Seg {
            addr: self.buf_iova,
            len: CHUNK as u32,
            write: true,
        };
        self.queue.push(&[seg]).map_err(|_| "push na fila")?;
        virtio_core::Mmio::write16(&self.notify, self.notify_at, 0);
        self.irq.wait(TIMEOUT_NS)?;
        let chain = match self.queue.pop() {
            Ok(Some(c)) => c,
            Ok(None) => return Err("fila sem cadeia usada"),
            Err(_) => return Err("dispositivo devolveu cadeia inválida"),
        };
        let n = (chain.len as usize).min(CHUNK);
        out[..n].copy_from_slice(&self.buf.bytes()[..n]);
        Ok(n)
    }
}

/// Duas leituras têm que dar bytes e diferir uma da outra; um dispositivo
/// que devolve zeros ou sempre o mesmo não é fonte de entropia.
fn self_test(rng: &mut Rng<'_>) -> Result<u32, &'static str> {
    let (mut a, mut b) = ([0u8; CHUNK], [0u8; CHUNK]);
    let na = rng.read(&mut a)?;
    let nb = rng.read(&mut b)?;
    if na == 0 || nb == 0 {
        return Err("o dispositivo não devolveu bytes");
    }
    if a[..na].iter().all(|&x| x == 0) || a[..na] == b[..nb] {
        return Err("os bytes do dispositivo não variam");
    }
    let h = optcrypt::blake3::hash(&a[..na]);
    Ok(u32::from_le_bytes([h[0], h[1], h[2], h[3]]))
}

fn run(s: &Session, quota: Handle) -> Result<(), &'static str> {
    let (Some(irq), Some(domain)) = (vdrv::resource(s, b"irq0"), vdrv::resource(s, b"dma")) else {
        return Err("faltou irq0 ou dma");
    };
    let caps = vdrv::read_caps(s, CFG_VA)?;
    let bar_map = vdrv::map_bar(s, BAR_VA, &[caps.common, caps.notify, caps.isr])?;
    let queue_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página da fila")?;
    let buf_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página do buffer")?;
    let queue_map = RefCell::new(
        Mapping::new(SELF, queue_obj, QUEUE_VA, 4096, ostd::kabi::vm::WRITE)
            .map_err(|_| "mapear a fila")?,
    );
    let buf = Mapping::new(SELF, buf_obj, BUF_VA, 4096, ostd::kabi::vm::WRITE)
        .map_err(|_| "mapear o buffer")?;
    let queue_at = ostd::dev::dma_map(domain, queue_obj, QUEUE_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map da fila")?;
    let buf_at = ostd::dev::dma_map(domain, buf_obj, BUF_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map do buffer")?;
    // Com IOMMU o `dma_map` devolve a IOVA; o dispositivo precisa de
    // `ACCESS_PLATFORM` para endereçar por ela.
    let required = if queue_at == QUEUE_IOVA {
        F_ACCESS_PLATFORM
    } else {
        0
    };
    let mut transport = Transport::new(Regs::new(&bar_map, caps.common.offset as usize));
    transport
        .negotiate(F_ACCESS_PLATFORM, required)
        .map_err(|_| "negociar as features")?;
    let (queue, notify_off) = transport
        .setup_queue::<_, QUEUE_SIZE>(0, Dma::new(&queue_map, queue_at), 0)
        .map_err(|_| "montar a fila 0")?;
    let irq = Irq::new(quota, irq)?;
    transport.driver_ok();
    let notify_at =
        caps.notify.offset as usize + usize::from(notify_off) * caps.notify_multiplier as usize;
    let mut rng = Rng {
        queue,
        notify: Regs::new(&bar_map, 0),
        notify_at,
        buf,
        buf_iova: buf_at,
        irq,
    };
    let tag = self_test(&mut rng)?;
    ostd::debug::print_fmt(format_args!(
        "virtio-rng: bytes do dispositivo variam (BLAKE3 {tag:08x})"
    ));
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
        ostd::debug::print_fmt(format_args!("virtio-rng: falhou: {e}"));
    }
    ostd::thread::exit()
}
