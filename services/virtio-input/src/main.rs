//! `virtio-input` (T-413; ADR 0042 e 0046): driver de entrada virtio
//! moderno (teclado e mouse) em processo de usuário. Deixa a fila de eventos
//! (fila 0) cheia de buffers de 8 bytes que o dispositivo preenche com um
//! evento `evdev` (`type`, `code`, `value`); cada evento é traduzido por
//! [`oinput::Evdev`] e vai ao `inputd` por `optimus.input.Sink@1`. O
//! dispositivo não é de confiança: o que não traduz é descartado.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

use core::cell::RefCell;

use oinput::{Evdev, Event};
use ostd::ipc::{self, Message};
use ostd::kabi::{Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};
use vdrv::{Dma, Irq, Regs};
use virtio_core::{F_ACCESS_PLATFORM, Mmio, Queue, Seg, Transport};

ostd::entry!(main);

/// `kind` das capabilities do descritor (ADR 0034): serviço e kernel.
const KIND_SVC: u8 = 1;
const KIND_KERNEL: u8 = 5;
/// Onde o `cfg`, o BAR e as páginas de DMA ficam mapeados.
const CFG_VA: u64 = 0x20_0000_0000;
const BAR_VA: u64 = 0x20_0010_0000;
const QUEUE_VA: u64 = 0x20_0020_0000;
const BUF_VA: u64 = 0x20_0030_0000;
/// IOVAs das páginas da fila e dos buffers.
const QUEUE_IOVA: u64 = 0x10_0000;
const BUF_IOVA: u64 = 0x10_1000;
/// Descritores da fila de eventos, cada um com um buffer de [`EVENT_LEN`].
const QUEUE_SIZE: usize = 8;
const EVENT_LEN: usize = 8;
/// Índice da fila de eventos.
const EVENT_QUEUE: u16 = 0;
/// Prazo de uma entrega ao `inputd`.
const SEND_NS: u64 = 100_000_000;
/// Espera de IRQ; a fila é checada de novo a cada estouro.
const WAIT_NS: u64 = 1_000_000_000;

struct Input<'a> {
    queue: Queue<Dma<'a>, QUEUE_SIZE>,
    notify: Regs<'a>,
    notify_at: usize,
    buf: Mapping,
    buf_iova: u64,
    irq: Irq,
    sink: Handle,
    evdev: Evdev,
    forwarded_key: bool,
}

impl Input<'_> {
    /// Entrega o buffer `slot` ao dispositivo.
    fn give(&mut self, slot: u16) -> Result<(), &'static str> {
        let seg = Seg {
            addr: self.buf_iova + u64::from(slot) * EVENT_LEN as u64,
            len: EVENT_LEN as u32,
            write: true,
        };
        self.queue.push(&[seg]).map_err(|_| "push na fila")?;
        Ok(())
    }

    /// Lê o evento do buffer `slot`: (`type`, `code`, `value`).
    fn read(&self, slot: u16) -> Option<(u16, u16, u32)> {
        let at = usize::from(slot) * EVENT_LEN;
        let b = self.buf.bytes().get(at..at + EVENT_LEN)?;
        Some((
            u16::from_le_bytes([b[0], b[1]]),
            u16::from_le_bytes([b[2], b[3]]),
            u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        ))
    }

    /// Manda o evento ao `inputd`; `false` quando ele se foi.
    fn send(&mut self, e: Event) -> bool {
        let words = oinput::encode(e);
        let deadline = ostd::time::now_ns().saturating_add(SEND_NS);
        let msg = Message::new(oinput::label(), &words);
        match ipc::call(self.sink, &msg, deadline) {
            Ok(_) | Err(ostd::kabi::Error::TimedOut) => true,
            Err(_) => false,
        }
    }

    /// Registra a primeira tecla encaminhada (o aceite procura a linha).
    fn log_first_key(&mut self, e: Event) {
        if let Event::Key { code, pressed } = e
            && !self.forwarded_key
        {
            self.forwarded_key = true;
            ostd::debug::print_fmt(format_args!(
                "virtio-input: tecla {code:#x} encaminhada (apertada={pressed})"
            ));
        }
    }

    /// Esvazia a fila de usados; `Ok(false)` quando o `inputd` se foi.
    fn drain(&mut self) -> Result<bool, &'static str> {
        let mut any = false;
        loop {
            let chain = match self.queue.pop() {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(_) => return Err("dispositivo devolveu cadeia inválida"),
            };
            let slot = chain.head;
            if usize::from(slot) >= QUEUE_SIZE {
                return Err("cadeia fora da fila");
            }
            if let Some((kind, code, value)) = self.read(slot)
                && let Some(e) = self.evdev.feed(kind, code, value)
            {
                self.log_first_key(e);
                if !self.send(e) {
                    return Ok(false);
                }
            }
            self.give(slot)?;
            any = true;
        }
        if any {
            self.notify.write16(self.notify_at, EVENT_QUEUE);
        }
        Ok(true)
    }
}

fn run(s: &Session, quota: Handle) -> Result<(), &'static str> {
    let (Some(irq), Some(domain)) = (vdrv::resource(s, b"irq0"), vdrv::resource(s, b"dma")) else {
        return Err("faltou irq0 ou dma");
    };
    let sink = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_SVC && c.name_hash == oinput::interface_id())
        .map(|c| Handle::from_raw(c.handle))
        .ok_or("sem o Sink do inputd")?;
    let caps = vdrv::read_caps(s, CFG_VA)?;
    let bar_map = vdrv::map_bar(s, BAR_VA, &[caps.common, caps.notify, caps.isr])?;
    let queue_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página da fila")?;
    let buf_obj = ostd::cap::create(quota, ObjectType::MemoryObject, 4096)
        .map_err(|_| "página dos buffers")?;
    let queue_map = RefCell::new(
        Mapping::new(SELF, queue_obj, QUEUE_VA, 4096, ostd::kabi::vm::WRITE)
            .map_err(|_| "mapear a fila")?,
    );
    let buf = Mapping::new(SELF, buf_obj, BUF_VA, 4096, ostd::kabi::vm::WRITE)
        .map_err(|_| "mapear os buffers")?;
    let queue_at = ostd::dev::dma_map(domain, queue_obj, QUEUE_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map da fila")?;
    let buf_at = ostd::dev::dma_map(domain, buf_obj, BUF_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map dos buffers")?;
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
        .setup_queue::<_, QUEUE_SIZE>(EVENT_QUEUE, Dma::new(&queue_map, queue_at), 0)
        .map_err(|_| "montar a fila de eventos")?;
    let irq = Irq::new(quota, irq)?;
    let notify_at =
        caps.notify.offset as usize + usize::from(notify_off) * caps.notify_multiplier as usize;
    let mut input = Input {
        queue,
        notify: Regs::new(&bar_map, 0),
        notify_at,
        buf,
        buf_iova: buf_at,
        irq,
        sink,
        evdev: Evdev::default(),
        forwarded_key: false,
    };
    for slot in 0..QUEUE_SIZE as u16 {
        input.give(slot)?;
    }
    transport.driver_ok();
    input.notify.write16(input.notify_at, EVENT_QUEUE);
    ostd::debug::print("virtio-input: fila de eventos pronta");
    loop {
        // Estouro do prazo só reconfere a fila; IRQ perdida não trava.
        let _ = input.irq.wait(WAIT_NS);
        if !input.drain()? {
            return Err("o inputd se foi");
        }
    }
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
        ostd::debug::print_fmt(format_args!("virtio-input: falhou: {e}"));
    }
    ostd::thread::exit()
}
