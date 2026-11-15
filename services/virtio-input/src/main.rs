//! `virtio-input` (T-413; ADR 0042 e 0046): driver de entrada virtio
//! moderno (teclado e mouse) em processo de usuário. Deixa a fila de eventos
//! (fila 0) cheia de buffers de 8 bytes que o dispositivo preenche com um
//! evento `evdev` (`type`, `code`, `value`); cada evento é traduzido por
//! [`oinput::Evdev`] e vai ao `inputd` por `optimus.input.Sink@1`. O
//! dispositivo não é de confiança: o que não traduz é descartado. Serve
//! também o contrato `InputDevice` (T-514; ADR 0064): os eventos `evdev` crus
//! vão a um anel SPSC do cliente, no laço único da ADR 0060 (`recv` de 5 ms).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

mod input_servidor;

use core::cell::RefCell;

use input_servidor::{Contexto, ID_INPUTDEVICE, InputDevice, InputError, InputInfo};
use oinput::{Evdev, Event};
use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::ring::Producer;
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
/// O contrato: prazo do `recv` do laço (ADR 0060), anel de eventos do
/// cliente (4 KiB de dados), tipo do registro e quantos eventos anteriores ao
/// `attach_events` o driver guarda.
const POLL_NS: u64 = 5_000_000;
const EVENTS_VA: u64 = 0x20_0040_0000;
const RING_BYTES: u32 = 4096;
const REC_KIND: u16 = 1;
const PENDING: usize = 16;
/// Badge da sessão (com `GRANT`), como no `BlockDevice` (ADR 0063).
const SESSION_BADGE: u64 = 1;

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
    /// O `inputd` ainda atende.
    sink_alive: bool,
    ep: Handle,
    /// Anel de eventos do cliente, depois do `attach_events`.
    events: Option<Producer>,
    /// Eventos crus anteriores ao `attach_events`.
    pending: [[u8; EVENT_LEN]; PENDING],
    npending: usize,
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

    /// Entrega o evento cru ao cliente do contrato, ou o guarda até ele ligar.
    fn emit(&mut self, kind: u16, code: u16, value: u32) {
        let mut raw = [0u8; EVENT_LEN];
        raw[0..2].copy_from_slice(&kind.to_le_bytes());
        raw[2..4].copy_from_slice(&code.to_le_bytes());
        raw[4..8].copy_from_slice(&value.to_le_bytes());
        if let Some(p) = self.events.as_mut() {
            // Cheio: o anel descarta e conta em `dropped`.
            let _ = p.push(REC_KIND, &raw);
        } else if self.npending < PENDING {
            self.pending[self.npending] = raw;
            self.npending += 1;
        }
    }

    /// Um passo do laço: confirma a IRQ e esvazia a fila de eventos.
    fn pump(&mut self) {
        if let Ok(bits) = ostd::cap::ntfy_poll(self.irq.ntfy)
            && bits & 1 != 0
        {
            let _ = ostd::dev::irq_ack(self.irq.irq);
        }
        // Se o `inputd` se foi, os eventos só seguem pelo contrato.
        let _ = self.drain();
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

    /// Esvazia a fila de usados.
    fn drain(&mut self) -> Result<(), &'static str> {
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
            if let Some((kind, code, value)) = self.read(slot) {
                self.emit(kind, code, value);
                if let Some(e) = self.evdev.feed(kind, code, value) {
                    self.log_first_key(e);
                    if self.sink_alive && !self.send(e) {
                        self.sink_alive = false;
                    }
                }
            }
            self.give(slot)?;
            any = true;
        }
        if any {
            self.notify.write16(self.notify_at, EVENT_QUEUE);
        }
        Ok(())
    }
}

impl InputDevice for Input<'_> {
    fn info(&mut self, _ctx: &Contexto) -> Result<InputInfo, InputError> {
        Ok(InputInfo {
            ring_bytes: RING_BYTES,
        })
    }

    fn session(&mut self, _ctx: &Contexto) -> Result<u64, InputError> {
        vdrv::serve::grant(self.ep, Rights::SEND | Rights::GRANT, SESSION_BADGE)
            .map_err(|_| InputError::Io)
    }

    fn attach_events(&mut self, ctx: &Contexto, ring: u64, signal: u64) -> Result<(), InputError> {
        if ctx.badge & 0xFFFF_FFFF != SESSION_BADGE || self.events.is_some() {
            return Err(InputError::BadRequest);
        }
        let (Ok(ring), Ok(signal)) = (u32::try_from(ring), u32::try_from(signal)) else {
            return Err(InputError::BadRequest);
        };
        let mut prod = Producer::open(
            Handle::from_raw(ring),
            EVENTS_VA,
            RING_BYTES,
            Handle::from_raw(signal),
            1,
        )
        .map_err(|_| InputError::BadRequest)?;
        for raw in &self.pending[..self.npending] {
            let _ = prod.push(REC_KIND, raw);
        }
        self.npending = 0;
        self.events = Some(prod);
        Ok(())
    }
}

/// Atende o contrato `InputDevice` em `ep` até o endpoint ser revogado.
fn serve(ep: Handle, quota: Handle, buf: &mut ipc::Buffer, input: &mut Input<'_>) -> Error {
    let input = RefCell::new(input);
    vdrv::serve::serve(
        ep,
        quota,
        buf,
        POLL_NS,
        &mut || input.borrow_mut().pump(),
        &mut |req, saida, caps_out| {
            let entrada = input_servidor::Entrada {
                rotulo: req.rotulo,
                badge: req.badge,
                corpo: req.corpo,
                caps: req.caps,
            };
            let d = input_servidor::despacha_input_device(
                &mut **input.borrow_mut(),
                0,
                &entrada,
                saida,
                caps_out,
            )?;
            Some(vdrv::serve::Resp {
                rotulo: d.rotulo,
                corpo: d.corpo,
                caps: d.caps,
            })
        },
    )
}

fn run(s: &mut Session, quota: Handle) -> Result<(), &'static str> {
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
    let ep = s
        .boot
        .provided(ID_INPUTDEVICE)
        .map(Handle::from_raw)
        .ok_or("descritor sem o endpoint do InputDevice")?;
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
        sink_alive: true,
        ep,
        events: None,
        pending: [[0; EVENT_LEN]; PENDING],
        npending: 0,
    };
    for slot in 0..QUEUE_SIZE as u16 {
        input.give(slot)?;
    }
    transport.driver_ok();
    input.notify.write16(input.notify_at, EVENT_QUEUE);
    ostd::debug::print("virtio-input: fila de eventos pronta");
    let e = serve(ep, quota, &mut s.buffer, &mut input);
    ostd::debug::print_fmt(format_args!("virtio-input: encerrado ({e:?})"));
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
    if let Err(e) = run(&mut s, quota) {
        ostd::debug::print_fmt(format_args!("virtio-input: falhou: {e}"));
    }
    ostd::thread::exit()
}
