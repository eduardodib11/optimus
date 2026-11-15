//! `virtio-console` (T-415; ADR 0042 e 0046): driver de console virtio
//! moderno em processo de usuário. Só tem o que o `devmgr` deu (`cfg`, o BAR
//! das capabilities, `irq0` e `dma`) e com isso negocia o transporte, monta a
//! fila de transmissão da porta 0 (fila 1) e escreve um texto nela, que o
//! QEMU entrega ao seu `chardev`. Depois serve o contrato `Console` gerado do
//! `idl/optimus/console.oidl` (T-514): quem tem o endpoint escreve na porta e
//! lê o que foi digitado nela (fila de recepção 0, para o pedido de senha do
//! `keyd`, T-527). As portas extras vêm depois.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

use core::cell::RefCell;

use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};
use vdrv::{Dma, Irq, Regs};
use virtio_core::{F_ACCESS_PLATFORM, Mmio, Queue, Seg, Transport};

mod console_servidor;

use console_servidor::{Console, ConsoleError, Contexto, ID_CONSOLE};

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
/// Fila e buffers de recepção.
const RXQ_VA: u64 = 0x20_0040_0000;
const RXBUF_VA: u64 = 0x20_0050_0000;
const RXQ_IOVA: u64 = 0x10_2000;
const RXBUF_IOVA: u64 = 0x10_3000;
/// Bytes de cada buffer de recepção; cabem `QUEUE_SIZE` numa página.
const RX_BUF: usize = 64;
/// Descritores de cada fila.
const QUEUE_SIZE: usize = 8;
/// Índice da fila de recepção da porta 0.
const RECEIVE_QUEUE: u16 = 0;
/// Índice da fila de transmissão da porta 0.
const TRANSMIT_QUEUE: u16 = 1;
/// Prazo de uma transmissão.
const TIMEOUT_NS: u64 = 1_000_000_000;
/// O texto que o aceite procura no `chardev` do QEMU.
const HELLO: &str = "virtio-console: ola do processo de usuario\n";

/// A porta 0 em uso.
struct Port<'a> {
    queue: Queue<Dma<'a>, QUEUE_SIZE>,
    rx: Queue<Dma<'a>, QUEUE_SIZE>,
    notify: Regs<'a>,
    notify_at: usize,
    rx_notify: usize,
    buf: Mapping,
    buf_iova: u64,
    rxbuf: Mapping,
    rxbuf_iova: u64,
    irq: Irq,
    /// Bytes recebidos que a leitura ainda não entregou.
    pending: [u8; RX_BUF],
    pending_pos: usize,
    pending_len: usize,
    /// Saída da leitura atual.
    out: [u8; RX_BUF],
}

impl Port<'_> {
    /// Escreve `text` na porta e espera o dispositivo consumi-lo.
    fn transmit(&mut self, text: &str) -> Result<(), ConsoleError> {
        let bytes = text.as_bytes();
        let dst = self.buf.bytes_mut().ok_or(ConsoleError::Io)?;
        dst.get_mut(..bytes.len())
            .ok_or(ConsoleError::Io)?
            .copy_from_slice(bytes);
        let seg = Seg {
            addr: self.buf_iova,
            len: bytes.len() as u32,
            write: false,
        };
        self.queue.push(&[seg]).map_err(|_| ConsoleError::Io)?;
        self.notify.write16(self.notify_at, TRANSMIT_QUEUE);
        // A interrupção também sai da recepção: sem cadeia usada na
        // transmissão, espera de novo (cada espera tem prazo).
        for _ in 0..4 {
            self.irq
                .wait(TIMEOUT_NS)
                .map_err(|_| ConsoleError::Timeout)?;
            match self.queue.pop() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {}
                // Cadeia inválida: o dispositivo não é confiável.
                Err(_) => return Err(ConsoleError::Io),
            }
        }
        Err(ConsoleError::Io)
    }

    /// Entrega o buffer `slot` de recepção ao dispositivo.
    fn give_rx(&mut self, slot: u16) -> Result<(), ConsoleError> {
        let seg = Seg {
            addr: self.rxbuf_iova + u64::from(slot) * RX_BUF as u64,
            len: RX_BUF as u32,
            write: true,
        };
        self.rx.push(&[seg]).map_err(|_| ConsoleError::Io)?;
        Ok(())
    }

    /// Espera até `prazo_ns` por uma cadeia de recepção e a guarda em
    /// `pending`, devolvendo o buffer ao dispositivo.
    fn fill_pending(&mut self, prazo_ns: u64) -> Result<(), ConsoleError> {
        loop {
            match self.rx.pop() {
                Ok(Some(chain)) => {
                    let slot = chain.head;
                    let len = (chain.len as usize).min(RX_BUF);
                    let at = usize::from(slot) * RX_BUF;
                    let src = self
                        .rxbuf
                        .bytes()
                        .get(at..at + len)
                        .ok_or(ConsoleError::Io)?;
                    self.pending[..len].copy_from_slice(src);
                    self.pending_pos = 0;
                    self.pending_len = len;
                    self.give_rx(slot)?;
                    self.notify.write16(self.rx_notify, RECEIVE_QUEUE);
                    if len > 0 {
                        return Ok(());
                    }
                }
                Ok(None) => self.irq.wait(prazo_ns).map_err(|_| ConsoleError::Timeout)?,
                Err(_) => return Err(ConsoleError::Io),
            }
        }
    }
}

impl Console for Port<'_> {
    fn write(&mut self, _ctx: &Contexto, texto: &str) -> Result<u32, ConsoleError> {
        self.transmit(texto)?;
        // `texto` tem no máximo 128 bytes (`string<128>`).
        Ok(texto.len() as u32)
    }

    fn read(&mut self, _ctx: &Contexto, max: u8, prazo_ms: u32) -> Result<&[u8], ConsoleError> {
        if self.pending_len == 0 {
            self.fill_pending(u64::from(prazo_ms).saturating_mul(1_000_000))?;
        }
        let n = usize::from(max).min(RX_BUF).min(self.pending_len);
        let from = self.pending_pos;
        self.out[..n].copy_from_slice(&self.pending[from..from + n]);
        self.pending_pos += n;
        self.pending_len -= n;
        Ok(&self.out[..n])
    }
}

/// Atende o contrato `Console` em `ep` até o endpoint ser revogado.
fn serve(ep: Handle, quota: Handle, buf: &mut ipc::Buffer, port: &mut Port<'_>) -> Error {
    let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let (mut corpo, mut saida) = ([0u8; 136], [0u8; 96]);
    let mut rec = match ipc::recv(ep, reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    loop {
        let resp = match ipc::copia(buf, &rec.msg, &mut corpo) {
            Ok(n) => {
                let entrada = console_servidor::Entrada {
                    rotulo: rec.msg.label,
                    badge: rec.badge,
                    corpo: &corpo[..n],
                    caps: &[],
                };
                match console_servidor::despacha_console(port, 0, &entrada, &mut saida, &mut []) {
                    Some(d) => ipc::monta(buf, d.rotulo, &saida[..d.corpo]),
                    None => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
                }
            }
            Err(_) => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
        };
        let Ok(resp) = resp else {
            return Error::InvalidArgument;
        };
        rec = match ipc::reply_recv(ep, reply, &resp, 0) {
            Ok(r) => r,
            Err(e) => return e,
        };
    }
}

fn run(s: &mut Session, quota: Handle) -> Result<(), &'static str> {
    let (Some(irq), Some(domain)) = (vdrv::resource(s, b"irq0"), vdrv::resource(s, b"dma")) else {
        return Err("faltou irq0 ou dma");
    };
    let caps = vdrv::read_caps(s, CFG_VA)?;
    let bar_map = vdrv::map_bar(s, BAR_VA, &[caps.common, caps.notify, caps.isr])?;
    let queue_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página da fila")?;
    let buf_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "página do buffer")?;
    let rxq_obj = ostd::cap::create(quota, ObjectType::MemoryObject, 4096)
        .map_err(|_| "página da fila rx")?;
    let rxbuf_obj =
        ostd::cap::create(quota, ObjectType::MemoryObject, 4096).map_err(|_| "buffers rx")?;
    let rxq_map = RefCell::new(
        Mapping::new(SELF, rxq_obj, RXQ_VA, 4096, ostd::kabi::vm::WRITE)
            .map_err(|_| "mapear a fila rx")?,
    );
    let rxbuf = Mapping::new(SELF, rxbuf_obj, RXBUF_VA, 4096, ostd::kabi::vm::WRITE)
        .map_err(|_| "mapear os buffers rx")?;
    let queue_map = RefCell::new(
        Mapping::new(SELF, queue_obj, QUEUE_VA, 4096, ostd::kabi::vm::WRITE)
            .map_err(|_| "mapear a fila")?,
    );
    let buf = Mapping::new(SELF, buf_obj, BUF_VA, 4096, ostd::kabi::vm::WRITE)
        .map_err(|_| "mapear o buffer")?;
    let queue_at = ostd::dev::dma_map(domain, queue_obj, QUEUE_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map da fila")?;
    let buf_at = ostd::dev::dma_map(domain, buf_obj, BUF_IOVA, 0, 4096, false)
        .map_err(|_| "dma_map do buffer")?;
    let rxq_at = ostd::dev::dma_map(domain, rxq_obj, RXQ_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map da fila rx")?;
    let rxbuf_at = ostd::dev::dma_map(domain, rxbuf_obj, RXBUF_IOVA, 0, 4096, true)
        .map_err(|_| "dma_map dos buffers rx")?;
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
    let (rx, rx_off) = transport
        .setup_queue::<_, QUEUE_SIZE>(RECEIVE_QUEUE, Dma::new(&rxq_map, rxq_at), 0)
        .map_err(|_| "montar a fila de recepção")?;
    let (queue, notify_off) = transport
        .setup_queue::<_, QUEUE_SIZE>(TRANSMIT_QUEUE, Dma::new(&queue_map, queue_at), 0)
        .map_err(|_| "montar a fila de transmissão")?;
    let irq = Irq::new(quota, irq)?;
    transport.driver_ok();
    let notify_at =
        |off: u16| caps.notify.offset as usize + usize::from(off) * caps.notify_multiplier as usize;
    let mut port = Port {
        queue,
        rx,
        notify: Regs::new(&bar_map, 0),
        notify_at: notify_at(notify_off),
        rx_notify: notify_at(rx_off),
        buf,
        buf_iova: buf_at,
        rxbuf,
        rxbuf_iova: rxbuf_at,
        irq,
        pending: [0; RX_BUF],
        pending_pos: 0,
        pending_len: 0,
        out: [0; RX_BUF],
    };
    for slot in 0..QUEUE_SIZE as u16 {
        port.give_rx(slot)
            .map_err(|_| "entregar buffer de recepção")?;
    }
    port.notify.write16(port.rx_notify, RECEIVE_QUEUE);
    port.transmit(HELLO).map_err(|_| "escrever na porta 0")?;
    ostd::debug::print("virtio-console: texto enviado à porta 0");
    let ep = s
        .boot
        .provided(ID_CONSOLE)
        .map(Handle::from_raw)
        .ok_or("descritor sem o endpoint do Console")?;
    let e = serve(ep, quota, &mut s.buffer, &mut port);
    // Antes de largar o DMA: o dispositivo ainda consulta a fila de recepção.
    transport.reset();
    ostd::debug::print_fmt(format_args!("virtio-console: encerrado ({e:?})"));
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
        ostd::debug::print_fmt(format_args!("virtio-console: falhou: {e}"));
    }
    ostd::thread::exit()
}
