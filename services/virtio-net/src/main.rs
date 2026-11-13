//! `virtio-net` (T-412; ADR 0042 e 0046): driver de rede virtio moderno em
//! processo de usuário. Lê o MAC da configuração do dispositivo, monta a
//! fila de recepção (0) com buffers de 2 KiB e a de transmissão (1), manda
//! um ARP "quem tem 10.0.2.2" e espera a resposta do QEMU (rede de usuário).
//! O `NetDevice` por OIDL vem na parte 2.

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

const KIND_KERNEL: u8 = 5;
/// Onde o `cfg`, o BAR e as páginas de DMA ficam mapeados.
const CFG_VA: u64 = 0x20_0000_0000;
const BAR_VA: u64 = 0x20_0010_0000;
const RXQ_VA: u64 = 0x20_0020_0000;
const TXQ_VA: u64 = 0x20_0021_0000;
const RXBUF_VA: u64 = 0x20_0030_0000; // + 4 KiB por página
const TXBUF_VA: u64 = 0x20_0040_0000;
/// IOVAs: filas, buffers de recepção (8 KiB) e de transmissão.
const RXQ_IOVA: u64 = 0x10_0000;
const TXQ_IOVA: u64 = 0x10_1000;
const RXBUF_IOVA: u64 = 0x10_2000; // + 4 KiB por página
const TXBUF_IOVA: u64 = 0x10_5000;
/// Descritores de cada fila e tamanho de um buffer de recepção.
const QUEUE_SIZE: usize = 4;
const RX_BUF: usize = 2048;
/// Páginas de recepção (sem IOMMU o DMA exige memória contígua, então cada
/// página é um objeto próprio com `4096 / RX_BUF` buffers).
const RX_PAGES: usize = QUEUE_SIZE * RX_BUF / 4096;
const PER_PAGE: usize = 4096 / RX_BUF;
/// `F_MAC`: o dispositivo tem MAC na configuração.
const F_MAC: u64 = 1 << 5;
/// Cabeçalho do virtio-net com `VERSION_1` (`num_buffers` incluso).
const HDR: usize = 12;
const ETH_ARP: [u8; 2] = [0x08, 0x06];
/// Nosso IP e o do gateway da rede de usuário do QEMU.
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
/// Prazo de cada espera e número delas.
const WAIT_NS: u64 = 500_000_000;
const WAITS: u32 = 6;

struct Nic<'a> {
    rx: Queue<Dma<'a>, QUEUE_SIZE>,
    tx: Queue<Dma<'a>, QUEUE_SIZE>,
    notify: Regs<'a>,
    rx_notify: usize,
    tx_notify: usize,
    rxbuf: [Mapping; RX_PAGES],
    rxbuf_iova: [u64; RX_PAGES],
    txbuf: Mapping,
    txbuf_iova: u64,
    irq: Irq,
    mac: [u8; 6],
}

impl Nic<'_> {
    fn give_rx(&mut self, slot: u16) -> Result<(), &'static str> {
        let seg = Seg {
            addr: self.rxbuf_iova[usize::from(slot) / PER_PAGE]
                + (usize::from(slot) % PER_PAGE * RX_BUF) as u64,
            len: RX_BUF as u32,
            write: true,
        };
        self.rx
            .push(&[seg])
            .map_err(|_| "push na fila de recepção")?;
        Ok(())
    }

    /// Manda o ARP "quem tem `GATEWAY_IP`".
    fn send_arp(&mut self) -> Result<(), &'static str> {
        let mut f = [0u8; HDR + 42];
        let e = &mut f[HDR..];
        e[0..6].fill(0xff);
        e[6..12].copy_from_slice(&self.mac);
        e[12..14].copy_from_slice(&ETH_ARP);
        e[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        e[22..28].copy_from_slice(&self.mac);
        e[28..32].copy_from_slice(&OUR_IP);
        e[38..42].copy_from_slice(&GATEWAY_IP);
        e[32..38].fill(0);
        self.txbuf
            .bytes_mut()
            .ok_or("buffer só de leitura")?
            .get_mut(..f.len())
            .ok_or("quadro maior que o buffer")?
            .copy_from_slice(&f);
        let seg = Seg {
            addr: self.txbuf_iova,
            len: f.len() as u32,
            write: false,
        };
        self.tx
            .push(&[seg])
            .map_err(|_| "push na fila de transmissão")?;
        self.notify.write16(self.tx_notify, 1);
        Ok(())
    }

    /// Esvazia a recepção; `true` se algum quadro era a resposta do ARP.
    fn drain_rx(&mut self) -> Result<bool, &'static str> {
        let mut found = false;
        loop {
            let chain = match self.rx.pop() {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(_) => return Err("dispositivo devolveu cadeia inválida"),
            };
            let slot = chain.head;
            if usize::from(slot) >= QUEUE_SIZE {
                return Err("cadeia fora da fila");
            }
            let len = (chain.len as usize).min(RX_BUF);
            let at = usize::from(slot) % PER_PAGE * RX_BUF;
            if let Some(b) = self.rxbuf[usize::from(slot) / PER_PAGE]
                .bytes()
                .get(at..at + len)
                && let Some(e) = b.get(HDR..)
                && e.len() >= 42
                && e[12..14] == ETH_ARP
                && e[20..22] == [0, 2]
                && e[28..32] == GATEWAY_IP
                && e[32..38] == self.mac
            {
                ostd::debug::print_fmt(format_args!(
                    "virtio-net: ARP de 10.0.2.2 é {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    e[22], e[23], e[24], e[25], e[26], e[27]
                ));
                found = true;
            }
            self.give_rx(slot)?;
        }
        self.notify.write16(self.rx_notify, 0);
        Ok(found)
    }

    fn self_test(&mut self) -> Result<(), &'static str> {
        self.send_arp()?;
        for _ in 0..WAITS {
            let _ = self.irq.wait(WAIT_NS);
            // A transmissão devolvida só libera o descritor.
            while matches!(self.tx.pop(), Ok(Some(_))) {}
            if self.drain_rx()? {
                return Ok(());
            }
        }
        Err("sem resposta ao ARP")
    }
}

fn run(s: &Session, quota: Handle) -> Result<(), &'static str> {
    let (Some(irq), Some(domain)) = (vdrv::resource(s, b"irq0"), vdrv::resource(s, b"dma")) else {
        return Err("faltou irq0 ou dma");
    };
    let caps = vdrv::read_caps(s, CFG_VA)?;
    let device_cfg = caps.device.ok_or("sem configuração de dispositivo")?;
    let bar_map = vdrv::map_bar(s, BAR_VA, &[caps.common, caps.notify, caps.isr, device_cfg])?;
    let mem = |size: u64| ostd::cap::create(quota, ObjectType::MemoryObject, size);
    let rxq_obj = mem(4096).map_err(|_| "página da fila rx")?;
    let txq_obj = mem(4096).map_err(|_| "página da fila tx")?;
    let rxbuf_obj = [
        mem(4096).map_err(|_| "buffers rx")?,
        mem(4096).map_err(|_| "buffers rx")?,
    ];
    let txbuf_obj = mem(4096).map_err(|_| "buffer tx")?;
    let map = |obj, va, len| {
        Mapping::new(SELF, obj, va, len, ostd::kabi::vm::WRITE).map_err(|_| "mapear memória")
    };
    let rxq_map = RefCell::new(map(rxq_obj, RXQ_VA, 4096)?);
    let txq_map = RefCell::new(map(txq_obj, TXQ_VA, 4096)?);
    let rxbuf = [
        map(rxbuf_obj[0], RXBUF_VA, 4096)?,
        map(rxbuf_obj[1], RXBUF_VA + 4096, 4096)?,
    ];
    let txbuf = map(txbuf_obj, TXBUF_VA, 4096)?;
    let dma = |obj, iova, len, dev_writes| {
        ostd::dev::dma_map(domain, obj, iova, 0, len, dev_writes).map_err(|e| {
            ostd::debug::print_fmt(format_args!("virtio-net: dma_map {iova:#x}: {e:?}"));
            "dma_map"
        })
    };
    let rxq_at = dma(rxq_obj, RXQ_IOVA, 4096, true)?;
    let txq_at = dma(txq_obj, TXQ_IOVA, 4096, true)?;
    let rxbuf_at = [
        dma(rxbuf_obj[0], RXBUF_IOVA, 4096, true)?,
        dma(rxbuf_obj[1], RXBUF_IOVA + 4096, 4096, true)?,
    ];
    let txbuf_at = dma(txbuf_obj, TXBUF_IOVA, 4096, false)?;
    // Com IOMMU o `dma_map` devolve a IOVA; o dispositivo precisa de
    // `ACCESS_PLATFORM` para endereçar por ela.
    let required = if rxq_at == RXQ_IOVA {
        F_ACCESS_PLATFORM
    } else {
        0
    };
    let mut transport = Transport::new(Regs::new(&bar_map, caps.common.offset as usize));
    let features = transport
        .negotiate(F_ACCESS_PLATFORM | F_MAC, required | F_MAC)
        .map_err(|_| "negociar as features")?;
    let (rx, rx_off) = transport
        .setup_queue::<_, QUEUE_SIZE>(0, Dma::new(&rxq_map, rxq_at), 0)
        .map_err(|_| "montar a fila de recepção")?;
    let (tx, tx_off) = transport
        .setup_queue::<_, QUEUE_SIZE>(1, Dma::new(&txq_map, txq_at), 0)
        .map_err(|_| "montar a fila de transmissão")?;
    let irq = Irq::new(quota, irq)?;
    let device = Regs::new(&bar_map, device_cfg.offset as usize);
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        *b = device.read8(i);
    }
    let notify_at =
        |off: u16| caps.notify.offset as usize + usize::from(off) * caps.notify_multiplier as usize;
    let mut nic = Nic {
        rx,
        tx,
        notify: Regs::new(&bar_map, 0),
        rx_notify: notify_at(rx_off),
        tx_notify: notify_at(tx_off),
        rxbuf,
        rxbuf_iova: rxbuf_at,
        txbuf,
        txbuf_iova: txbuf_at,
        irq,
        mac,
    };
    for slot in 0..QUEUE_SIZE as u16 {
        nic.give_rx(slot)?;
    }
    transport.driver_ok();
    nic.notify.write16(nic.rx_notify, 0);
    ostd::debug::print_fmt(format_args!(
        "virtio-net: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, features {features:#x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ));
    nic.self_test()?;
    ostd::debug::print("virtio-net: ARP enviado e resposta recebida");
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
        ostd::debug::print_fmt(format_args!("virtio-net: falhou: {e}"));
    }
    ostd::thread::exit()
}
