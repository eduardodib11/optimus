//! `virtio-gpu` (T-416; ADR 0042, 0046 e 0047): driver de vídeo virtio 2D em
//! processo de usuário. Cria um recurso 2D `XRGB8888` de 64x64, liga a
//! memória de apoio (uma página por entrada, que serve com e sem IOMMU),
//! pinta de cor sólida, e o põe no scanout 0 com `SET_SCANOUT`,
//! `TRANSFER_TO_HOST_2D` e `RESOURCE_FLUSH`. Depois serve o `DisplayDevice` gerado do
//! `idl/optimus/display.oidl` (T-514): modos, troca de modo e apresentação de
//! um retângulo. Os buffers compartilhados com o `displayd` e os eventos vêm
//! na parte seguinte.

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

mod display_servidor;

use display_servidor::{Contexto, DisplayDevice, DisplayError, ID_DISPLAYDEVICE, Mode};

ostd::entry!(main);

const KIND_KERNEL: u8 = 5;
const CFG_VA: u64 = 0x20_0000_0000;
const BAR_VA: u64 = 0x20_0010_0000;
const QUEUE_VA: u64 = 0x20_0020_0000;
const CMD_VA: u64 = 0x20_0021_0000;
const FB_VA: u64 = 0x20_0030_0000;
const QUEUE_IOVA: u64 = 0x10_0000;
const CMD_IOVA: u64 = 0x10_1000;
const FB_IOVA: u64 = 0x10_2000;
const QUEUE_SIZE: usize = 8;
const WAIT_NS: u64 = 1_000_000_000;
/// Offsets do pedido e da resposta na página de comandos.
const RESP_AT: usize = 512;
/// Recurso e scanout.
const RESOURCE_ID: u32 = 1;
const WIDTH: u32 = 64;
const HEIGHT: u32 = 64;
const PAGES: usize = (WIDTH * HEIGHT * 4 / 4096) as usize;
/// `B8G8R8X8_UNORM`: o `XRGB8888` do `DisplayDevice` (ADR 0047).
const FORMAT_XRGB8888: u32 = 2;
/// A cor sólida (R, G, B) que o aceite procura no quadro.
const COLOR: [u8; 3] = [0x20, 0x80, 0xe0];
/// Tipos de comando e a resposta de sucesso.
const CMD_CREATE_2D: u32 = 0x101;
const CMD_SET_SCANOUT: u32 = 0x103;
const CMD_FLUSH: u32 = 0x104;
const CMD_TRANSFER: u32 = 0x105;
const CMD_ATTACH: u32 = 0x106;
const RESP_OK_NODATA: u32 = 0x1100;
const HDR: usize = 24;

struct Gpu<'a> {
    queue: Queue<Dma<'a>, QUEUE_SIZE>,
    notify: Regs<'a>,
    notify_at: usize,
    cmd: Mapping,
    cmd_iova: u64,
    irq: Irq,
}

impl Gpu<'_> {
    /// Manda `words` (u32 após o cabeçalho de 24 bytes) e confere `OK_NODATA`.
    fn command(&mut self, kind: u32, body: &[u8]) -> Result<(), &'static str> {
        let len = HDR + body.len();
        let buf = self.cmd.bytes_mut().ok_or("buffer só de leitura")?;
        buf[..len].fill(0);
        buf[..4].copy_from_slice(&kind.to_le_bytes());
        buf[HDR..len].copy_from_slice(body);
        buf[RESP_AT..RESP_AT + HDR].fill(0);
        let segs = [
            Seg {
                addr: self.cmd_iova,
                len: len as u32,
                write: false,
            },
            Seg {
                addr: self.cmd_iova + RESP_AT as u64,
                len: HDR as u32,
                write: true,
            },
        ];
        self.queue.push(&segs).map_err(|_| "push na fila")?;
        self.notify.write16(self.notify_at, 0);
        self.irq.wait(WAIT_NS)?;
        match self.queue.pop() {
            Ok(Some(_)) => {}
            Ok(None) => return Err("fila sem cadeia usada"),
            Err(_) => return Err("dispositivo devolveu cadeia inválida"),
        }
        let b = self.cmd.bytes();
        let resp = u32::from_le_bytes([b[RESP_AT], b[RESP_AT + 1], b[RESP_AT + 2], b[RESP_AT + 3]]);
        if resp == RESP_OK_NODATA {
            Ok(())
        } else {
            ostd::debug::print_fmt(format_args!("virtio-gpu: comando {kind:#x}: {resp:#x}"));
            Err("o dispositivo recusou o comando")
        }
    }
}

impl DisplayDevice for Gpu<'_> {
    fn mode_count(&mut self, _ctx: &Contexto) -> Result<u16, DisplayError> {
        Ok(1)
    }

    fn mode(&mut self, _ctx: &Contexto, index: u16) -> Result<Mode, DisplayError> {
        if index != 0 {
            return Err(DisplayError::BadMode);
        }
        Ok(Mode {
            id: 0,
            width: WIDTH as u16,
            height: HEIGHT as u16,
        })
    }

    fn set_mode(&mut self, _ctx: &Contexto, id: u16) -> Result<(), DisplayError> {
        if id != 0 {
            return Err(DisplayError::BadMode);
        }
        self.command(
            CMD_SET_SCANOUT,
            &le(&[0, 0, WIDTH, HEIGHT, 0, RESOURCE_ID])[..24],
        )
        .map_err(|_| DisplayError::Io)
    }

    fn present(
        &mut self,
        _ctx: &Contexto,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    ) -> Result<(), DisplayError> {
        let (x, y, w, h) = (
            u32::from(x),
            u32::from(y),
            u32::from(width),
            u32::from(height),
        );
        if w == 0 || h == 0 || x + w > WIDTH || y + h > HEIGHT {
            return Err(DisplayError::BadRect);
        }
        let offset = u64::from(y * WIDTH + x) * 4;
        let io = |_| DisplayError::Io;
        self.command(
            CMD_TRANSFER,
            &le(&[
                x,
                y,
                w,
                h,
                offset as u32,
                (offset >> 32) as u32,
                RESOURCE_ID,
            ])[..32],
        )
        .map_err(io)?;
        self.command(CMD_FLUSH, &le(&[x, y, w, h, RESOURCE_ID])[..24])
            .map_err(io)
    }
}

/// Atende o contrato `DisplayDevice` em `ep` até o endpoint ser revogado.
fn serve(ep: Handle, quota: Handle, buf: &mut ipc::Buffer, gpu: &mut Gpu<'_>) -> Error {
    let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let (mut corpo, mut saida) = ([0u8; 64], [0u8; 32]);
    let mut rec = match ipc::recv(ep, reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    loop {
        let ctx = Contexto { badge: rec.badge };
        let resp = if let Some((rotulo, w)) = display_servidor::despacha_display_device_palavras(
            gpu,
            rec.msg.label,
            &rec.msg.words,
            &ctx,
        ) {
            Ok(Message::new(rotulo, &w))
        } else {
            match ipc::copia(buf, &rec.msg, &mut corpo) {
                Ok(n) => {
                    let entrada = display_servidor::Entrada {
                        rotulo: rec.msg.label,
                        badge: rec.badge,
                        corpo: &corpo[..n],
                        caps: &[],
                    };
                    match display_servidor::despacha_display_device(
                        gpu,
                        0,
                        &entrada,
                        &mut saida,
                        &mut [],
                    ) {
                        Some(d) => ipc::monta(buf, d.rotulo, &saida[..d.corpo]),
                        None => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
                    }
                }
                Err(_) => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
            }
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

fn le(fields: &[u32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, f) in fields.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&f.to_le_bytes());
    }
    out
}

fn run(s: &mut Session, quota: Handle) -> Result<(), &'static str> {
    let (Some(irq), Some(domain)) = (vdrv::resource(s, b"irq0"), vdrv::resource(s, b"dma")) else {
        return Err("faltou irq0 ou dma");
    };
    let caps = vdrv::read_caps(s, CFG_VA)?;
    let bar_map = vdrv::map_bar(s, BAR_VA, &[caps.common, caps.notify, caps.isr])?;
    let mem = |size: u64| ostd::cap::create(quota, ObjectType::MemoryObject, size);
    let queue_obj = mem(4096).map_err(|_| "página da fila")?;
    let cmd_obj = mem(4096).map_err(|_| "página de comandos")?;
    let map = |obj, va| {
        Mapping::new(SELF, obj, va, 4096, ostd::kabi::vm::WRITE).map_err(|_| "mapear memória")
    };
    let queue_map = RefCell::new(map(queue_obj, QUEUE_VA)?);
    let cmd = map(cmd_obj, CMD_VA)?;
    let dma = |obj, iova, dev_writes| {
        ostd::dev::dma_map(domain, obj, iova, 0, 4096, dev_writes).map_err(|_| "dma_map")
    };
    let queue_at = dma(queue_obj, QUEUE_IOVA, true)?;
    let cmd_at = dma(cmd_obj, CMD_IOVA, true)?;
    // O quadro: uma página por entrada de apoio, pintada de `COLOR`.
    let mut fb_at = [0u64; PAGES];
    for (i, at) in fb_at.iter_mut().enumerate() {
        let obj = mem(4096).map_err(|_| "página do quadro")?;
        let mut m = map(obj, FB_VA + i as u64 * 4096)?;
        for px in m
            .bytes_mut()
            .ok_or("quadro só de leitura")?
            .chunks_exact_mut(4)
        {
            px.copy_from_slice(&[COLOR[2], COLOR[1], COLOR[0], 0xff]);
        }
        *at = dma(obj, FB_IOVA + i as u64 * 4096, false)?;
    }
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
        .map_err(|_| "montar a fila de controle")?;
    let irq = Irq::new(quota, irq)?;
    transport.driver_ok();
    let notify_at =
        caps.notify.offset as usize + usize::from(notify_off) * caps.notify_multiplier as usize;
    let mut gpu = Gpu {
        queue,
        notify: Regs::new(&bar_map, 0),
        notify_at,
        cmd,
        cmd_iova: cmd_at,
        irq,
    };
    ostd::debug::print("virtio-gpu: fila de controle pronta");
    gpu.command(
        CMD_CREATE_2D,
        &le(&[RESOURCE_ID, FORMAT_XRGB8888, WIDTH, HEIGHT])[..16],
    )?;
    // ATTACH_BACKING: `resource_id`, `nr_entries` e as entradas (addr, len).
    let mut attach = [0u8; 8 + PAGES * 16];
    attach[..4].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    attach[4..8].copy_from_slice(&(PAGES as u32).to_le_bytes());
    for (i, at) in fb_at.iter().enumerate() {
        let e = 8 + i * 16;
        attach[e..e + 8].copy_from_slice(&at.to_le_bytes());
        attach[e + 8..e + 12].copy_from_slice(&4096u32.to_le_bytes());
    }
    gpu.command(CMD_ATTACH, &attach)?;
    // SET_SCANOUT: retângulo, `scanout_id` 0 e o recurso.
    gpu.command(
        CMD_SET_SCANOUT,
        &le(&[0, 0, WIDTH, HEIGHT, 0, RESOURCE_ID])[..24],
    )?;
    // TRANSFER_TO_HOST_2D: retângulo, `offset` (u64) e o recurso.
    gpu.command(
        CMD_TRANSFER,
        &le(&[0, 0, WIDTH, HEIGHT, 0, 0, RESOURCE_ID])[..32],
    )?;
    gpu.command(CMD_FLUSH, &le(&[0, 0, WIDTH, HEIGHT, RESOURCE_ID])[..24])?;
    ostd::debug::print("virtio-gpu: quadro de cor sólida enviado");
    let ep = s
        .boot
        .provided(ID_DISPLAYDEVICE)
        .map(Handle::from_raw)
        .ok_or("descritor sem o endpoint do DisplayDevice")?;
    let e = serve(ep, quota, &mut s.buffer, &mut gpu);
    ostd::debug::print_fmt(format_args!("virtio-gpu: encerrado ({e:?})"));
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
        ostd::debug::print_fmt(format_args!("virtio-gpu: falhou: {e}"));
    }
    ostd::thread::exit()
}
