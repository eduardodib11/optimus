//! `virtio-blk` (T-411; ADR 0042 e 0046): driver de disco virtio moderno
//! em processo de usuário. Só tem o que o `devmgr` deu (`cfg`, o BAR das
//! capabilities, `irq0` e `dma`) e com isso
//!
//! 1. acha as regiões do virtio no `cfg` e mapeia o BAR;
//! 2. negocia as features e monta a fila 0 em memória do `dma`;
//! 3. escreve um setor, lê de volta e confere o BLAKE3 (aceite da T-411);
//! 4. serve o contrato `BlockDevice` (T-514; ADR 0056, item 10): os pedidos
//!    chegam num anel SPSC de submissões e as conclusões voltam por outro,
//!    com os dados numa região de DMA compartilhada com o `storaged`.
//!
//! O laço é um só (ADR 0060): bloqueia em `recv` com prazo de 5 ms e, a cada
//! volta (por pedido ou por prazo), colhe o `used ring` e lê o anel.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

mod block_servidor;

use core::cell::RefCell;

use block_servidor::{BlockDevice, BlockError, BlockInfo, Contexto, ID_BLOCKDEVICE};
use ostd::ipc;
use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::ring::{Consumer, Producer};
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
const QUEUE_SIZE: usize = 16;
/// Na página de requisições: cabeçalho, dados e status.
const HDR_AT: usize = 0;
const DATA_AT: usize = 512;
const STATUS_AT: usize = 1024;
/// Tamanho do setor.
const SECTOR: usize = 512;
/// Setor do autoteste: depois da tabela GPT (LBA 0 a 33) e antes da primeira
/// partição alinhada a 1 MiB, para não pisar na tabela (T-520).
const SELF_TEST_SECTOR: u64 = 64;
const T_IN: u32 = 0;
const T_OUT: u32 = 1;
/// Prazo de uma requisição.
const TIMEOUT_NS: u64 = 1_000_000_000;
/// Prazo do `recv` do laço (ADR 0060, item 2).
const POLL_NS: u64 = 5_000_000;
/// Recursos do contrato: o anel de submissões, a região de dados, a página
/// de cabeçalhos e o anel de conclusões do `storaged`.
const SUBMIT_VA: u64 = 0x20_0040_0000;
const DATA_VA: u64 = 0x20_0050_0000;
const META_VA: u64 = 0x20_0060_0000;
const DONE_VA: u64 = 0x20_0070_0000;
const META_IOVA: u64 = 0x10_2000;
const DATA_IOVA: u64 = 0x11_0000;
/// Pedidos em voo: uma página de dados e três descritores cada.
const DEPTH: usize = 4;
const PAGE: usize = 4096;
const DATA_BYTES: usize = DEPTH * PAGE;
/// Setores de 512 bytes que cabem numa página (o máximo de um pedido).
const MAX_SECTORS: u16 = (PAGE / SECTOR) as u16;
/// Bytes de dados de cada anel (128 registros de 32 bytes).
const RING_BYTES: u32 = 4096;
/// Tipo do anel e dos registros (ADR 0056, item 4).
const RING_KIND: u16 = 0x0B01;
const REC_KIND: u16 = 1;
/// Bits de feature do virtio-blk (seção 5.2 da especificação).
const F_RO: u64 = 1 << 5;
const F_FLUSH: u64 = 1 << 9;
const T_FLUSH: u32 = 4;
const OP_READ: u8 = 0;
const OP_WRITE: u8 = 1;
const OP_FLUSH: u8 = 2;
/// Bytes de cada slot na página de cabeçalhos: cabeçalho e status.
const SLOT_BYTES: usize = 64;
const SLOT_STATUS: usize = 16;

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

/// Escreve o setor `SELF_TEST_SECTOR`, lê de volta e confere o BLAKE3 (aceite da T-411).
fn self_test(disk: &mut Disk<'_>) -> Result<(), &'static str> {
    let mut sent = [0u8; SECTOR];
    for (i, b) in sent.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(11) ^ 0xa5;
    }
    let Some(bytes) = disk.req.bytes_mut() else {
        return Err("página de requisições só de leitura");
    };
    bytes[DATA_AT..DATA_AT + SECTOR].copy_from_slice(&sent);
    disk.request(T_OUT, SELF_TEST_SECTOR)?;
    disk.req.bytes_mut().ok_or("página só de leitura")?[DATA_AT..DATA_AT + SECTOR].fill(0);
    disk.request(T_IN, SELF_TEST_SECTOR)?;
    let got = &disk.req.bytes()[DATA_AT..DATA_AT + SECTOR];
    if optcrypt::blake3::hash(got) != optcrypt::blake3::hash(&sent) {
        return Err("o setor lido difere do escrito");
    }
    Ok(())
}

/// O que o laço sabe de um pedido em voo, por cabeça de cadeia.
#[derive(Clone, Copy)]
struct Voo {
    id: u64,
    slot: usize,
}

/// `id` de um pedido em voo cujo cliente morreu: nunca vai para o anel de
/// conclusões do cliente novo (ADR 0067).
const ORFAO: u64 = u64::MAX;

/// Um pedido lido do anel de submissões (ADR 0056, item 4).
#[derive(Clone, Copy)]
struct Pedido {
    id: u64,
    op: u8,
    flags: u8,
    count: u16,
    offset: u32,
    sector: u64,
}

impl Pedido {
    /// Lê os 24 bytes da carga; `None` se o tamanho não bate.
    fn parse(b: &[u8]) -> Option<Self> {
        if b.len() != 24 {
            return None;
        }
        Some(Self {
            id: u64::from_le_bytes(b[..8].try_into().ok()?),
            op: b[8],
            flags: b[9],
            count: u16::from_le_bytes([b[10], b[11]]),
            offset: u32::from_le_bytes(b[12..16].try_into().ok()?),
            sector: u64::from_le_bytes(b[16..24].try_into().ok()?),
        })
    }
}

/// Resultado de tentar iniciar um pedido.
enum Inicio {
    /// Foi para o dispositivo ou já concluiu.
    Feito,
    /// Sem slot (ou à espera de esvaziar, no `FLUSH`): tenta de novo depois.
    Espera(Pedido),
}

/// O driver em serviço: o disco e o estado do contrato `BlockDevice`.
struct Servico<'a> {
    disk: Disk<'a>,
    sectors: u64,
    read_only: bool,
    flush: bool,
    /// Cabeçalhos e status dos pedidos em voo (um slot cada).
    meta: Mapping,
    meta_at: u64,
    /// Endereço de DMA de cada página da região de dados.
    data_at: [u64; DEPTH],
    data_obj: Handle,
    submit_obj: Handle,
    submit_ntfy: Handle,
    /// O endpoint do contrato (para a sessão com `GRANT`).
    ep: Handle,
    submit: Consumer,
    done: Option<Producer>,
    used: [bool; DEPTH],
    voo: [Option<Voo>; QUEUE_SIZE],
    held: Option<Pedido>,
}

impl Servico<'_> {
    /// Conclui `id` no anel de conclusões (16 bytes: `id` e `status`).
    fn complete(&mut self, id: u64, status: u8) {
        if id == ORFAO {
            return;
        }
        if let Some(done) = self.done.as_mut() {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&id.to_le_bytes());
            b[8] = status;
            // Cheio só se o `storaged` passou de `depth`: o registro some e
            // o anel conta (`dropped`).
            let _ = done.push(REC_KIND, &b);
        }
    }

    /// Colhe o que o dispositivo terminou e confirma a IRQ.
    fn reap(&mut self) {
        loop {
            match self.disk.queue.pop() {
                Ok(Some(chain)) => {
                    let Some(v) = self
                        .voo
                        .get_mut(usize::from(chain.head))
                        .and_then(Option::take)
                    else {
                        continue;
                    };
                    self.used[v.slot] = false;
                    let status = self.meta.bytes()[v.slot * SLOT_BYTES + SLOT_STATUS];
                    let code = if status == 0 { 0 } else { BlockError::Io.0 };
                    self.complete(v.id, code);
                }
                Ok(None) => break,
                // Cadeia inválida: a entrada já foi consumida.
                Err(_) => {}
            }
        }
        if let Ok(bits) = ostd::cap::ntfy_poll(self.disk.irq.ntfy)
            && bits & 1 != 0
        {
            let _ = ostd::dev::irq_ack(self.disk.irq.irq);
        }
    }

    fn em_voo(&self) -> usize {
        self.used.iter().filter(|u| **u).count()
    }

    /// Valida e inicia um pedido.
    fn start(&mut self, req: Pedido) -> Inicio {
        let reject = |me: &mut Self, e: BlockError| {
            me.complete(req.id, e.0);
            Inicio::Feito
        };
        if req.flags != 0 {
            return reject(self, BlockError::BadRequest);
        }
        if req.op == OP_FLUSH {
            if req.count != 0 {
                return reject(self, BlockError::BadRequest);
            }
            // Barreira: só conclui (ou vai ao dispositivo) sem nada em voo.
            if self.em_voo() > 0 {
                return Inicio::Espera(req);
            }
            if !self.flush {
                self.complete(req.id, 0);
                return Inicio::Feito;
            }
            return self.send(req, T_FLUSH, &[]);
        }
        let (kind, write) = match req.op {
            OP_READ => (T_IN, false),
            OP_WRITE => (T_OUT, true),
            _ => return reject(self, BlockError::BadRequest),
        };
        let page = req.offset as usize / PAGE;
        if req.count == 0
            || req.count > MAX_SECTORS
            || !(req.offset as usize).is_multiple_of(PAGE)
            || page >= DEPTH
        {
            return reject(self, BlockError::BadRequest);
        }
        match req.sector.checked_add(u64::from(req.count)) {
            Some(end) if end <= self.sectors => {}
            _ => return reject(self, BlockError::OutOfRange),
        }
        if write && self.read_only {
            return reject(self, BlockError::ReadOnly);
        }
        let len = u32::from(req.count) * SECTOR as u32;
        self.send(req, kind, &[(self.data_at[page], len, !write)])
    }

    /// Monta a cadeia (cabeçalho, dados opcionais, status) e notifica.
    fn send(&mut self, req: Pedido, kind: u32, data: &[(u64, u32, bool)]) -> Inicio {
        let Some(slot) = self.used.iter().position(|u| !*u) else {
            return Inicio::Espera(req);
        };
        if self.disk.queue.free() < data.len() + 2 {
            return Inicio::Espera(req);
        }
        let base = slot * SLOT_BYTES;
        let Some(bytes) = self.meta.bytes_mut() else {
            self.complete(req.id, BlockError::Io.0);
            return Inicio::Feito;
        };
        bytes[base..base + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[base + 4..base + 8].fill(0);
        bytes[base + 8..base + 16].copy_from_slice(&req.sector.to_le_bytes());
        bytes[base + SLOT_STATUS] = 0xFF;
        let at = self.meta_at + base as u64;
        let mut segs = [Seg {
            addr: at,
            len: 16,
            write: false,
        }; 3];
        let mut n = 1;
        for &(addr, len, write) in data {
            segs[n] = Seg { addr, len, write };
            n += 1;
        }
        segs[n] = Seg {
            addr: at + SLOT_STATUS as u64,
            len: 1,
            write: true,
        };
        n += 1;
        let Ok(head) = self.disk.queue.push(&segs[..n]) else {
            self.complete(req.id, BlockError::Io.0);
            return Inicio::Feito;
        };
        self.used[slot] = true;
        self.voo[usize::from(head)] = Some(Voo { id: req.id, slot });
        self.disk.notify.write16(self.disk.notify_at, 0);
        Inicio::Feito
    }

    /// Lê o anel de submissões enquanto houver pedido e espaço.
    fn accept(&mut self) {
        if self.done.is_none() {
            return;
        }
        let mut raw = [0u8; 32];
        loop {
            let req = if let Some(r) = self.held.take() {
                r
            } else {
                match self.submit.pop(&mut raw) {
                    Ok(Some((REC_KIND, n))) => {
                        if let Some(r) = Pedido::parse(&raw[..n]) {
                            r
                        } else {
                            if n >= 8 {
                                let id = u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8]));
                                self.complete(id, BlockError::BadRequest.0);
                            }
                            continue;
                        }
                    }
                    Ok(Some(_)) => continue,
                    Ok(None) | Err(_) => break,
                }
            };
            if let Inicio::Espera(r) = self.start(req) {
                self.held = Some(r);
                break;
            }
        }
    }

    /// O cliente anterior morreu e o `svcmgr` partiu outro (ADR 0067): larga
    /// o anel de conclusões dele, descarta o que ele deixou na fila de
    /// submissão e espera o dispositivo terminar o que estava em voo, para
    /// que nenhum DMA caia numa página que o cliente novo vai usar.
    fn reset_session(&mut self) {
        self.done = None;
        self.held = None;
        let mut raw = [0u8; 32];
        while matches!(self.submit.pop(&mut raw), Ok(Some(_))) {}
        let until = ostd::time::now_ns().saturating_add(ORFAO_NS);
        while self.voo.iter().any(Option::is_some) && ostd::time::now_ns() < until {
            self.reap();
            ostd::thread::yield_now();
        }
        // O que o dispositivo não devolveu a tempo fica sem dono.
        for v in self.voo.iter_mut().flatten() {
            v.id = ORFAO;
        }
    }

    /// Um passo do laço: conclusões primeiro, depois pedidos novos.
    fn pump(&mut self) {
        self.reap();
        self.accept();
    }
}

/// Cópia de `h` com `rights` e `badge`, para ir na resposta.
fn grant(h: Handle, rights: Rights, badge: u64) -> Result<u64, BlockError> {
    ostd::cap::mint(h, rights, badge, None)
        .map(|c| u64::from(c.raw()))
        .map_err(|_| BlockError::Io)
}

/// Quanto o driver espera o dispositivo terminar os pedidos do cliente morto.
const ORFAO_NS: u64 = 500_000_000;

/// Badge da sessão (o `storaged`): distingue a capability com `GRANT`.
const SESSION_BADGE: u64 = 1;

impl BlockDevice for Servico<'_> {
    fn info(&mut self, _ctx: &Contexto) -> Result<BlockInfo, BlockError> {
        Ok(BlockInfo {
            sectors: self.sectors,
            sector_size: SECTOR as u32,
            data_bytes: DATA_BYTES as u32,
            ring_bytes: RING_BYTES,
            max_sectors: MAX_SECTORS,
            depth: DEPTH as u16,
            read_only: self.read_only,
            flush: self.flush,
        })
    }

    fn session(&mut self, _ctx: &Contexto) -> Result<u64, BlockError> {
        grant(self.ep, Rights::SEND | Rights::GRANT, SESSION_BADGE)
    }

    fn submit_ring(&mut self, _ctx: &Contexto) -> Result<u64, BlockError> {
        grant(
            self.submit_obj,
            Rights::MAP | Rights::READ | Rights::WRITE,
            0,
        )
    }

    fn submit_signal(&mut self, _ctx: &Contexto) -> Result<u64, BlockError> {
        grant(self.submit_ntfy, Rights::SIGNAL, 0)
    }

    fn data_region(&mut self, _ctx: &Contexto) -> Result<u64, BlockError> {
        grant(self.data_obj, Rights::MAP | Rights::READ | Rights::WRITE, 0)
    }

    fn attach_done(&mut self, ctx: &Contexto, ring: u64, signal: u64) -> Result<(), BlockError> {
        if ctx.badge & 0xFFFF_FFFF != SESSION_BADGE {
            return Err(BlockError::BadRequest);
        }
        if self.done.is_some() {
            // Só o `storaged` tem a sessão (ADR 0067): outro pedido de
            // anexo é o `storaged` novo, depois da morte do antigo.
            self.reset_session();
        }
        let (Ok(ring), Ok(signal)) = (u32::try_from(ring), u32::try_from(signal)) else {
            return Err(BlockError::BadRequest);
        };
        let done = Producer::open(
            Handle::from_raw(ring),
            DONE_VA,
            RING_BYTES,
            Handle::from_raw(signal),
            1,
        )
        .map_err(|_| BlockError::BadRequest)?;
        self.done = Some(done);
        Ok(())
    }
}

/// Atende o contrato `BlockDevice` em `ep` até o endpoint ser revogado.
fn serve(ep: Handle, quota: Handle, buf: &mut ipc::Buffer, svc: &mut Servico<'_>) -> Error {
    let svc = RefCell::new(svc);
    vdrv::serve::serve(
        ep,
        quota,
        buf,
        POLL_NS,
        &mut || svc.borrow_mut().pump(),
        &mut |req, saida, caps_out| {
            let entrada = block_servidor::Entrada {
                rotulo: req.rotulo,
                badge: req.badge,
                corpo: req.corpo,
                caps: req.caps,
            };
            let d = block_servidor::despacha_block_device(
                &mut **svc.borrow_mut(),
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

#[allow(clippy::too_many_lines)]
fn run(s: &mut Session, quota: Handle) -> Result<(), &'static str> {
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
    let features = transport
        .negotiate(F_ACCESS_PLATFORM | F_FLUSH | F_RO, required)
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
    // 4. O contrato: anel de submissões, região de dados e cabeçalhos.
    let rw = ostd::kabi::vm::WRITE;
    let meta_obj = ostd::cap::create(quota, ObjectType::MemoryObject, PAGE as u64)
        .map_err(|_| "página de cabeçalhos")?;
    let data_obj = ostd::cap::create(quota, ObjectType::MemoryObject, DATA_BYTES as u64)
        .map_err(|_| "região de dados")?;
    let submit_obj = ostd::cap::create(
        quota,
        ObjectType::MemoryObject,
        ostd::ring::object_bytes(RING_BYTES),
    )
    .map_err(|_| "anel de submissões")?;
    let submit_ntfy =
        ostd::cap::create(quota, ObjectType::Notification, 0).map_err(|_| "notificação do anel")?;
    let meta =
        Mapping::new(SELF, meta_obj, META_VA, PAGE as u64, rw).map_err(|_| "mapear cabeçalhos")?;
    let _data = Mapping::new(SELF, data_obj, DATA_VA, DATA_BYTES as u64, rw)
        .map_err(|_| "mapear a região de dados")?;
    let meta_at = ostd::dev::dma_map(domain, meta_obj, META_IOVA, 0, PAGE as u64, true)
        .map_err(|_| "dma_map de cabeçalhos")?;
    let mut data_at = [0u64; DEPTH];
    for (i, at) in data_at.iter_mut().enumerate() {
        let off = (i * PAGE) as u64;
        *at = ostd::dev::dma_map(domain, data_obj, DATA_IOVA + off, off, PAGE as u64, true)
            .map_err(|_| "dma_map da região de dados")?;
    }
    let submit = Consumer::create(submit_obj, SUBMIT_VA, RING_BYTES, RING_KIND, submit_ntfy)
        .map_err(|_| "criar o anel de submissões")?;
    let ep = s
        .boot
        .provided(ID_BLOCKDEVICE)
        .map(Handle::from_raw)
        .ok_or("descritor sem o endpoint do BlockDevice")?;
    let mut svc = Servico {
        disk,
        sectors,
        read_only: features & F_RO != 0,
        flush: features & F_FLUSH != 0,
        meta,
        meta_at,
        data_at,
        data_obj,
        submit_obj,
        submit_ntfy,
        ep,
        submit,
        done: None,
        used: [false; DEPTH],
        voo: [None; QUEUE_SIZE],
        held: None,
    };
    ostd::debug::print("virtio-blk: contrato BlockDevice pronto");
    let e = serve(ep, quota, &mut s.buffer, &mut svc);
    ostd::debug::print_fmt(format_args!("virtio-blk: encerrado ({e:?})"));
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
        ostd::debug::print_fmt(format_args!("virtio-blk: falhou: {e}"));
    }
    ostd::thread::exit()
}
