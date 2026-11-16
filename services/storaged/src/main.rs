//! `storaged` (T-520; ADR 0056 e 0066): lê a GPT do disco e serve cada
//! partição como `BlockStore`.
//!
//! 1. espera o driver (`optimus.block.BlockDevice`) pelo `svcmgr` e pega os
//!    anéis dele pelo contrato, como diz a ADR 0056, item 10;
//! 2. lê a GPT com a `ogpt` e guarda as partições alinhadas a 4 KiB;
//! 3. serve `Storage.open(nome)` (um `BlockStore` da partição, só com
//!    `SEND`) e o `BlockStore` (`open_queue`, `submit_ring`, `kick`...).
//!
//! O laço é um só (ADR 0060): bloqueia em `recv` com prazo curto e, a cada
//! volta, colhe as conclusões do driver, lê os anéis de submissão dos
//! clientes e leva os pedidos ao driver. Cada fila atende um pedido por vez,
//! na ordem; dentro do pedido, os blocos andam em paralelo até a
//! profundidade do driver. Entre as filas, vale a prioridade pedida, com um
//! pedido esperando mais de 100 ms subindo ao topo (ADR 0056, item 6).
//!
//! O `storaged` não guarda dados: só os pedidos em voo (item 7).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

mod block_cliente;
mod storage_servidor;

use block_cliente::BlockDeviceCliente;
use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::ring::{Consumer, Producer};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};
use storage_servidor::{
    BlockStore, Contexto, ID_BLOCKSTORE, ID_STORAGE, Info, IoError, Storage, despacha_block_store,
    despacha_storage,
};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Quanto esperar o driver partir e o intervalo entre as tentativas.
const WAIT_NS: u64 = 8_000_000_000;
const TRY_NS: u64 = 50_000_000;
const CALL_NS: u64 = 200_000_000;
/// Prazo de cada volta do laço: curto com pedidos em andamento, longo sem.
const BUSY_NS: u64 = 50_000;
const IDLE_NS: u64 = 2_000_000;
/// Um pedido esperando mais que isso sobe ao topo (ADR 0056, item 6).
const STARVE_NS: u64 = 100_000_000;
/// Intervalo da sondagem do driver (ADR 0072): `info` com prazo curto.
const PROBE_NS: u64 = 250_000_000;
/// Rótulo do método `info` do `BlockDevice` (corpo vazio).
const INFO_LABEL: u64 = 0x207C_D811_0000_0000;
/// Prazo da sondagem: o driver vivo responde em microssegundos.
const PROBE_CALL_NS: u64 = 100_000_000;
/// Espera entre duas tentativas de reconexão ao driver.
const REATTACH_NS: u64 = 50_000_000;
/// Espera de uma operação do driver durante a leitura da GPT.
const BOOT_IO_NS: u64 = 1_000_000_000;

const PAGE: usize = 4096;
/// Dados de cada anel (o mesmo que o driver informa).
const RING_BYTES: u32 = 4096;
/// Início da região de dados na área do cliente: depois do anel.
const AREA_HEAD: u64 = ostd::ring::object_bytes(RING_BYTES);
const RING_KIND: u16 = 0x0C01;
const DEV_DONE_KIND: u16 = 0x0B02;
const REC_KIND: u16 = 1;

const OP_READ: u8 = 0;
const OP_WRITE: u8 = 1;
const OP_FLUSH: u8 = 2;
const FLAG_FUA: u8 = 1;

/// Limites do contrato (ADR 0056, itens 3 e 8).
const MAX_DEPTH: u16 = 64;
const MAX_BLOCKS: u16 = 32;
const MAX_DATA_BLOCKS: u16 = 2048;
const MAX_PARTS: usize = 8;
const MAX_SESSIONS: usize = 16;
const MAX_QUEUES: usize = 8;
const QUEUES_PER_SESSION: u8 = 4;
/// Pedidos em voo no driver, no máximo (o `depth` dele é menor).
const MAX_SLOTS: usize = 16;

/// Onde os anéis do driver e as áreas dos clientes ficam mapeados.
const DEV_SUBMIT_VA: u64 = 0x40_0000_0000;
const DEV_DONE_VA: u64 = 0x40_0010_0000;
const DEV_DATA_VA: u64 = 0x40_0020_0000;
/// O driver reiniciado é mapeado no outro banco, para o novo `Dev` nascer
/// antes de o velho ser desmapeado (ADR 0072).
const DEV_BANK_STRIDE: u64 = 0x400_0000;
const Q_VA: u64 = 0x41_0000_0000;
const Q_STRIDE: u64 = 0x1000_0000;
const Q_AREA_OFF: u64 = 0x10_0000;

/// Badge das capabilities `BlockStore` que o próprio `storaged` cunha: a
/// marca, a sessão e a partição.
const BADGE_TAG: u64 = 1 << 48;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// `interface_id(nome, 1)` (ADR 0033).
fn interface_id(name: &[u8]) -> u32 {
    let mut full = [0u8; 64];
    full[..name.len()].copy_from_slice(name);
    full[name.len()..name.len() + 2].copy_from_slice(b"@1");
    hash(&full[..name.len() + 2])
}

/// Cede a vez até passar `ns`.
fn pause(ns: u64) {
    let until = ostd::time::now_ns().saturating_add(ns);
    while ostd::time::now_ns() < until {
        ostd::thread::yield_now();
    }
}

/// Espera o driver partir: `connect` devolve `NotRunning` até ele chamar
/// `ready`.
fn connect(s: &mut Session, name: &[u8]) -> Option<Handle> {
    let iid = interface_id(name);
    let until = ostd::time::now_ns().saturating_add(WAIT_NS);
    while ostd::time::now_ns() < until {
        let call_until = ostd::time::now_ns().saturating_add(CALL_NS);
        match s.connect_svc_until(iid, 0, call_until) {
            Ok(Ok(h)) => return Some(h),
            Err(Error::TimedOut) | Ok(Err(_)) => {}
            Err(_) => return None,
        }
        pause(TRY_NS);
    }
    None
}

/// Cópia de `h` com `rights` e `badge`, para ir na resposta.
fn grant(h: Handle, rights: Rights, badge: u64) -> Result<u64, IoError> {
    ostd::cap::mint(h, rights, badge, None)
        .map(|c| u64::from(c.raw()))
        .map_err(|_| IoError::Io)
}

/// Um pedido lido de um anel de submissão (ADR 0056, item 4).
#[derive(Clone, Copy)]
struct Req {
    id: u64,
    op: u8,
    flags: u8,
    count: u16,
    offset: u32,
    block: u64,
}

impl Req {
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
            block: u64::from_le_bytes(b[16..24].try_into().ok()?),
        })
    }
}

/// O que um pedido ao driver faz.
#[derive(Clone, Copy)]
enum Kind {
    /// O bloco `n` do pedido corrente de uma fila.
    Block(u16),
    /// O `FLUSH` do fim de um `FUA` ou de um `FLUSH` do cliente.
    Flush,
}

/// Um pedido em voo no driver (o `id` dele é o índice do slot).
#[derive(Clone, Copy)]
struct Slot {
    queue: u8,
    epoch: u32,
    kind: Kind,
}

/// As capabilities de uma ligação ao driver: apagadas quando a ligação some
/// (driver reiniciado, ADR 0072) ou falha no meio.
struct Held {
    caps: [Handle; 9],
    n: usize,
}

impl Held {
    fn new() -> Self {
        Self {
            caps: [Handle::from_raw(0); 9],
            n: 0,
        }
    }

    /// Guarda `h` para apagar depois e o devolve.
    fn keep(&mut self, h: Handle) -> Handle {
        if self.n < self.caps.len() {
            self.caps[self.n] = h;
            self.n += 1;
        }
        h
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        for h in &self.caps[..self.n] {
            let _ = ostd::cap::delete(*h);
        }
    }
}

/// O disco: os anéis do contrato `BlockDevice` e os pedidos em voo.
struct Dev {
    /// O endpoint do driver, para sondá-lo.
    ep: Handle,
    submit: Producer,
    done: Consumer,
    data: Mapping,
    sectors: u64,
    sector_size: usize,
    /// Setores de um bloco de 4 KiB.
    per_block: u16,
    flush: bool,
    read_only: bool,
    nslots: usize,
    slots: [Option<Slot>; MAX_SLOTS],
    /// Fica depois dos mapeamentos nos campos: as capabilities saem por último.
    _held: Held,
}

impl Dev {
    /// Liga ao driver pelo contrato: `info`, a sessão, os anéis e a região de
    /// dados, e entrega o anel de conclusões (papéis da ADR 0061).
    fn attach(ep: Handle, buf: &mut ipc::Buffer, quota: Handle, bank: u64) -> Option<Self> {
        let mut held = Held::new();
        let ep = held.keep(ep);
        let off = bank * DEV_BANK_STRIDE;
        let cli = BlockDeviceCliente::new(ep);
        let info = cli.info(buf).ok()?.ok()?;
        if (info.sector_size != 512 && info.sector_size != 4096)
            || info.ring_bytes != RING_BYTES
            || info.depth == 0
            || (info.data_bytes as usize) < PAGE
            || usize::from(info.max_sectors) < PAGE / info.sector_size as usize
        {
            return None;
        }
        let session = BlockDeviceCliente::new(held.keep(cli.session(buf).ok()?.ok()?));
        let submit_obj = held.keep(session.submit_ring(buf).ok()?.ok()?);
        let submit_sig = held.keep(session.submit_signal(buf).ok()?.ok()?);
        let data_obj = held.keep(session.data_region(buf).ok()?.ok()?);
        let done_obj = held.keep(
            ostd::cap::create(
                quota,
                ObjectType::MemoryObject,
                ostd::ring::object_bytes(RING_BYTES),
            )
            .ok()?,
        );
        let done_ntfy = held.keep(ostd::cap::create(quota, ObjectType::Notification, 0).ok()?);
        let done = Consumer::create(
            done_obj,
            DEV_DONE_VA + off,
            RING_BYTES,
            DEV_DONE_KIND,
            done_ntfy,
        )
        .ok()?;
        let done_sig = held.keep(ostd::cap::mint(done_ntfy, Rights::SIGNAL, 0, None).ok()?);
        let done_rw = held.keep(
            ostd::cap::mint(
                done_obj,
                Rights::MAP | Rights::READ | Rights::WRITE,
                0,
                None,
            )
            .ok()?,
        );
        session.attach_done(buf, done_rw, done_sig).ok()?.ok()?;
        let submit =
            Producer::open(submit_obj, DEV_SUBMIT_VA + off, RING_BYTES, submit_sig, 1).ok()?;
        let pages = (info.data_bytes as usize / PAGE).min(MAX_SLOTS);
        let data = Mapping::new(
            SELF,
            data_obj,
            DEV_DATA_VA + off,
            (pages * PAGE) as u64,
            ostd::kabi::vm::WRITE,
        )
        .ok()?;
        Some(Self {
            ep,
            submit,
            done,
            data,
            sectors: info.sectors,
            sector_size: info.sector_size as usize,
            per_block: (PAGE / info.sector_size as usize) as u16,
            flush: info.flush,
            read_only: info.read_only,
            nslots: pages.min(usize::from(info.depth)),
            slots: [None; MAX_SLOTS],
            _held: held,
        })
    }

    fn free_slot(&self) -> Option<usize> {
        self.slots[..self.nslots].iter().position(Option::is_none)
    }

    fn in_flight(&self) -> bool {
        self.slots.iter().any(Option::is_some)
    }

    /// Manda ao driver o pedido `op` do slot `slot` (a página dele tem os
    /// dados). `false` se o anel recusou.
    fn send(&mut self, slot: usize, op: u8, sector: u64, count: u16) -> bool {
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&(slot as u64).to_le_bytes());
        b[8] = op;
        b[10..12].copy_from_slice(&count.to_le_bytes());
        b[12..16].copy_from_slice(&((slot * PAGE) as u32).to_le_bytes());
        b[16..24].copy_from_slice(&sector.to_le_bytes());
        self.submit.push(REC_KIND, &b).is_ok()
    }

    /// A próxima conclusão do driver: o slot e o status.
    fn next_done(&mut self) -> Option<(usize, u8)> {
        let mut rec = [0u8; 16];
        match self.done.pop(&mut rec) {
            Ok(Some((_, 16))) => {
                let id = u64::from_le_bytes(rec[..8].try_into().ok()?);
                Some((usize::try_from(id).ok()?, rec[8]))
            }
            _ => None,
        }
    }

    fn page(&self, slot: usize) -> &[u8] {
        &self.data.bytes()[slot * PAGE..(slot + 1) * PAGE]
    }
}

/// Leitura da GPT pelo driver: um setor por vez, esperando a conclusão.
struct Boot<'a>(&'a mut Dev);

impl ogpt::Disk for Boot<'_> {
    fn sector_size(&self) -> usize {
        self.0.sector_size
    }

    fn sectors(&self) -> u64 {
        self.0.sectors
    }

    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        let dev = &mut *self.0;
        if buf.len() != dev.sector_size || !dev.send(0, OP_READ, lba, 1) {
            return false;
        }
        let until = ostd::time::now_ns().saturating_add(BOOT_IO_NS);
        while ostd::time::now_ns() < until {
            match dev.next_done() {
                Some((0, 0)) => {
                    buf.copy_from_slice(&dev.page(0)[..buf.len()]);
                    return true;
                }
                Some(_) => return false,
                None => ostd::thread::yield_now(),
            }
        }
        false
    }
}

/// Uma partição que o `storaged` expõe.
#[derive(Clone, Copy)]
struct Part {
    /// Primeiro setor do dispositivo.
    first: u64,
    /// Blocos de 4 KiB.
    blocks: u64,
    name: [u8; 36],
    name_len: usize,
    /// Só de leitura: as `sys-*` no M5 (o slot ativo é do `updated`, depois
    /// do Gate 2).
    read_only: bool,
}

impl Part {
    fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Uma sessão aberta por `Storage.open`.
#[derive(Clone, Copy)]
struct Sess {
    part: usize,
    queues: u8,
    /// Quem abriu: id do serviço e geração (os 48 bits baixos do badge do
    /// `svcmgr`, ADR 0034, item 8). Geração diferente do mesmo id é o
    /// cliente que morreu e foi reiniciado (ADR 0072).
    owner: u64,
}

/// Um pedido da fila em andamento.
#[derive(Clone, Copy)]
struct Cur {
    req: Req,
    issued: u16,
    done: u16,
    /// Primeiro erro do driver (0 = nenhum).
    status: u8,
    /// O `FLUSH` do fim (de um `FUA` ou do próprio pedido) já foi ao driver.
    flushing: bool,
}

/// Uma fila aberta por `open_queue`.
struct Queue {
    sess: usize,
    epoch: u32,
    priority: u8,
    data_len: u64,
    submit: Consumer,
    submit_obj: Handle,
    kick: Handle,
    /// O anel de conclusões do cliente.
    done: Producer,
    /// A região de dados do cliente (depois do anel).
    area: Mapping,
    area_obj: Handle,
    done_ntfy: Handle,
    cur: Option<Cur>,
    /// Desde quando o pedido corrente espera um slot do driver (0 = não).
    waiting: u64,
}

impl Queue {
    /// Conclui `id` no anel do cliente. Cheio só se o cliente passou de
    /// `depth`: o registro some e o anel conta.
    fn complete(&mut self, id: u64, status: u8) {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&id.to_le_bytes());
        b[8] = status;
        let _ = self.done.push(REC_KIND, &b);
    }
}

/// O serviço: o disco, as partições, as sessões e as filas.
struct Servico {
    dev: Dev,
    parts: [Option<Part>; MAX_PARTS],
    sess: [Option<Sess>; MAX_SESSIONS],
    queues: [Option<Queue>; MAX_QUEUES],
    quota: Handle,
    ep: Handle,
    next_epoch: u32,
    /// Banco de endereços da ligação atual ao driver (alterna a cada
    /// reconexão).
    bank: u64,
    /// O driver morreu: pedidos concluem com `Reset` até reconectar.
    down: bool,
    /// Próxima sondagem do driver (ns) ou, com `down`, próxima tentativa.
    next_check: u64,
}

impl Servico {
    /// Valida um pedido de leitura ou escrita da fila `qi`.
    fn check(&self, qi: usize, req: &Req) -> Result<(), IoError> {
        let Some(q) = self.queues[qi].as_ref() else {
            return Err(IoError::BadRequest);
        };
        let part = self.parts[self.sess[q.sess].map_or(0, |s| s.part)]
            .as_ref()
            .ok_or(IoError::BadRequest)?;
        match req.op {
            OP_READ | OP_WRITE => {}
            OP_FLUSH => {
                return if req.count == 0 && req.flags == 0 {
                    Ok(())
                } else {
                    Err(IoError::BadRequest)
                };
            }
            _ => return Err(IoError::BadRequest),
        }
        let fua_ok = req.op == OP_WRITE || req.flags == 0;
        if req.flags & !FLAG_FUA != 0
            || !fua_ok
            || req.count == 0
            || req.count > MAX_BLOCKS
            || !req.offset.is_multiple_of(PAGE as u32)
            || u64::from(req.offset) + u64::from(req.count) * PAGE as u64 > q.data_len
        {
            return Err(IoError::BadRequest);
        }
        if req
            .block
            .checked_add(u64::from(req.count))
            .is_none_or(|end| end > part.blocks)
        {
            return Err(IoError::OutOfRange);
        }
        if req.op == OP_WRITE && (part.read_only || self.dev.read_only) {
            return Err(IoError::ReadOnly);
        }
        Ok(())
    }

    /// Conclui o pedido corrente da fila `qi` com `status`.
    fn finish(&mut self, qi: usize, status: u8) {
        if let Some(q) = self.queues[qi].as_mut()
            && let Some(cur) = q.cur.take()
        {
            q.complete(cur.req.id, status);
            q.waiting = 0;
        }
    }

    /// Trata uma conclusão do driver.
    fn on_done(&mut self, slot: usize, status: u8) {
        let Some(s) = self.dev.slots.get_mut(slot).and_then(Option::take) else {
            return;
        };
        let qi = usize::from(s.queue);
        let live = self.queues[qi].as_ref().is_some_and(|q| q.epoch == s.epoch);
        if !live {
            return;
        }
        match s.kind {
            Kind::Block(n) => {
                let dev = &self.dev;
                let Some(q) = self.queues[qi].as_mut() else {
                    return;
                };
                let Some(cur) = q.cur.as_mut() else { return };
                cur.done += 1;
                if status != 0 {
                    if cur.status == 0 {
                        cur.status = status;
                    }
                } else if cur.req.op == OP_READ {
                    let at = cur.req.offset as usize + usize::from(n) * PAGE;
                    let src = dev.page(slot);
                    if let Some(dst) = q.area.bytes_mut().and_then(|a| a.get_mut(at..at + PAGE)) {
                        dst.copy_from_slice(src);
                    } else {
                        cur.status = IoError::Io.0;
                    }
                }
            }
            Kind::Flush => {
                let st = self.queues[qi]
                    .as_ref()
                    .and_then(|q| q.cur.as_ref())
                    .map_or(0, |c| c.status);
                let code = if status != 0 && st == 0 { status } else { st };
                self.finish(qi, code);
            }
        }
    }

    /// Anda o pedido corrente da fila `qi`: manda blocos ao driver enquanto
    /// houver slot e conclui o pedido quando o driver terminou.
    #[allow(clippy::too_many_lines)]
    fn advance(&mut self, qi: usize) -> bool {
        let mut progress = false;
        loop {
            let Some(cur) = self.queues[qi].as_ref().and_then(|q| q.cur) else {
                return progress;
            };
            let count = cur.req.count;
            if cur.req.op == OP_FLUSH {
                // Barreira da fila: nada seu em voo, depois o `FLUSH`.
                if cur.flushing {
                    return progress;
                }
                if !self.dev.flush {
                    self.finish(qi, 0);
                    progress = true;
                    continue;
                }
                if self.send_flush(qi) {
                    progress = true;
                }
                return progress;
            }
            if cur.issued < count {
                if self.issue_block(qi) {
                    progress = true;
                    continue;
                }
                return progress;
            }
            if cur.done < count {
                return progress;
            }
            // Todos os blocos voltaram.
            if cur.status == 0
                && cur.req.op == OP_WRITE
                && cur.req.flags & FLAG_FUA != 0
                && self.dev.flush
                && !cur.flushing
            {
                if self.send_flush(qi) {
                    progress = true;
                }
                return progress;
            }
            if cur.flushing {
                return progress;
            }
            self.finish(qi, cur.status);
            progress = true;
        }
    }

    /// Manda o bloco `issued` do pedido corrente de `qi`. `false` sem slot.
    fn issue_block(&mut self, qi: usize) -> bool {
        let Some(slot) = self.dev.free_slot() else {
            return false;
        };
        let (cur, epoch, part_first) = {
            let Some(q) = self.queues[qi].as_ref() else {
                return false;
            };
            let Some(cur) = q.cur else { return false };
            let first = self.parts[self.sess[q.sess].map_or(0, |s| s.part)]
                .as_ref()
                .map_or(0, |p| p.first);
            (cur, q.epoch, first)
        };
        let n = cur.issued;
        let sector = part_first + (cur.req.block + u64::from(n)) * u64::from(self.dev.per_block);
        let at = cur.req.offset as usize + usize::from(n) * PAGE;
        if cur.req.op == OP_WRITE {
            let ok = {
                let Some(src) = self.queues[qi]
                    .as_ref()
                    .and_then(|q| q.area.bytes().get(at..at + PAGE))
                else {
                    return self.fail_block(qi);
                };
                match self.dev.data.bytes_mut() {
                    Some(d) => {
                        d[slot * PAGE..(slot + 1) * PAGE].copy_from_slice(src);
                        true
                    }
                    None => false,
                }
            };
            if !ok {
                return self.fail_block(qi);
            }
        }
        let op = if cur.req.op == OP_WRITE {
            OP_WRITE
        } else {
            OP_READ
        };
        if !self.dev.send(slot, op, sector, self.dev.per_block) {
            return self.fail_block(qi);
        }
        self.dev.slots[slot] = Some(Slot {
            queue: qi as u8,
            epoch,
            kind: Kind::Block(n),
        });
        if let Some(c) = self.queues[qi].as_mut().and_then(|q| q.cur.as_mut()) {
            c.issued += 1;
        }
        true
    }

    /// Um bloco que não foi ao driver conta como feito com erro.
    fn fail_block(&mut self, qi: usize) -> bool {
        if let Some(c) = self.queues[qi].as_mut().and_then(|q| q.cur.as_mut()) {
            c.issued += 1;
            c.done += 1;
            if c.status == 0 {
                c.status = IoError::Io.0;
            }
        }
        true
    }

    /// Manda um `FLUSH` ao driver pela fila `qi`.
    fn send_flush(&mut self, qi: usize) -> bool {
        let in_flight_own = self
            .dev
            .slots
            .iter()
            .flatten()
            .any(|s| usize::from(s.queue) == qi);
        if in_flight_own {
            return false;
        }
        let Some(slot) = self.dev.free_slot() else {
            return false;
        };
        let Some(epoch) = self.queues[qi].as_ref().map(|q| q.epoch) else {
            return false;
        };
        if !self.dev.send(slot, OP_FLUSH, 0, 0) {
            self.finish(qi, IoError::Io.0);
            return true;
        }
        self.dev.slots[slot] = Some(Slot {
            queue: qi as u8,
            epoch,
            kind: Kind::Flush,
        });
        if let Some(c) = self.queues[qi].as_mut().and_then(|q| q.cur.as_mut()) {
            c.flushing = true;
        }
        true
    }

    /// Tira o próximo pedido da fila `qi` se não há pedido corrente. Os
    /// inválidos concluem na hora com o erro.
    fn take(&mut self, qi: usize) -> bool {
        let mut progress = false;
        loop {
            let Some(q) = self.queues[qi].as_mut() else {
                return progress;
            };
            if q.cur.is_some() {
                return progress;
            }
            let mut rec = [0u8; 24];
            let req = match q.submit.pop(&mut rec) {
                Ok(Some((_, n))) => Req::parse(&rec[..n]),
                // Vazio, ou corrompido pelo cliente (o anel não serve mais).
                Ok(None) | Err(_) => return progress,
            };
            progress = true;
            let Some(req) = req else { continue };
            match self.check(qi, &req) {
                Ok(()) => {
                    if let Some(q) = self.queues[qi].as_mut() {
                        q.cur = Some(Cur {
                            req,
                            issued: 0,
                            done: 0,
                            status: 0,
                            flushing: false,
                        });
                        q.waiting = ostd::time::now_ns();
                    }
                    return true;
                }
                Err(e) => {
                    if let Some(q) = self.queues[qi].as_mut() {
                        q.complete(req.id, e.0);
                    }
                }
            }
        }
    }

    /// Ordem de atendimento: pedidos esperando há mais de `STARVE_NS`
    /// primeiro, depois a maior prioridade (FIFO entre iguais).
    fn order(&self) -> ([usize; MAX_QUEUES], usize) {
        let now = ostd::time::now_ns();
        let mut idx = [0usize; MAX_QUEUES];
        let mut n = 0;
        for (i, q) in self.queues.iter().enumerate() {
            if q.is_some() {
                idx[n] = i;
                n += 1;
            }
        }
        let key = |i: usize| -> (bool, u8) {
            self.queues[i].as_ref().map_or((false, 0), |q| {
                let starved = q.waiting != 0 && now.saturating_sub(q.waiting) > STARVE_NS;
                (starved, q.priority)
            })
        };
        // Inserção: poucos elementos, estável.
        for a in 1..n {
            let mut b = a;
            while b > 0 && key(idx[b]) > key(idx[b - 1]) {
                idx.swap(b, b - 1);
                b -= 1;
            }
        }
        (idx, n)
    }

    /// Uma volta: colhe o driver e anda as filas.
    fn pump(&mut self) {
        if self.down {
            self.reset_queues();
            return;
        }
        loop {
            let mut progress = false;
            while let Some((slot, status)) = self.dev.next_done() {
                self.on_done(slot, status);
                progress = true;
            }
            let (idx, n) = self.order();
            for &qi in &idx[..n] {
                progress |= self.take(qi);
                progress |= self.advance(qi);
            }
            if !progress {
                return;
            }
        }
    }

    /// Um `open` de `owner` prova que o cliente daquele id está numa geração
    /// nova: as sessões de gerações antigas do mesmo id são de um cliente
    /// morto e o `svcmgr` já revogou as capabilities dele. Fecha as filas e
    /// devolve as sessões (ADR 0072).
    fn reap_dead(&mut self, owner: u64) {
        let id = owner & 0xFFFF_FFFF;
        for sess in 0..MAX_SESSIONS {
            let Some(s) = self.sess[sess] else { continue };
            if s.owner & 0xFFFF_FFFF != id || s.owner == owner {
                continue;
            }
            let mut queues = 0;
            for qi in 0..MAX_QUEUES {
                if self.queues[qi].as_ref().is_some_and(|q| q.sess == sess) {
                    self.drop_queue(qi);
                    queues += 1;
                }
            }
            self.sess[sess] = None;
            ostd::debug::print_fmt(format_args!(
                "storaged: cliente {id} morreu (geração {} -> {}): sessão {sess} e {queues} fila(s) liberadas",
                s.owner >> 32,
                owner >> 32
            ));
        }
    }

    /// Dá o driver por morto: o que estava em voo e o que está esperando
    /// concluem com `Reset`; os clientes refazem (ADR 0056, ADR 0072).
    fn driver_down(&mut self) {
        ostd::debug::print("storaged: driver de bloco morreu; pedidos concluem com Reset");
        self.dev.slots = [None; MAX_SLOTS];
        self.down = true;
        self.next_check = 0;
        self.reset_queues();
    }

    /// Conclui com `Reset` o pedido corrente e tudo o que os clientes já
    /// submeteram.
    fn reset_queues(&mut self) {
        for qi in 0..MAX_QUEUES {
            self.finish(qi, IoError::Reset.0);
            let Some(q) = self.queues[qi].as_mut() else {
                continue;
            };
            let mut rec = [0u8; 24];
            while let Ok(Some((_, n))) = q.submit.pop(&mut rec) {
                if n >= 8 {
                    let id = u64::from_le_bytes(rec[..8].try_into().unwrap_or([0; 8]));
                    q.complete(id, IoError::Reset.0);
                }
            }
        }
    }

    /// Vigia o driver (ADR 0072): sonda de tempos em tempos e quando há
    /// pedido em voo há muito tempo; com o driver morto, tenta ligar ao
    /// novo. Só roda com o buffer livre (laço sem resposta pendente).
    fn maintain(&mut self, s: &mut Session) {
        let now = ostd::time::now_ns();
        if now < self.next_check {
            return;
        }
        if self.down {
            self.next_check = now.saturating_add(REATTACH_NS);
            self.reattach(s);
            return;
        }
        self.next_check = now.saturating_add(PROBE_NS);
        let deadline = now.saturating_add(PROBE_CALL_NS);
        let r = ipc::call_palavras(
            self.dev.ep,
            INFO_LABEL,
            [0; ostd::kabi::MSG_REG_WORDS],
            deadline,
        );
        if matches!(r, Err(Error::PeerClosed | Error::InvalidHandle)) {
            self.driver_down();
        }
    }

    /// Liga ao `BlockDevice` novo que o `svcmgr` partiu.
    fn reattach(&mut self, s: &mut Session) {
        let iid = interface_id(b"optimus.block.BlockDevice");
        let deadline = ostd::time::now_ns().saturating_add(CALL_NS);
        let Ok(Ok(ep)) = s.connect_svc_until(iid, 0, deadline) else {
            return;
        };
        let bank = self.bank ^ 1;
        let Some(dev) = Dev::attach(ep, &mut s.buffer, self.quota, bank) else {
            return;
        };
        if dev.sectors != self.dev.sectors || dev.sector_size != self.dev.sector_size {
            return;
        }
        self.dev = dev;
        self.bank = bank;
        self.down = false;
        self.next_check = ostd::time::now_ns().saturating_add(PROBE_NS);
        ostd::debug::print("storaged: driver de bloco de volta; E/S retomada");
    }

    fn busy(&self) -> bool {
        self.dev.in_flight() || self.queues.iter().flatten().any(|q| q.cur.is_some())
    }

    /// Sessão e partição de um badge do `BlockStore`.
    fn who(&self, badge: u64) -> Result<(usize, usize), IoError> {
        if badge & BADGE_TAG == 0 {
            return Err(IoError::BadRequest);
        }
        let sess = ((badge >> 8) & 0xFF) as usize;
        let s = self
            .sess
            .get(sess)
            .copied()
            .flatten()
            .ok_or(IoError::BadRequest)?;
        Ok((sess, s.part))
    }

    /// Fecha a fila `qi`: os pedidos dela que ainda estão no driver
    /// terminam sem efeito no cliente (a `epoch` não bate mais).
    fn drop_queue(&mut self, qi: usize) {
        if let Some(q) = self.queues[qi].take() {
            if let Some(s) = self.sess.get_mut(q.sess).and_then(Option::as_mut) {
                s.queues = s.queues.saturating_sub(1);
            }
            for h in [q.submit_obj, q.kick, q.area_obj, q.done_ntfy] {
                let _ = ostd::cap::delete(h);
            }
        }
    }

    fn queue_of(&self, badge: u64, queue: u32) -> Result<usize, IoError> {
        let (sess, _) = self.who(badge)?;
        let qi = usize::try_from(queue).map_err(|_| IoError::BadRequest)?;
        match self.queues.get(qi) {
            Some(Some(q)) if q.sess == sess => Ok(qi),
            _ => Err(IoError::BadRequest),
        }
    }

    /// Cria a fila `qi` para a sessão `sess` sobre a área do cliente.
    #[allow(clippy::too_many_arguments)]
    fn make_queue(
        &mut self,
        qi: usize,
        sess: usize,
        area: Handle,
        done: Handle,
        priority: u8,
        data_blocks: u16,
    ) -> Result<(), IoError> {
        let base = Q_VA + qi as u64 * Q_STRIDE;
        let data_len = u64::from(data_blocks) * PAGE as u64;
        let submit_obj = ostd::cap::create(
            self.quota,
            ObjectType::MemoryObject,
            ostd::ring::object_bytes(RING_BYTES),
        )
        .map_err(|_| IoError::Full)?;
        let Ok(kick) = ostd::cap::create(self.quota, ObjectType::Notification, 0) else {
            let _ = ostd::cap::delete(submit_obj);
            return Err(IoError::Full);
        };
        let made = (|| {
            let submit = Consumer::create(submit_obj, base, RING_BYTES, RING_KIND, kick).ok()?;
            let ring = Producer::open(area, base + Q_AREA_OFF, RING_BYTES, done, 1).ok()?;
            let map = Mapping::new_at(
                SELF,
                area,
                base + Q_AREA_OFF + AREA_HEAD,
                AREA_HEAD,
                data_len,
                ostd::kabi::vm::WRITE,
            )
            .ok()?;
            Some((submit, ring, map))
        })();
        let Some((submit, done_ring, area_map)) = made else {
            let _ = ostd::cap::delete(submit_obj);
            let _ = ostd::cap::delete(kick);
            return Err(IoError::BadRequest);
        };
        self.next_epoch = self.next_epoch.wrapping_add(1);
        self.queues[qi] = Some(Queue {
            sess,
            epoch: self.next_epoch,
            priority,
            data_len,
            submit,
            submit_obj,
            kick,
            done: done_ring,
            area: area_map,
            area_obj: area,
            done_ntfy: done,
            cur: None,
            waiting: 0,
        });
        Ok(())
    }
}

impl Storage for Servico {
    fn open(&mut self, ctx: &Contexto, name: &str) -> Result<u64, IoError> {
        if ctx.badge & BADGE_TAG != 0 {
            return Err(IoError::BadRequest);
        }
        let part = self
            .parts
            .iter()
            .position(|p| p.is_some_and(|p| p.name() == name.as_bytes()))
            .ok_or(IoError::BadRequest)?;
        // Os 48 bits baixos do badge são o id e a geração do cliente.
        let owner = ctx.badge & 0xFFFF_FFFF_FFFF;
        self.reap_dead(owner);
        let slot = self
            .sess
            .iter()
            .position(Option::is_none)
            .ok_or(IoError::Full)?;
        let badge = BADGE_TAG | (slot as u64) << 8 | part as u64;
        let cap = grant(self.ep, Rights::SEND | Rights::GRANT, badge)?;
        self.sess[slot] = Some(Sess {
            part,
            queues: 0,
            owner,
        });
        Ok(cap)
    }
}

impl BlockStore for Servico {
    fn info(&mut self, ctx: &Contexto) -> Result<Info, IoError> {
        let (_, part) = self.who(ctx.badge)?;
        let p = self.parts[part].as_ref().ok_or(IoError::BadRequest)?;
        Ok(Info {
            blocks: p.blocks,
            read_only: p.read_only || self.dev.read_only,
            flush: self.dev.flush,
            max_depth: MAX_DEPTH,
            max_blocks: MAX_BLOCKS,
        })
    }

    fn open_queue(
        &mut self,
        ctx: &Contexto,
        area: u64,
        done: u64,
        depth: u16,
        priority: u8,
        data_blocks: u16,
    ) -> Result<u32, IoError> {
        let (Ok(area), Ok(done)) = (u32::try_from(area), u32::try_from(done)) else {
            return Err(IoError::BadRequest);
        };
        let (area, done) = (Handle::from_raw(area), Handle::from_raw(done));
        let drop_caps = || {
            let _ = ostd::cap::delete(area);
            let _ = ostd::cap::delete(done);
        };
        let checked = self.who(ctx.badge).and_then(|(sess, _)| {
            let ok_area = ostd::cap::info(area).is_ok_and(|i| {
                i.object_type == ObjectType::MemoryObject
                    && i.rights
                        .contains(Rights::MAP | Rights::READ | Rights::WRITE)
            });
            let ok_done = ostd::cap::info(done).is_ok_and(|i| {
                i.object_type == ObjectType::Notification && i.rights.contains(Rights::SIGNAL)
            });
            if !ok_area
                || !ok_done
                || depth == 0
                || depth > MAX_DEPTH
                || data_blocks == 0
                || data_blocks > MAX_DATA_BLOCKS
            {
                return Err(IoError::BadRequest);
            }
            if self.sess[sess].is_none_or(|s| s.queues >= QUEUES_PER_SESSION) {
                return Err(IoError::Full);
            }
            self.queues
                .iter()
                .position(Option::is_none)
                .map(|qi| (sess, qi))
                .ok_or(IoError::Full)
        });
        let (sess, qi) = match checked {
            Ok(v) => v,
            Err(e) => {
                drop_caps();
                return Err(e);
            }
        };
        if let Err(e) = self.make_queue(qi, sess, area, done, priority, data_blocks) {
            drop_caps();
            return Err(e);
        }
        if let Some(s) = self.sess[sess].as_mut() {
            s.queues += 1;
        }
        Ok(qi as u32)
    }

    fn submit_ring(&mut self, ctx: &Contexto, queue: u32) -> Result<u64, IoError> {
        let qi = self.queue_of(ctx.badge, queue)?;
        let q = self.queues[qi].as_ref().ok_or(IoError::BadRequest)?;
        grant(q.submit_obj, Rights::MAP | Rights::READ | Rights::WRITE, 0)
    }

    fn kick(&mut self, ctx: &Contexto, queue: u32) -> Result<u64, IoError> {
        let qi = self.queue_of(ctx.badge, queue)?;
        let q = self.queues[qi].as_ref().ok_or(IoError::BadRequest)?;
        grant(q.kick, Rights::SIGNAL, 0)
    }

    fn close_queue(&mut self, ctx: &Contexto, queue: u32) -> Result<(), IoError> {
        let qi = self.queue_of(ctx.badge, queue)?;
        self.drop_queue(qi);
        Ok(())
    }

    fn release(&mut self, ctx: &Contexto) -> Result<(), IoError> {
        let (sess, _) = self.who(ctx.badge)?;
        for qi in 0..MAX_QUEUES {
            if self.queues[qi].as_ref().is_some_and(|q| q.sess == sess) {
                self.drop_queue(qi);
            }
        }
        self.sess[sess] = None;
        Ok(())
    }
}

/// Atende `Storage` e `BlockStore` em `ep` até o endpoint ser revogado.
fn serve(ep: Handle, quota: Handle, s: &mut Session, svc: &mut Servico) -> Error {
    let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let (mut corpo, mut saida) = ([0u8; 128], [0u8; 64]);
    let mut resp: Option<Message> = None;
    loop {
        let wait = if svc.busy() { BUSY_NS } else { IDLE_NS };
        let deadline = ostd::time::now_ns().saturating_add(wait);
        let got = match resp.take() {
            Some(r) => ipc::reply_recv(ep, reply, &r, deadline),
            None => ipc::recv(ep, reply, deadline),
        };
        let rec = match got {
            Ok(rec) => rec,
            Err(Error::TimedOut | Error::PeerClosed) => {
                svc.pump();
                svc.maintain(s);
                continue;
            }
            Err(e) => return e,
        };
        let ctx_badge = rec.badge;
        let mut caps = [0u64; 4];
        let ncaps = usize::from(rec.msg.info.caps).min(caps.len());
        for (dst, src) in caps.iter_mut().zip(s.buffer.get().caps.iter()).take(ncaps) {
            *dst = u64::from(*src);
        }
        let mut caps_out = [0u64; 1];
        let built = match ipc::copia(&mut s.buffer, &rec.msg, &mut corpo) {
            Ok(n) => {
                let entrada = storage_servidor::Entrada {
                    rotulo: rec.msg.label,
                    badge: ctx_badge,
                    corpo: &corpo[..n],
                    caps: &caps[..ncaps],
                };
                let despacho = match (rec.msg.label >> 32) as u32 {
                    ID_STORAGE => despacha_storage(svc, 0, &entrada, &mut saida, &mut caps_out),
                    ID_BLOCKSTORE => {
                        despacha_block_store(svc, 0, &entrada, &mut saida, &mut caps_out)
                    }
                    _ => None,
                };
                match despacho {
                    Some(d) => {
                        ipc::monta(&mut s.buffer, d.rotulo, &saida[..d.corpo]).map(|mut m| {
                            if d.caps == 1 {
                                s.buffer.get().caps[0] = caps_out[0] as u32;
                                m.info.caps = 1;
                            }
                            m
                        })
                    }
                    None => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
                }
            }
            Err(_) => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
        };
        match built {
            Ok(m) => resp = Some(m),
            Err(e) => return e,
        }
        svc.pump();
    }
}

/// Lê a GPT e guarda as partições que servem.
#[inline(never)]
fn load_parts(dev: &mut Dev) -> Option<[Option<Part>; MAX_PARTS]> {
    let ss = dev.sector_size;
    // A tabela tem mais de 17 KiB e a pilha é de 64 KiB: uma cópia só.
    let mut table = ogpt::Table::empty();
    if let Err(e) = ogpt::parse_into(&mut Boot(dev), &mut table) {
        ostd::debug::print_fmt(format_args!("storaged: GPT inválida ({e:?})"));
        return None;
    }
    let mut parts = [None; MAX_PARTS];
    let mut n = 0;
    for p in table.parts() {
        if !p.aligned_4k(ss) {
            ostd::debug::print("storaged: partição não alinhada a 4 KiB recusada");
            continue;
        }
        if n == MAX_PARTS {
            break;
        }
        let mut name = [0u8; 36];
        let mut len = 0;
        for c in p.name.iter().take_while(|c| **c != 0) {
            name[len] = u8::try_from(*c)
                .ok()
                .filter(u8::is_ascii_graphic)
                .unwrap_or(b'?');
            len += 1;
        }
        parts[n] = Some(Part {
            first: p.first,
            blocks: p.sectors() * ss as u64 / PAGE as u64,
            name,
            name_len: len,
            read_only: name[..len].starts_with(b"sys-"),
        });
        n += 1;
    }
    Some(parts)
}

fn run(s: &mut Session, quota: Handle) -> Result<(), &'static str> {
    let ep = s
        .boot
        .provided(ID_STORAGE)
        .map(Handle::from_raw)
        .ok_or("descritor sem o endpoint do Storage")?;
    let dev_ep = connect(s, b"optimus.block.BlockDevice").ok_or("sem disco")?;
    let mut dev = Dev::attach(dev_ep, &mut s.buffer, quota, 0).ok_or("ligar ao BlockDevice")?;
    let parts = load_parts(&mut dev).ok_or("sem GPT")?;
    let mut line = [0u8; 128];
    let mut at = 0;
    let mut count = 0;
    for p in parts.iter().flatten() {
        let name = p.name();
        if at + name.len() + 1 > line.len() {
            break;
        }
        line[at..at + name.len()].copy_from_slice(name);
        line[at + name.len()] = b' ';
        at += name.len() + 1;
        count += 1;
    }
    ostd::debug::print_fmt(format_args!(
        "storaged: {count} partições: {}",
        core::str::from_utf8(&line[..at]).unwrap_or("?").trim_end()
    ));
    let mut svc = Servico {
        dev,
        parts,
        sess: [None; MAX_SESSIONS],
        queues: [const { None }; MAX_QUEUES],
        quota,
        ep,
        next_epoch: 0,
        bank: 0,
        down: false,
        next_check: ostd::time::now_ns().saturating_add(PROBE_NS),
    };
    ostd::debug::print("storaged: contrato BlockStore pronto");
    let e = serve(ep, quota, s, &mut svc);
    ostd::debug::print_fmt(format_args!("storaged: encerrado ({e:?})"));
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
    if let Err(e) = run(&mut s, quota) {
        ostd::debug::print_fmt(format_args!("storaged: falhou: {e}"));
    }
    ostd::thread::exit()
}
