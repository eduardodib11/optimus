//! `svcmgr`: o corretor de capabilities (ADR 0034). Criado pelo `root`
//! (T-351), que lhe entrega, nesta ordem em `rdi`, `rsi` e `rdx`:
//!
//! - `rdi`: o endpoint do `root` (badge 1);
//! - `rsi`: o bootfs só de leitura e a cota de partida;
//! - `rdx`: a `DebugLog` do `kernel:debug` (0 se o `root` não tiver).
//!
//! O `svcmgr` não recebe a capability da própria thread (ADR 0034, item 2):
//! ela fecharia o ciclo thread ↔ `CapSpace` da ADR 0029 e prenderia o
//! processo na cota do `root` depois da saída. Para configurar a si mesmo,
//! usa `thread = 0` (ADR 0039, item 3).
//!
//! Ele se anuncia, lê os manifestos do bootfs ([`svcmgr::plan`]) e parte os
//! serviços nível a nível (ADR 0034, itens 6 e 7): `process::load`, entrega
//! das capabilities pelo [`svcmgr::broker::Broker`], `start` com o canal
//! de controle em `rdi` e a cota em `rsi`, e atende `bootstrap` e `ready`
//! no canal de controle. Um nível só começa quando o anterior está todo em
//! `Running`; quem não chega lá em [`READY_NS`] fica fora (o reinício pelo
//! [`svcmgr::supervisor`] vem depois).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use ostd::ipc::{self, Message};

use ostd::ipc::Buffer;
use ostd::kabi::{Error, Handle, ObjectType, split_handle_pair};
use ostd::process::{self, Spec};
use ostd::rt::Start;
use ostd::vm::{Mapping, SELF};
use svcmgr::broker::Boot as Desc;
use svcmgr::plan::Plan;

ostd::entry!(main);

/// Quanto o `svcmgr` espera a resposta do `root`, em ns.
const CALL_WAIT_NS: u64 = 15_000_000_000;
/// Rótulo do "olá" ao `root` (o `root` aceita só esse rótulo do badge 1).
const LABEL_OLA: u64 = 1;

/// Onde o `svcmgr` mapeia o bootfs.
const BOOTFS_VA: u64 = 0x10_0000_0000;

/// Faixa livre para os mapeamentos temporários do `process::load`.
const SCRATCH_VA: u64 = 0x8000_0000;
/// Prazo para um serviço chamar `ready` depois do `start` (ADR 0034, item 7).
const READY_NS: u64 = 5_000_000_000;
/// Onde fica o buffer de IPC do `svcmgr`.
const BUFFER_VA: u64 = ostd::ipc::DEFAULT_BUFFER_VA;

/// Mapeia o bootfs inteiro (o tamanho está no byte 32 do cabeçalho).
fn map_bootfs(bootfs: Handle) -> Result<Mapping, Error> {
    let len = {
        let head = Mapping::new(SELF, bootfs, BOOTFS_VA, 4096, 0)?;
        let field = head.bytes().get(32..40).ok_or(Error::InvalidArgument)?;
        u64::from_le_bytes(field.try_into().map_err(|_| Error::InvalidArgument)?)
    };
    Mapping::new(SELF, bootfs, BOOTFS_VA, len, 0)
}

/// Lê os manifestos e monta o plano.
fn plan(fs: &obfs::Image<'_>) -> Result<Plan, Error> {
    let entries: Vec<(&str, &[u8])> = fs.entries().map(|e| (e.name, e.data)).collect();
    svcmgr::plan::build(&entries).map_err(|e| {
        ostd::debug::print_fmt(format_args!("svcmgr: plano recusado: {e:?}"));
        Error::InvalidArgument
    })
}

/// Um serviço partido e o descritor dele.
struct Started {
    id: u32,
    desc: Desc,
    child: process::Child,
}

/// Parte o serviço `id`: carrega, entrega as capabilities e inicia.
fn spawn(
    plan: &mut Plan,
    fs: &obfs::Image<'_>,
    id: u32,
    boot: &Boot,
    control: Handle,
) -> Result<Started, Error> {
    let m = plan.broker.manifest(id).ok_or(Error::InvalidArgument)?;
    let elf = fs.find(&m.binary).ok_or(Error::InvalidArgument)?;
    let bytes = m
        .needs
        .iter()
        .find(|n| n.kind == oman::NeedKind::Mem)
        .map_or(0, |n| n.value);
    let child = process::load(&Spec {
        elf: elf.data,
        quota: boot.quota,
        quota_bytes: bytes,
        own_aspace: SELF,
        scratch_va: SCRATCH_VA,
        priority: m.priority,
    })?;
    let pool: &[(&str, Handle)] = if boot.log.raw() == 0 {
        &[]
    } else {
        &[("debug", boot.log)]
    };
    let desc = plan
        .broker
        .deliver(
            id,
            child.cspace,
            control,
            child.quota,
            pool,
            &mut svcmgr::kernel::Kernel,
        )
        .map_err(|e| {
            ostd::debug::print_fmt(format_args!("svcmgr: entrega recusada: {e:?}"));
            Error::InvalidArgument
        })?;
    let find = |kind: u8, index: u16| {
        desc.caps
            .iter()
            .find(|c| c.kind == kind && c.index == index)
            .map_or(0, |c| u64::from(c.handle))
    };
    let args = [
        find(osvc::KIND_CONTROL, 0),
        find(osvc::KIND_MEM, osvc::QUOTA_INDEX),
        0,
    ];
    child.start(args)?;
    Ok(Started { id, desc, child })
}

/// Atende `bootstrap` e `ready` no canal de controle até os serviços de
/// `level` ficarem em `Running` ou o prazo vencer. Devolve quantos ficaram.
fn serve_level(
    plan: &mut Plan,
    started: &[Started],
    level: &[u32],
    control: Handle,
    reply: Handle,
    buffer: &mut Buffer,
) -> usize {
    let deadline = ostd::time::now_ns().saturating_add(READY_NS);
    let mut ready: Vec<u32> = Vec::new();
    let mut body = [0u8; osvc::MAX_BOOT_BYTES];
    let mut sink = [0u8; 64];
    while ready.len() < level.len() {
        let Ok(r) = ipc::recv_corpo(control, reply, buffer, &mut sink, deadline) else {
            break;
        };
        let id = u32::try_from(r.badge & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        let live = plan.broker.badge_of(id) == Some(r.badge);
        let svc = started.iter().find(|s| s.id == id).filter(|_| live);
        let answer = match (svc, osvc::method_of(r.rotulo)) {
            (Some(s), Some(osvc::Method::Bootstrap)) => {
                let caps: Vec<osvc::CapDesc> = s
                    .desc
                    .caps
                    .iter()
                    .map(|c| osvc::CapDesc {
                        kind: c.kind,
                        index: c.index,
                        handle: c.handle,
                        name_hash: c.name_hash,
                    })
                    .collect();
                match osvc::encode_boot(&caps, s.desc.generation, &mut body) {
                    Ok(n) => (osvc::REPLY_OK, n),
                    Err(_) => (osvc::REPLY_ERR, 0),
                }
            }
            (Some(s), Some(osvc::Method::Ready)) => {
                plan.broker.set_running(s.id, true);
                if !ready.contains(&s.id) {
                    ready.push(s.id);
                }
                let name = plan.broker.manifest(s.id).map_or("?", |m| m.name.as_str());
                ostd::debug::print_fmt(format_args!("svcmgr: {name} em Running"));
                (osvc::REPLY_OK, 0)
            }
            (Some(_), _) => (osvc::REPLY_UNKNOWN_METHOD, 0),
            (None, _) => (osvc::REPLY_ERR, 0),
        };
        let _ = ipc::responde_corpo(reply, buffer, answer.0, &body[..answer.1], 0);
    }
    ready.len()
}

/// Parte todos os serviços do plano, nível a nível.
fn start_all(boot: &Boot) -> Result<(), Error> {
    let map = map_bootfs(boot.bootfs)?;
    let fs = obfs::Image::parse(map.bytes()).map_err(|_| Error::InvalidArgument)?;
    let mut plan = plan(&fs)?;
    let control = ostd::cap::create(boot.quota, ObjectType::Endpoint, 0)?;
    let reply = ostd::cap::create(boot.quota, ObjectType::Reply, 0)?;
    let mut buffer = Buffer::new(boot.quota, SELF, Handle::from_raw(0), BUFFER_VA)?;
    let levels = plan.levels.clone();
    let mut started = Vec::new();
    let mut running = 0;
    for level in &levels {
        let mut here = Vec::new();
        for &id in level {
            match spawn(&mut plan, &fs, id, boot, control) {
                Ok(s) => {
                    here.push(id);
                    started.push(s);
                }
                Err(e) => {
                    let name = plan.broker.manifest(id).map_or("?", |m| m.name.as_str());
                    ostd::debug::print_fmt(format_args!("svcmgr: {name} não partiu: {e:?}"));
                }
            }
        }
        let n = serve_level(&mut plan, &started, &here, control, reply, &mut buffer);
        running += n;
        if n < level.len() {
            break;
        }
    }
    ostd::debug::print_fmt(format_args!("svcmgr: {running} serviços em Running"));
    // Até o laço de supervisão (ADR 0034, item 9), o `svcmgr` sai depois da
    // partida: antes, encerra os serviços para a cota voltar ao `root`. A
    // revogação das raízes dá `PeerClosed` a quem atende, e o serviço sai.
    for s in &started {
        let _ = svcmgr::supervisor::revoke_instance(
            &mut plan.broker,
            s.id,
            &mut svcmgr::kernel::Kernel,
        );
        let c = s.child;
        for h in [c.thread, c.aspace, c.cspace, c.quota] {
            let _ = ostd::cap::delete(h);
        }
    }
    ostd::debug::print("svcmgr: serviços encerrados");
    Ok(())
}

/// Capabilities recebidas do `root`, já separadas.
#[derive(Clone, Copy)]
struct Boot {
    root_ep: Handle,
    bootfs: Handle,
    quota: Handle,
    log: Handle,
}

fn main(start: Start) -> ! {
    let [a, b, c] = start.args;
    let (root_ep, _) = split_handle_pair(a);
    let (bootfs, quota) = split_handle_pair(b);
    let boot = Boot {
        root_ep,
        bootfs,
        quota,
        log: Handle::from_raw(u32::try_from(c).unwrap_or(0)),
    };
    if boot.log.raw() != 0 {
        ostd::debug::set_log(boot.log);
    }
    ostd::rt::init(ostd::rt::Env { quota: boot.quota });
    ostd::debug::print("svcmgr: iniciado pelo root");
    ostd::debug::print_fmt(format_args!(
        "svcmgr: caps recebidas: root_ep={} bootfs={} quota={}",
        boot.root_ep.raw(),
        boot.bootfs.raw(),
        boot.quota.raw()
    ));
    // Prazo: se o `root` não responder, o `svcmgr` sai em vez de ficar preso
    // e segurar a cota de partida (ADR 0034, item 2).
    let deadline = ostd::time::now_ns() + CALL_WAIT_NS;
    match ipc::call(boot.root_ep, &Message::new(LABEL_OLA, &[]), deadline) {
        Ok(r) if r.msg.label == 0 => ostd::debug::print("svcmgr: o root aceitou o anúncio"),
        Ok(_) => ostd::debug::print("svcmgr: o root respondeu com erro"),
        Err(Error::AccessDenied) => ostd::debug::print("svcmgr: o root recusou o anúncio"),
        Err(_) => ostd::debug::print("svcmgr: falha ao falar com o root"),
    }
    if let Err(e) = start_all(&boot) {
        ostd::debug::print_fmt(format_args!("svcmgr: partida falhou: {e:?}"));
    }
    ostd::thread::exit()
}
