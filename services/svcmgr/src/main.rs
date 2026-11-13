//! `svcmgr`: o corretor de capabilities (ADR 0034). Criado pelo `root`
//! (T-351), que lhe entrega, nesta ordem em `rdi`, `rsi` e `rdx`:
//!
//! - `rdi`: o endpoint do `root` (badge 1);
//! - `rsi`: o bootfs só de leitura e a cota de partida;
//! - `rdx`: a `DebugLog` do `kernel:debug` e o anel do `kernel:log` (0 se o
//!   `root` não tiver).
//!
//! A resposta do `root` ao anúncio traz, no buffer de IPC, a janela ECAM
//! (`kernel:ecam`) e a cota de dispositivo (`kernel:device`) (T-402).
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
use osvc::{Method, SvcError};
use svcmgr::broker::Boot as Desc;
use svcmgr::plan::Plan;
use svcmgr::supervisor::{Action, Exit, Policy, Supervisor};

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
    desc: Desc,
    child: process::Child,
    /// Recursos de dispositivo que o `devmgr` deu (só num driver): as
    /// cópias do `svcmgr` ficam até o fim da instância.
    devices: Vec<Handle>,
}

/// Parte o serviço `id`: carrega, entrega as capabilities e inicia.
fn spawn(
    plan: &mut Plan,
    fs: &obfs::Image<'_>,
    id: u32,
    boot: &Boot,
    control: Handle,
    devices: Option<&[(Handle, u32)]>,
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
    let mut pool: Vec<(&str, Handle)> = Vec::new();
    if boot.log.raw() != 0 {
        pool.push(("debug", boot.log));
    }
    if boot.klog.raw() != 0 {
        pool.push(("log", boot.klog));
    }
    if boot.ecam.raw() != 0 {
        pool.push(("ecam", boot.ecam));
    }
    if boot.device.raw() != 0 {
        pool.push(("device", boot.device));
    }
    if boot.acpi.raw() != 0 {
        pool.push(("acpi", boot.acpi));
    }
    let kernel = &mut svcmgr::kernel::Kernel;
    let delivered = match devices {
        Some(d) => {
            let (cs, q) = (child.cspace, child.quota);
            plan.broker
                .deliver_driver(id, cs, control, q, &pool, d, kernel)
        }
        None => plan
            .broker
            .deliver(id, child.cspace, control, child.quota, &pool, kernel),
    };
    let desc = delivered.map_err(|e| {
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
    Ok(Started {
        desc,
        child,
        devices: Vec::new(),
    })
}

/// Quanto o laço espera por mensagem antes de olhar as mortes, em ns.
const TICK_NS: u64 = 20_000_000;
/// Janela de supervisão do M3: quanto o `svcmgr` supervisiona depois da
/// partida antes do desligamento ordenado. Até existir quem peça o
/// desligamento (M4), é ela que devolve a cota ao `root` nos testes.
const SUPERVISE_NS: u64 = 1_000_000_000;

/// O `svcmgr` em execução: plano, canal de controle e instâncias vivas.
struct Svcmgr<'a> {
    plan: Plan,
    fs: obfs::Image<'a>,
    boot: Boot,
    control: Handle,
    reply: Handle,
    deaths: Handle,
    buffer: Buffer,
    sup: Supervisor,
    live: Vec<Option<Started>>,
    /// Mortes que o próprio `svcmgr` causou (teste de caos).
    induced: Vec<u32>,
    /// Recursos que o `devmgr` deu a cada driver, até o `driver_start`.
    pending: Vec<(u32, Vec<(Handle, u32)>)>,
}

/// Teto de recursos de dispositivo de um driver.
const MAX_DEVICE_CAPS: usize = 16;

/// O erro do corretor no fio.
const fn wire(e: svcmgr::broker::SvcError) -> SvcError {
    use svcmgr::broker::SvcError as B;
    match e {
        B::NotInManifest => SvcError::NotInManifest,
        B::NotRunning => SvcError::NotRunning,
        B::VersionTooOld => SvcError::VersionTooOld,
        B::Busy => SvcError::Busy,
    }
}

fn name(plan: &Plan, id: u32) -> &str {
    plan.broker.manifest(id).map_or("?", |m| m.name.as_str())
}

impl Svcmgr<'_> {
    /// Parte `id` e liga a morte do processo ao bit dele em `deaths`.
    fn launch(&mut self, id: u32) -> bool {
        self.launch_with(id, None)
    }

    /// Como [`Svcmgr::launch`]; um driver leva os recursos `devices`, que
    /// ficam com a instância (ou são apagados se ela não partir).
    fn launch_with(&mut self, id: u32, devices: Option<&[(Handle, u32)]>) -> bool {
        let r = spawn(
            &mut self.plan,
            &self.fs,
            id,
            &self.boot,
            self.control,
            devices,
        );
        let handles: Vec<Handle> = devices.unwrap_or(&[]).iter().map(|d| d.0).collect();
        match r {
            Ok(mut s) => {
                s.devices = handles;
                let bit = 1u64 << (id % 64);
                if let Err(e) = ostd::cap::bind_notify(s.child.cspace, self.deaths, bit) {
                    ostd::debug::print_fmt(format_args!("svcmgr: sem aviso de morte: {e:?}"));
                }
                self.sup.started(id, ostd::time::now_ns());
                if let Some(slot) = usize::try_from(id).ok().and_then(|i| self.live.get_mut(i)) {
                    *slot = Some(s);
                }
                true
            }
            Err(e) => {
                let n = name(&self.plan, id);
                ostd::debug::print_fmt(format_args!("svcmgr: {n} não partiu: {e:?}"));
                for h in handles {
                    let _ = ostd::cap::delete(h);
                }
                false
            }
        }
    }

    fn started(&self, id: u32) -> Option<&Started> {
        self.live.get(usize::try_from(id).ok()?)?.as_ref()
    }

    /// Fim da instância de `id` (item 9): revoga os endpoints e apaga o
    /// processo.
    fn retire(&mut self, id: u32) {
        let Some(s) = usize::try_from(id)
            .ok()
            .and_then(|i| self.live.get_mut(i))
            .and_then(Option::take)
        else {
            return;
        };
        let _ = ostd::cap::bind_notify(s.child.cspace, self.deaths, 0);
        let _ = svcmgr::supervisor::revoke_instance(
            &mut self.plan.broker,
            id,
            &mut svcmgr::kernel::Kernel,
        );
        for &h in &s.devices {
            let _ = ostd::cap::delete(h);
        }
        let c = s.child;
        for h in [c.thread, c.aspace, c.cspace, c.quota] {
            if h.raw() != 0 {
                let _ = ostd::cap::delete(h);
            }
        }
    }

    /// Olha as mortes sinalizadas e decide cada uma; parte os reinícios
    /// vencidos.
    fn reap(&mut self) {
        let bits = ostd::cap::ntfy_poll(self.deaths).unwrap_or(0);
        let ids: Vec<u32> = (0..self.live.len())
            .filter_map(|i| u32::try_from(i).ok())
            .filter(|&id| bits & (1u64 << (id % 64)) != 0)
            .collect();
        for id in ids {
            let Some(s) = self.started(id) else { continue };
            let Ok(Some(d)) = ostd::cap::death(s.child.cspace) else {
                continue;
            };
            let exit = if d.cause == ostd::kabi::exit::CAUSE_EXITED && d.code == 0 {
                Exit::Clean
            } else {
                Exit::Failed
            };
            self.retire(id);
            let now = ostd::time::now_ns();
            let n = name(&self.plan, id);
            if let Some(i) = self.induced.iter().position(|&x| x == id) {
                self.induced.swap_remove(i);
                self.sup.induced(id, now);
                continue;
            }
            match self.sup.exited(id, exit, now) {
                Action::Restart { backoff_ns, .. } => ostd::debug::print_fmt(format_args!(
                    "svcmgr: {n} morreu ({exit:?}); volta em {} ms",
                    backoff_ns / 1_000_000
                )),
                Action::Stop => {
                    ostd::debug::print_fmt(format_args!("svcmgr: {n} terminou ({exit:?})"));
                }
                Action::Alert { failures } => ostd::debug::print_fmt(format_args!(
                    "svcmgr: error: {n} falhou {failures} vezes em 1 min; fica Failed"
                )),
            }
        }
        for id in self.sup.due(ostd::time::now_ns()) {
            if self.launch(id) {
                let n = name(&self.plan, id);
                ostd::debug::print_fmt(format_args!("svcmgr: {n} reiniciado"));
            }
        }
    }

    /// Resposta de `bootstrap`: o descritor de `id`.
    fn boot_answer(&self, id: u32, body: &mut [u8]) -> (u64, usize) {
        let Some(s) = self.started(id) else {
            return (osvc::REPLY_ERR, 0);
        };
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
        match osvc::encode_boot(&caps, s.desc.generation, body) {
            Ok(n) => (osvc::REPLY_OK, n),
            Err(_) => (osvc::REPLY_ERR, 0),
        }
    }

    /// `driver_give(id, names)`: guarda os recursos que chegaram com a
    /// mensagem para o driver `id`. Só o `devmgr`, e só para um driver
    /// parado; o que for recusado é apagado.
    fn driver_give(&mut self, caller: u32, req: &[u8], got: &[Handle]) -> Result<(), SvcError> {
        let mut names = [0u32; osvc::MAX_MSG_CAPS];
        let (id, n) =
            osvc::decode_driver_give(req, &mut names).map_err(|_| SvcError::NotInManifest)?;
        if n != got.len() || !self.may_drive(caller, id) {
            return Err(SvcError::NotInManifest);
        }
        let i = if let Some(i) = self.pending.iter().position(|p| p.0 == id) {
            i
        } else {
            self.pending.push((id, Vec::new()));
            self.pending.len() - 1
        };
        let list = &mut self.pending[i].1;
        if list.len() + n > MAX_DEVICE_CAPS {
            return Err(SvcError::Busy);
        }
        list.extend(got.iter().copied().zip(names));
        Ok(())
    }

    /// `driver_start(id)`: parte o driver com os recursos guardados.
    fn driver_start(&mut self, caller: u32, id: u32) -> Result<(), SvcError> {
        if !self.may_drive(caller, id) {
            return Err(SvcError::NotInManifest);
        }
        let devices = match self.pending.iter().position(|p| p.0 == id) {
            Some(i) => self.pending.swap_remove(i).1,
            None => Vec::new(),
        };
        if self.launch_with(id, Some(&devices)) {
            Ok(())
        } else {
            Err(SvcError::Busy)
        }
    }

    /// Os métodos do `devmgr` (1.1 e 1.2); devolve a resposta e se os
    /// recursos que chegaram ficaram guardados.
    fn serve_driver(
        &mut self,
        id: u32,
        m: Method,
        req: &[u8],
        got: &[Handle],
        body: &mut [u8],
    ) -> ((u64, usize), bool) {
        let err = |e, body: &mut [u8]| (osvc::REPLY_ERR, osvc::encode_error(e, body).unwrap_or(0));
        match m {
            Method::Driver => match osvc::decode_driver(req) {
                Ok(index) => (self.driver_answer(id, index, body), false),
                Err(_) => ((osvc::REPLY_BAD_MESSAGE, 0), false),
            },
            Method::DriverGive => match self.driver_give(id, req, got) {
                Ok(()) => ((osvc::REPLY_OK, 0), true),
                Err(e) => (err(e, body), false),
            },
            Method::DriverStart => match osvc::decode_driver_start(req) {
                Ok(driver) => match self.driver_start(id, driver) {
                    Ok(()) => ((osvc::REPLY_OK, 0), false),
                    Err(e) => (err(e, body), false),
                },
                Err(_) => ((osvc::REPLY_BAD_MESSAGE, 0), false),
            },
            _ => ((osvc::REPLY_UNKNOWN_METHOD, 0), false),
        }
    }

    /// `caller` é o `devmgr` e `id` é um driver parado.
    fn may_drive(&self, caller: u32, id: u32) -> bool {
        self.plan.broker.is_device_manager(caller)
            && self.plan.drivers.contains(&id)
            && self.started(id).is_none()
    }

    /// Resposta de `driver(index)`: só o `devmgr` lê a lista de drivers.
    fn driver_answer(&self, id: u32, index: u16, body: &mut [u8]) -> (u64, usize) {
        let err = |e, body: &mut [u8]| (osvc::REPLY_ERR, osvc::encode_error(e, body).unwrap_or(0));
        let drivers = &self.plan.drivers;
        let found = drivers
            .get(usize::from(index))
            .and_then(|&d| Some((d, self.plan.broker.manifest(d)?)));
        let (Some((driver, m)), true) = (found, self.plan.broker.is_device_manager(id)) else {
            return err(SvcError::NotInManifest, body);
        };
        let rules: Vec<&str> = m
            .needs
            .iter()
            .filter(|n| n.kind == oman::NeedKind::Dev)
            .map(|n| n.name.as_str())
            .collect();
        let total = u16::try_from(drivers.len()).unwrap_or(u16::MAX);
        let encoded = osvc::DriverInfo::new(driver, total, &m.name, &rules)
            .and_then(|info| osvc::encode_driver_info(&info, body).ok());
        match encoded {
            Some(n) => (osvc::REPLY_OK, n),
            None => err(SvcError::Busy, body),
        }
    }

    /// Responde pelo `Reply` (com a capability de um `connect`, se houver)
    /// e apaga as capabilities recebidas que não ficaram guardadas.
    fn respond(
        &mut self,
        answer: (u64, usize),
        body: &[u8],
        cap: Option<Handle>,
        drop: Vec<Handle>,
    ) {
        for h in drop {
            let _ = ostd::cap::delete(h);
        }
        match cap {
            Some(h) => {
                let mut msg = Message::new(answer.0, &[]);
                msg.info.caps = 1;
                self.buffer.get().caps[0] = h.raw();
                let _ = ipc::send(self.reply, &msg, 0);
                let _ = ostd::cap::delete(h);
            }
            None => {
                let _ = ipc::responde_corpo(
                    self.reply,
                    &mut self.buffer,
                    answer.0,
                    &body[..answer.1],
                    0,
                );
            }
        }
    }

    /// Atende uma mensagem do canal de controle (ou nada, até `until`).
    /// Devolve o id que chamou `ready`, se foi isso.
    fn serve_one(&mut self, until: u64) -> Option<u32> {
        let mut body = [0u8; osvc::MAX_REPLY_BYTES];
        let mut req = [0u8; osvc::MAX_SHORT_BYTES];
        let tick = ostd::time::now_ns().saturating_add(TICK_NS);
        let deadline = match self.sup.next_due() {
            Some(at) => until.min(tick).min(at),
            None => until.min(tick),
        };
        let r = ipc::recv_corpo(
            self.control,
            self.reply,
            &mut self.buffer,
            &mut req,
            deadline,
        );
        let Ok(r) = r else {
            self.reap();
            return None;
        };
        let id = u32::try_from(r.badge & 0xFFFF_FFFF).unwrap_or(u32::MAX);
        let live = self.plan.broker.badge_of(id) == Some(r.badge) && self.started(id).is_some();
        // Capabilities só valem num `driver_give`; nas outras mensagens são
        // apagadas aqui.
        let got: Vec<Handle> = {
            let caps = &self.buffer.get().caps;
            caps.iter()
                .take(r.caps.min(caps.len()))
                .map(|&h| Handle::from_raw(h))
                .collect()
        };
        let mut kept = false;
        let mut ready = None;
        let mut cap = None;
        let err = |e, body: &mut [u8]| match osvc::encode_error(e, body) {
            Ok(n) => (osvc::REPLY_ERR, n),
            Err(_) => (osvc::REPLY_ERR, 0),
        };
        let answer = match (live, osvc::method_of(r.rotulo)) {
            (false, _) => err(SvcError::NotRunning, &mut body),
            (true, Some(Method::Bootstrap)) => self.boot_answer(id, &mut body),
            (true, Some(Method::Ready)) => {
                self.plan.broker.set_running(id, true);
                ready = Some(id);
                let n = name(&self.plan, id);
                ostd::debug::print_fmt(format_args!("svcmgr: {n} em Running"));
                (osvc::REPLY_OK, 0)
            }
            (true, Some(Method::Connect)) => match osvc::decode_connect(&req[..r.corpo]) {
                Ok((interface, minor)) => {
                    let got = self.plan.broker.connect(
                        r.badge,
                        interface,
                        minor,
                        &mut svcmgr::kernel::Kernel,
                    );
                    match got {
                        Ok(h) => {
                            cap = Some(h);
                            (osvc::REPLY_OK, 0)
                        }
                        Err(e) => err(wire(e), &mut body),
                    }
                }
                Err(_) => (osvc::REPLY_BAD_MESSAGE, 0),
            },
            (true, Some(Method::NameOf)) => match osvc::decode_name_of(&req[..r.corpo]) {
                Ok(who) => match self.plan.broker.manifest(who) {
                    Some(m) => match osvc::encode_name(&m.name, &mut body) {
                        Ok(n) => (osvc::REPLY_OK, n),
                        Err(_) => (osvc::REPLY_ERR, 0),
                    },
                    None => err(SvcError::NotInManifest, &mut body),
                },
                Err(_) => (osvc::REPLY_BAD_MESSAGE, 0),
            },
            (true, Some(m @ (Method::Driver | Method::DriverGive | Method::DriverStart))) => {
                let (answer, keep) = self.serve_driver(id, m, &req[..r.corpo], &got, &mut body);
                kept = keep;
                answer
            }
            (true, None) => (osvc::REPLY_UNKNOWN_METHOD, 0),
        };
        self.respond(answer, &body, cap, if kept { Vec::new() } else { got });
        self.reap();
        ready
    }

    /// Parte um nível e espera todos em `Running` até [`READY_NS`].
    fn start_level(&mut self, level: &[u32]) -> usize {
        let here: Vec<u32> = level
            .iter()
            .copied()
            .filter(|&id| self.launch(id))
            .collect();
        let deadline = ostd::time::now_ns().saturating_add(READY_NS);
        let mut ready: Vec<u32> = Vec::new();
        while ready.len() < here.len() && ostd::time::now_ns() < deadline {
            if let Some(id) = self.serve_one(deadline)
                && here.contains(&id)
                && !ready.contains(&id)
            {
                ready.push(id);
            }
        }
        ready.len()
    }

    /// Supervisiona até `until`: atende o canal de controle e reinicia.
    fn supervise(&mut self, until: u64) {
        while ostd::time::now_ns() < until {
            let _ = self.serve_one(until);
        }
    }

    /// Teste de caos (T-366; §18, "volta em ≤ 1 s"): `rounds` vezes, mata
    /// um serviço em `Running` escolhido ao acaso (`cap_delete` com
    /// `DESTROY` da thread dele) e espera que volte a `Running`. Registra o
    /// tempo de cada volta; quem não volta em [`READY_NS`] conta como falha.
    fn chaos(&mut self, rounds: u64) {
        let mut seed = ostd::time::now_ns() | 1;
        let mut worst = 0;
        let mut failed = 0u64;
        for k in 0..rounds {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let alive: Vec<u32> = (0..self.live.len())
                .filter_map(|i| u32::try_from(i).ok())
                .filter(|&id| self.started(id).is_some() && self.plan.broker.badge_of(id).is_some())
                .collect();
            let Some(&id) =
                alive.get(usize::try_from(seed % alive.len().max(1) as u64).unwrap_or(0))
            else {
                ostd::debug::print("svcmgr: caos: nenhum serviço vivo");
                return;
            };
            let Some(thread) = self.started(id).map(|s| s.child.thread) else {
                continue;
            };
            let t0 = ostd::time::now_ns();
            self.induced.push(id);
            if ostd::cap::destroy(thread).is_err() {
                self.induced.retain(|&x| x != id);
                continue;
            }
            // `destroy` já apagou a capability: o `retire` não pode apagar o
            // mesmo número, que o kernel pode ter dado a outra.
            if let Some(Some(s)) = usize::try_from(id).ok().and_then(|i| self.live.get_mut(i)) {
                s.child.thread = Handle::from_raw(0);
            }
            let deadline = t0.saturating_add(READY_NS);
            let back = loop {
                if ostd::time::now_ns() >= deadline {
                    break None;
                }
                if self.serve_one(deadline) == Some(id) {
                    break Some(ostd::time::now_ns().saturating_sub(t0));
                }
            };
            let n = name(&self.plan, id);
            if let Some(ns) = back {
                worst = worst.max(ns);
                ostd::debug::print_fmt(format_args!(
                    "svcmgr: caos {k}: {n} voltou em {} ms",
                    ns / 1_000_000
                ));
            } else {
                failed += 1;
                ostd::debug::print_fmt(format_args!("svcmgr: caos {k}: {n} não voltou"));
            }
        }
        ostd::debug::print_fmt(format_args!(
            "svcmgr: caos: {rounds} rodadas, {failed} sem volta, pior volta {} ms",
            worst / 1_000_000
        ));
    }

    /// Desligamento ordenado: encerra os serviços em ordem inversa de
    /// partida, para a cota voltar ao `root`.
    fn shutdown(&mut self) {
        let levels = self.plan.levels.clone();
        for level in levels.iter().rev() {
            for &id in level.iter().rev() {
                self.retire(id);
            }
        }
        ostd::debug::print("svcmgr: serviços encerrados");
    }
}

/// Parte todos os serviços do plano, nível a nível, supervisiona e desliga.
fn start_all(boot: &Boot, buffer: Buffer) -> Result<(), Error> {
    let map = map_bootfs(boot.bootfs)?;
    let fs = obfs::Image::parse(map.bytes()).map_err(|_| Error::InvalidArgument)?;
    let plan = plan(&fs)?;
    let count = plan
        .levels
        .iter()
        .flatten()
        .max()
        .map_or(0, |&m| m as usize + 1);
    let policies: Vec<Policy> = (0..count)
        .map(|i| {
            let id = u32::try_from(i).unwrap_or(u32::MAX);
            plan.broker
                .manifest(id)
                .map_or(Policy::Never, |m| Policy::from_manifest(m.restart))
        })
        .collect();
    let control = ostd::cap::create(boot.quota, ObjectType::Endpoint, 0)?;
    let reply = ostd::cap::create(boot.quota, ObjectType::Reply, 0)?;
    let deaths = ostd::cap::create(boot.quota, ObjectType::Notification, 0)?;
    let mut live = Vec::new();
    live.resize_with(count, || None);
    let mut s = Svcmgr {
        plan,
        fs,
        boot: *boot,
        control,
        reply,
        deaths,
        buffer,
        sup: Supervisor::new(&policies),
        live,
        induced: Vec::new(),
        pending: Vec::new(),
    };
    let levels = s.plan.levels.clone();
    let t0 = ostd::time::now_ns();
    let mut running = 0;
    for level in &levels {
        let k = s.start_level(level);
        running += k;
        if k < level.len() {
            break;
        }
    }
    ostd::debug::print_fmt(format_args!("svcmgr: {running} serviços em Running"));
    ostd::debug::print_fmt(format_args!(
        "svcmgr: partida em {} us",
        ostd::time::now_ns().saturating_sub(t0) / 1_000
    ));
    if let Some(rounds) =
        s.fs.find("svcmgr.caos")
            .and_then(|e| core::str::from_utf8(e.data).ok())
            .and_then(|t| t.trim().parse::<u64>().ok())
    {
        s.chaos(rounds);
    }
    s.supervise(ostd::time::now_ns().saturating_add(SUPERVISE_NS));
    s.shutdown();
    for h in [s.deaths, s.reply, s.control] {
        let _ = ostd::cap::delete(h);
    }
    Ok(())
}

/// Capabilities recebidas do `root`, já separadas.
#[derive(Clone, Copy)]
struct Boot {
    root_ep: Handle,
    bootfs: Handle,
    quota: Handle,
    log: Handle,
    klog: Handle,
    /// `kernel:ecam` e `kernel:device` (T-402), que o `root` manda na
    /// resposta ao anúncio; 0 se não vierem.
    ecam: Handle,
    device: Handle,
    /// `kernel:acpi`: a cópia da DSDT (T-405); 0 se não vier.
    acpi: Handle,
}

fn main(start: Start) -> ! {
    let [a, b, c] = start.args;
    let (root_ep, _) = split_handle_pair(a);
    let (bootfs, quota) = split_handle_pair(b);
    let (log, klog) = split_handle_pair(c);
    let boot = Boot {
        root_ep,
        bootfs,
        quota,
        log,
        klog,
        ecam: Handle::from_raw(0),
        device: Handle::from_raw(0),
        acpi: Handle::from_raw(0),
    };
    let mut boot = boot;
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
    // O buffer vem antes do anúncio: a resposta traz as capabilities de
    // dispositivo (T-402).
    let mut buffer = match Buffer::new(boot.quota, SELF, Handle::from_raw(0), BUFFER_VA) {
        Ok(b) => b,
        Err(e) => {
            ostd::debug::print_fmt(format_args!("svcmgr: sem buffer de IPC: {e:?}"));
            ostd::thread::exit()
        }
    };
    match ipc::call(boot.root_ep, &Message::new(LABEL_OLA, &[]), deadline) {
        Ok(r) if r.msg.label == 0 => {
            let caps = buffer.get().caps;
            if r.msg.info.caps >= 2 {
                boot.ecam = Handle::from_raw(caps[0]);
                boot.device = Handle::from_raw(caps[1]);
            }
            if r.msg.info.caps >= 3 {
                boot.acpi = Handle::from_raw(caps[2]);
            }
            ostd::debug::print("svcmgr: o root aceitou o anúncio");
        }
        Ok(_) => ostd::debug::print("svcmgr: o root respondeu com erro"),
        Err(Error::AccessDenied) => ostd::debug::print("svcmgr: o root recusou o anúncio"),
        Err(_) => ostd::debug::print("svcmgr: falha ao falar com o root"),
    }
    if let Err(e) = start_all(&boot, buffer) {
        ostd::debug::print_fmt(format_args!("svcmgr: partida falhou: {e:?}"));
    }
    ostd::thread::exit()
}
