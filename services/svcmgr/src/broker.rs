//! Corretor de capabilities (ADR 0034, itens 5, 6, 8 e 9; T-353).
//!
//! Para cada serviço, [`Broker::deliver`] põe no `CapSpace` do filho só o
//! que o manifesto lista, na ordem do item 6: canal de controle, cota,
//! `needs` e `provides`. Devolve o descritor de partida ([`Boot`]).
//! [`Broker::connect`] atende o `Supervisor.connect`: só entrega interfaces
//! que estão em `needs`, e o resto dá [`SvcError::NotInManifest`] (no kabi,
//! `AccessDenied`).
//!
//! Regras de TCB (revisão dupla, SDD 17.1):
//!
//! - Toda capability de `Endpoint` entregue a um serviço leva badge
//!   `(generation << 32) | id`, com `generation` de 1 a `u16::MAX`, então
//!   nunca é zero. `cap_mint` com badge 0 mantém a capability sem badge, e
//!   o dono de uma cópia sem badge poderia cunhar outra com qualquer badge e
//!   se passar por outro cliente. O canal de controle usa o mesmo badge (o
//!   item 6 da ADR diz "badge = id"; os 32 bits baixos continuam sendo o
//!   id).
//! - Os clientes recebem só `SEND`. O provedor recebe `RECV|SEND|GRANT` e
//!   a raiz de derivação fica com o `svcmgr`, que a revoga no reinício.
//! - Tudo que pode ser recusado é conferido antes de qualquer syscall. Se
//!   um `cap_mint` falhar no meio, as raízes já criadas são apagadas e o
//!   chamador destrói o `CapSpace` do filho, que leva as cópias.
//!
//! O corretor não chama o kernel: as operações passam por [`Caps`], que no
//! alvo são syscalls do `ostd` e no host um registro de teste.

use alloc::format;
use alloc::vec::Vec;

use kabi::{Badge, Error as KError, Handle, Rights};
use oman::{NeedKind, Oman};

/// `CapDesc.kind` do canal de controle.
pub const KIND_CONTROL: u8 = 0;
/// `CapDesc.kind` de um `svc:` (como no `OMAN`).
pub const KIND_SVC: u8 = 1;
/// `CapDesc.kind` da cota (`mem:quota:`).
pub const KIND_MEM: u8 = 2;
/// `CapDesc.kind` de um `kernel:`.
pub const KIND_KERNEL: u8 = 5;
/// `CapDesc.kind` de um `provide`.
pub const KIND_PROVIDE: u8 = 6;
/// `CapDesc.index` da cota do processo.
pub const QUOTA_INDEX: u16 = 0xFFFF;

/// Interface do `devmgr` (ADR 0042, item 1).
pub const DEVICE_BUS: &str = "optimus.dev.DeviceBus";

/// Direitos do cliente sobre o endpoint de um provedor.
pub const CLIENT_RIGHTS: Rights = Rights::SEND;
/// Direitos do provedor sobre o próprio endpoint.
pub const PROVIDER_RIGHTS: Rights = Rights::RECV.union(Rights::SEND).union(Rights::GRANT);
/// Direitos do serviço sobre a própria cota.
pub const QUOTA_RIGHTS: Rights = Rights::CREATE.union(Rights::SPLIT);

/// Operações de capability que o corretor pede.
pub trait Caps {
    /// `obj_create(quota, Endpoint)`: devolve a capability completa no
    /// `CapSpace` do `svcmgr` (a raiz de derivação).
    ///
    /// # Errors
    /// Os do kernel.
    fn create_endpoint(&mut self, quota: Handle) -> Result<Handle, KError>;
    /// `cap_mint(src, rights, badge, dest)`; `dest = None` é o próprio
    /// `CapSpace` do `svcmgr`.
    ///
    /// # Errors
    /// Os do kernel.
    fn mint(
        &mut self,
        src: Handle,
        rights: Rights,
        badge: Badge,
        dest: Option<Handle>,
    ) -> Result<Handle, KError>;
    /// `cap_revoke`: apaga todas as cópias derivadas de `h` (as dos
    /// clientes e a do provedor), mantendo `h`.
    ///
    /// # Errors
    /// Os do kernel.
    fn revoke(&mut self, h: Handle) -> Result<(), KError>;
    /// `cap_delete` de uma capability do `svcmgr`.
    ///
    /// # Errors
    /// Os do kernel.
    fn delete(&mut self, h: Handle) -> Result<(), KError>;
}

/// Uma capability do descritor de partida (layout da ADR 0033, 12 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapDesc {
    /// 0 controle, 1 a 5 como em `needs`, 6 `provide`.
    pub kind: u8,
    /// Posição em `needs` ou `provides`; 0 no controle; [`QUOTA_INDEX`].
    pub index: u16,
    /// Handle no `CapSpace` do filho.
    pub handle: u32,
    /// `interface_id` (kinds 1 e 6), hash do nome (3 a 5) ou 0.
    pub name_hash: u32,
}

/// Descritor de partida (`Supervisor.bootstrap`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Boot {
    /// Capabilities entregues, na ordem do item 6.
    pub caps: Vec<CapDesc>,
    /// Geração desta instância.
    pub generation: u16,
}

/// Erros do protocolo `optimus.svc.Supervisor@1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcError {
    /// Fora do manifesto; corresponde a `AccessDenied` no kabi.
    NotInManifest,
    /// Provedor sem instância em `Running`, ou badge de instância velha.
    NotRunning,
    /// O provedor tem versão menor abaixo da pedida.
    VersionTooOld,
    /// O kernel recusou a cópia (cota, slots).
    Busy,
}

/// Recusa de [`Broker::new`] ou [`Broker::deliver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliverError {
    /// Id sem serviço.
    NoSuchService,
    /// Duas provisões com o mesmo `interface_id`.
    DuplicateProvider,
    /// `dev:` ou `fs:` (fora do M3), ou mais de um `mem:quota`.
    NotSupported,
    /// Dependência obrigatória sem provedor em `Running`.
    NotRunning,
    /// `kernel:` obrigatório que o `root` não repassou.
    MissingKernelCap,
    /// Máscara de direitos de `kernel:` zero ou inválida no manifesto.
    BadRights,
    /// O serviço já tem endpoints; falta [`Broker::retire`].
    Busy,
    /// O kernel recusou uma operação.
    Kernel(KError),
}

/// `interface_id` da ADR 0033: os quatro primeiros bytes, em
/// little-endian, de `BLAKE3("<pacote>.<Interface>@<maior>")`.
#[must_use]
pub fn interface_id(name: &str, major: u16) -> u32 {
    name_hash(&format!("{name}@{major}"))
}

/// Os quatro primeiros bytes, em little-endian, de `BLAKE3(text)`.
#[must_use]
pub fn name_hash(text: &str) -> u32 {
    let h = optcrypt::blake3::hash(text.as_bytes());
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Badge do cliente (ADR 0034, item 8).
#[must_use]
pub const fn badge(id: u32, generation: u16) -> Badge {
    ((generation as u64) << 32) | id as u64
}

struct Entry {
    manifest: Oman,
    generation: u16,
    running: bool,
    /// `interface_id` de cada `provide`.
    provide_ids: Vec<u32>,
    /// Raiz de cada `provide`, enquanto a instância existe.
    roots: Vec<Handle>,
}

/// Uma capability a cunhar no filho, já conferida.
enum Step {
    Mint {
        src: Handle,
        rights: Rights,
        badge: Badge,
        kind: u8,
        index: u16,
        name_hash: u32,
    },
    Provide(u16),
}

/// O corretor: manifestos, gerações e raízes dos endpoints.
pub struct Broker {
    svcs: Vec<Entry>,
}

impl Broker {
    /// Corretor para o conjunto compilado; o id de um serviço é a posição
    /// dele em `manifests`.
    ///
    /// # Errors
    /// [`DeliverError::DuplicateProvider`] se duas provisões têm o mesmo
    /// `interface_id`.
    pub fn new(manifests: Vec<Oman>) -> Result<Self, DeliverError> {
        let mut seen: Vec<u32> = Vec::new();
        let mut svcs = Vec::with_capacity(manifests.len());
        for manifest in manifests {
            let mut provide_ids = Vec::with_capacity(manifest.provides.len());
            for p in &manifest.provides {
                let iid = interface_id(&p.name, p.major);
                if seen.contains(&iid) {
                    return Err(DeliverError::DuplicateProvider);
                }
                seen.push(iid);
                provide_ids.push(iid);
            }
            svcs.push(Entry {
                manifest,
                generation: 1,
                running: false,
                provide_ids,
                roots: Vec::new(),
            });
        }
        Ok(Self { svcs })
    }

    /// Manifesto do serviço `id`.
    #[must_use]
    pub fn manifest(&self, id: u32) -> Option<&Oman> {
        self.entry(id).map(|e| &e.manifest)
    }

    /// `id` é o `devmgr`: provê `optimus.dev.DeviceBus@1`, o único que
    /// pode ler a lista de drivers e pedir a partida de um (ADR 0042).
    #[must_use]
    pub fn is_device_manager(&self, id: u32) -> bool {
        let bus = interface_id(DEVICE_BUS, 1);
        self.entry(id).is_some_and(|e| e.provide_ids.contains(&bus))
    }

    /// Badge da instância atual de `id`.
    #[must_use]
    pub fn badge_of(&self, id: u32) -> Option<Badge> {
        self.entry(id).map(|e| badge(id, e.generation))
    }

    fn entry(&self, id: u32) -> Option<&Entry> {
        self.svcs.get(usize::try_from(id).ok()?)
    }

    /// Provedor em `Running` de `iid`: (serviço, posição em `provides`).
    fn provider(&self, iid: u32) -> Option<(&Entry, usize)> {
        self.svcs.iter().find_map(|e| {
            let j = e.provide_ids.iter().position(|&x| x == iid)?;
            (e.running && j < e.roots.len()).then_some((e, j))
        })
    }

    /// Marca `id` como `Running` (`Supervisor.ready`) ou não.
    pub fn set_running(&mut self, id: u32, running: bool) {
        if let Some(e) = usize::try_from(id).ok().and_then(|i| self.svcs.get_mut(i)) {
            e.running = running;
        }
    }

    /// Confere o manifesto de `id` e monta os passos, sem efeito.
    fn plan(
        &self,
        id: u32,
        control: Handle,
        quota: Handle,
        pool: &[(&str, Handle)],
    ) -> Result<Vec<Step>, DeliverError> {
        let e = self.entry(id).ok_or(DeliverError::NoSuchService)?;
        if !e.roots.is_empty() {
            return Err(DeliverError::Busy);
        }
        let b = badge(id, e.generation);
        let mint = |src, rights, badge, kind, index, name_hash| Step::Mint {
            src,
            rights,
            badge,
            kind,
            index,
            name_hash,
        };
        let mut steps = Vec::new();
        steps.push(mint(control, Rights::SEND, b, KIND_CONTROL, 0, 0));
        steps.push(mint(quota, QUOTA_RIGHTS, 0, KIND_MEM, QUOTA_INDEX, 0));
        let mut quotas = 0;
        for (i, need) in e.manifest.needs.iter().enumerate() {
            let index = u16::try_from(i).map_err(|_| DeliverError::NotSupported)?;
            match need.kind {
                NeedKind::Mem => quotas += 1,
                NeedKind::Dev | NeedKind::Fs => return Err(DeliverError::NotSupported),
                NeedKind::Svc => {
                    let iid = interface_id(&need.name, need.major);
                    match self.provider(iid) {
                        Some((p, j)) if p.manifest.provides[j].minor >= need.minor => {
                            steps.push(mint(p.roots[j], CLIENT_RIGHTS, b, KIND_SVC, index, iid));
                        }
                        _ if need.optional => {}
                        _ => return Err(DeliverError::NotRunning),
                    }
                }
                NeedKind::Kernel => {
                    // Menor privilégio: a máscara é obrigatória (o
                    // `mkmanifest` a grava por nome); 0 ou bits
                    // desconhecidos recusam a partida, nunca abrem tudo.
                    let rights = Rights::try_from(need.value)
                        .ok()
                        .filter(|r| *r != Rights::NONE)
                        .ok_or(DeliverError::BadRights)?;
                    match pool.iter().find(|(n, _)| *n == need.name) {
                        Some(&(_, h)) => {
                            steps.push(mint(
                                h,
                                rights,
                                0,
                                KIND_KERNEL,
                                index,
                                name_hash(&need.name),
                            ));
                        }
                        None if need.optional => {}
                        None => return Err(DeliverError::MissingKernelCap),
                    }
                }
            }
        }
        if quotas != 1 {
            return Err(DeliverError::NotSupported);
        }
        for j in 0..e.provide_ids.len() {
            let j = u16::try_from(j).map_err(|_| DeliverError::NotSupported)?;
            steps.push(Step::Provide(j));
        }
        Ok(steps)
    }

    /// Entrega ao filho `child` (`CapSpace` com `MANAGE`) as capabilities
    /// do manifesto de `id`: o canal de controle a partir de `control`
    /// (endpoint do `svcmgr`), a cota `quota` (que também paga os endpoints
    /// dos `provides`, ADR 0034, decisão 4), os `needs` e os `provides`.
    /// `pool` são as capabilities de origem do kernel, por nome
    /// (`kernel:<nome>`).
    ///
    /// # Errors
    /// Ver [`DeliverError`]. Nada é cunhado se a recusa vier do manifesto;
    /// se o kernel recusar no meio, as raízes criadas são apagadas e o
    /// chamador deve destruir `child`.
    pub fn deliver<C: Caps>(
        &mut self,
        id: u32,
        child: Handle,
        control: Handle,
        quota: Handle,
        pool: &[(&str, Handle)],
        caps: &mut C,
    ) -> Result<Boot, DeliverError> {
        let steps = self.plan(id, control, quota, pool)?;
        let i = usize::try_from(id).map_err(|_| DeliverError::NoSuchService)?;
        let mut roots = Vec::new();
        let mut out = Vec::with_capacity(steps.len());
        let mut run = || -> Result<(), KError> {
            for step in &steps {
                let desc = match *step {
                    Step::Mint {
                        src,
                        rights,
                        badge,
                        kind,
                        index,
                        name_hash,
                    } => {
                        let h = caps.mint(src, rights, badge, Some(child))?;
                        CapDesc {
                            kind,
                            index,
                            handle: h.raw(),
                            name_hash,
                        }
                    }
                    Step::Provide(j) => {
                        let root = caps.create_endpoint(quota)?;
                        roots.push(root);
                        let h = caps.mint(root, PROVIDER_RIGHTS, 0, Some(child))?;
                        CapDesc {
                            kind: KIND_PROVIDE,
                            index: j,
                            handle: h.raw(),
                            name_hash: self.svcs[i].provide_ids[usize::from(j)],
                        }
                    }
                };
                out.push(desc);
            }
            Ok(())
        };
        if let Err(err) = run() {
            for root in roots {
                let _ = caps.delete(root);
            }
            return Err(DeliverError::Kernel(err));
        }
        let e = &mut self.svcs[i];
        e.roots = roots;
        e.running = false;
        Ok(Boot {
            caps: out,
            generation: e.generation,
        })
    }

    /// `Supervisor.connect` do cliente com badge `client`: uma capability
    /// `SEND` com o badge dele, no `CapSpace` do `svcmgr`, para ir na
    /// resposta.
    ///
    /// # Errors
    /// [`SvcError::NotInManifest`] para interface fora dos `needs` do
    /// cliente ou badge que não é de serviço; [`SvcError::NotRunning`] para
    /// instância velha ou provedor parado; [`SvcError::VersionTooOld`];
    /// [`SvcError::Busy`] se o kernel recusar.
    pub fn connect<C: Caps>(
        &self,
        client: Badge,
        interface: u32,
        minor: u16,
        caps: &mut C,
    ) -> Result<Handle, SvcError> {
        let id = u32::try_from(client & 0xFFFF_FFFF).map_err(|_| SvcError::NotInManifest)?;
        let generation = client >> 32;
        let e = self.entry(id).ok_or(SvcError::NotInManifest)?;
        if generation != u64::from(e.generation) {
            return Err(SvcError::NotRunning);
        }
        let listed = e
            .manifest
            .needs
            .iter()
            .any(|n| n.kind == NeedKind::Svc && interface_id(&n.name, n.major) == interface);
        if !listed {
            return Err(SvcError::NotInManifest);
        }
        let (p, j) = self.provider(interface).ok_or(SvcError::NotRunning)?;
        if p.manifest.provides[j].minor < minor {
            return Err(SvcError::VersionTooOld);
        }
        caps.mint(p.roots[j], CLIENT_RIGHTS, client, None)
            .map_err(|_| SvcError::Busy)
    }

    /// Fim da instância atual de `id` (morte ou reinício, item 9): devolve
    /// as raízes dos endpoints dela, para o chamador fazer `cap_revoke` e
    /// apagá-las, e avança a geração (de 1 a `u16::MAX`, nunca 0).
    pub fn retire(&mut self, id: u32) -> Vec<Handle> {
        let Some(e) = usize::try_from(id).ok().and_then(|i| self.svcs.get_mut(i)) else {
            return Vec::new();
        };
        e.running = false;
        e.generation = if e.generation == u16::MAX {
            1
        } else {
            e.generation + 1
        };
        core::mem::take(&mut e.roots)
    }
}

#[cfg(test)]
mod tests;
