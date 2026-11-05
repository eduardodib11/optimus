//! `memd`: tratador de faltas de página em espaço de usuário (T-361; ADR
//! 0038, itens 3 e 6).
//!
//! O kernel manda cada falta de uma thread ao endpoint de exceções dela
//! (`kabi::fault`); o `memd` é o tratador padrão. Esta crate guarda a tabela
//! de regiões gerenciadas por processo ([`Pager`]) e o laço que atende as
//! faltas ([`serve`]):
//!
//! - falta de página dentro de uma região registrada: `COMMIT` com
//!   `PUBLISH` da página (demand-zero) e resposta `REPLY_RESUME`;
//! - região `Stack`: igual, até o limite reservado; a página de guarda abaixo
//!   dela não pertence a nenhuma região;
//! - endereço abaixo de [`NULL_LIMIT`], fora de qualquer região, falta de
//!   proteção (página presente), execução ou outra exceção: resposta sem
//!   `RESUME`, que encerra a thread, e a falta entra na contagem de
//!   [`Pager::denied`].
//!
//! O processo é identificado pelos 32 bits baixos do badge do endpoint
//! (ADR 0034, item 8). Ficam para depois: a interface OIDL
//! `optimus.mem.Mem@1` com transferência do objeto (`manage` remoto), o
//! aviso ao `svcmgr` ao negar uma falta (T-353) e a pressão global de
//! memória.
//!
//! Com [`Pager::enable_compression`], a região ganha memória comprimida
//! ([`compress`], T-364): quando o `COMMIT` dá `QuotaExceeded`, o `memd`
//! despeja a página mais fria do mesmo processo e tenta de novo
//! (auto-paginação), e a falta numa página despejada a restaura.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod compress;

use alloc::vec::Vec;

use ostd::cap;
use ostd::ipc::{self, Message};
use ostd::kabi::fault::{PAGE_FAULT, REPLY_RESUME, WORD_ADDR, WORD_ERROR};
use ostd::kabi::vm::PAGE_SIZE;
use ostd::kabi::{Badge, Error, Handle, ObjectType, Rights};
use ostd::mem;

/// Endereços abaixo deste limite nunca são atendidos (acesso nulo).
pub const NULL_LIMIT: u64 = 0x1_0000;
/// Regiões por processo (ADR 0038, item 4).
pub const MAX_REGIONS_PER_PROCESS: usize = 64;
/// Regiões no `memd` inteiro.
pub const MAX_REGIONS: usize = 1024;
/// Rótulo da resposta que encerra a thread que faltou.
pub const REPLY_KILL: u64 = 1;

/// Bit do código de erro do #PF: a página estava presente (falta de
/// proteção).
const PF_PRESENT: u64 = 1;
/// Bit do código de erro do #PF: busca de instrução.
const PF_FETCH: u64 = 1 << 4;

/// Tipo da região (`optimus.mem.RegionKind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Heap do processo.
    Heap,
    /// Pilha: cresce sob demanda até o limite reservado.
    Stack,
    /// Memória anônima.
    Anon,
}

/// Erros de [`Pager::manage`] e [`Pager::unmanage`] (`optimus.mem.MemError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemError {
    /// O objeto não é um `MemoryObject` com `READ|WRITE|MAP|EVICT`.
    AccessDenied,
    /// Faixa vazia, desalinhada, abaixo de [`NULL_LIMIT`] ou sobreposta.
    InvalidArgument,
    /// Limite de regiões atingido.
    TooMany,
    /// A região ainda tem estado do `memd` (memória comprimida, T-364).
    Busy,
}

/// Por que uma falta foi negada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// Exceção que não é falta de página.
    NotPageFault,
    /// Endereço abaixo de [`NULL_LIMIT`].
    Null,
    /// Página presente: violação de proteção.
    Protection,
    /// Busca de instrução em região sem execução.
    Exec,
    /// Endereço fora de qualquer região do processo.
    Unmanaged,
    /// O `COMMIT` falhou (cota esgotada, objeto destruído...).
    Commit(Error),
}

/// Decisão sobre uma falta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Comprometer a página em `offset` de `object` e retomar.
    Commit {
        /// O objeto da região.
        object: Handle,
        /// Deslocamento da página no objeto.
        offset: u64,
    },
    /// Encerrar a thread.
    Deny(Denial),
}

/// Tentativas de despejo por falta antes de desistir.
const EVICT_TRIES: usize = 8;

#[derive(Debug)]
struct Region {
    id: u32,
    owner: u32,
    object: Handle,
    base: u64,
    len: u64,
    kind: Kind,
    store: Option<compress::Store>,
}

/// Tabela de regiões gerenciadas e contadores.
#[derive(Debug, Default)]
pub struct Pager {
    regions: Vec<Region>,
    next_id: u32,
    /// Faltas atendidas.
    pub served: u64,
    /// Faltas negadas.
    pub denied: u64,
    /// Última negação, para relatório.
    pub last_denial: Option<(u32, u64, Denial)>,
}

/// Processo dono de uma falta: os 32 bits baixos do badge.
#[must_use]
pub const fn owner_of(badge: Badge) -> u32 {
    (badge & 0xffff_ffff) as u32
}

impl Pager {
    /// Tabela vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
            next_id: 1,
            served: 0,
            denied: 0,
            last_denial: None,
        }
    }

    /// Registra `[base, base + len)` do processo `owner`, servida por
    /// `object` a partir do deslocamento 0. O cliente garante que mapeou o
    /// objeto em `base`.
    ///
    /// # Errors
    ///
    /// Os de [`MemError`].
    pub fn manage(
        &mut self,
        owner: u32,
        object: Handle,
        base: u64,
        len: u64,
        kind: Kind,
    ) -> Result<u32, MemError> {
        let end = base.checked_add(len).ok_or(MemError::InvalidArgument)?;
        if len == 0
            || !base.is_multiple_of(PAGE_SIZE)
            || !len.is_multiple_of(PAGE_SIZE)
            || base < NULL_LIMIT
        {
            return Err(MemError::InvalidArgument);
        }
        let need = Rights::READ | Rights::WRITE | Rights::MAP | Rights::EVICT;
        match cap::info(object) {
            Ok(i) if i.object_type == ObjectType::MemoryObject && i.rights.contains(need) => {}
            _ => return Err(MemError::AccessDenied),
        }
        let mine = self.regions.iter().filter(|r| r.owner == owner);
        if mine.clone().any(|r| base < r.base + r.len && r.base < end) {
            return Err(MemError::InvalidArgument);
        }
        if mine.count() >= MAX_REGIONS_PER_PROCESS || self.regions.len() >= MAX_REGIONS {
            return Err(MemError::TooMany);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.regions.push(Region {
            id,
            owner,
            object,
            base,
            len,
            kind,
            store: None,
        });
        Ok(id)
    }

    /// Tira a região `id` do processo `owner`; o controle volta ao cliente.
    ///
    /// # Errors
    ///
    /// [`MemError::InvalidArgument`] se a região não existe ou é de outro.
    pub fn unmanage(&mut self, owner: u32, id: u32) -> Result<(), MemError> {
        let at = self
            .regions
            .iter()
            .position(|r| r.id == id && r.owner == owner)
            .ok_or(MemError::InvalidArgument)?;
        self.regions.swap_remove(at);
        Ok(())
    }

    /// Liga a memória comprimida na região `id` de `owner`: o `memd` mapeia
    /// a visão `RAW` do objeto em `raw_va` do próprio espaço e guarda no
    /// máximo `max_compressed` bytes comprimidos da região.
    ///
    /// # Errors
    ///
    /// [`MemError::InvalidArgument`] se a região não existe ou o mapeamento
    /// falha; [`MemError::Busy`] se já estiver ligada.
    pub fn enable_compression(
        &mut self,
        owner: u32,
        id: u32,
        raw_va: u64,
        max_compressed: u64,
    ) -> Result<(), MemError> {
        let r = self
            .regions
            .iter_mut()
            .find(|r| r.id == id && r.owner == owner)
            .ok_or(MemError::InvalidArgument)?;
        if r.store.is_some() {
            return Err(MemError::Busy);
        }
        let store = compress::Store::new(r.object, raw_va, r.len, max_compressed)
            .map_err(|_| MemError::InvalidArgument)?;
        r.store = Some(store);
        Ok(())
    }

    /// Contadores de compressão da região `id` de `owner`.
    #[must_use]
    pub fn compression_stats(&self, owner: u32, id: u32) -> Option<compress::Stats> {
        self.regions
            .iter()
            .find(|r| r.id == id && r.owner == owner)
            .and_then(|r| r.store.as_ref().map(|s| s.stats))
    }

    /// Resolve a falta na página `offset` da região de `owner` em `addr`,
    /// despejando páginas frias do mesmo processo se a cota acabar.
    fn resolve(&mut self, owner: u32, addr: u64, offset: u64) -> Result<(), Error> {
        let Some(i) = self
            .regions
            .iter()
            .position(|r| r.owner == owner && addr >= r.base && addr - r.base < r.len)
        else {
            return Err(Error::InvalidArgument);
        };
        for _ in 0..EVICT_TRIES {
            let r = &mut self.regions[i];
            let result = match r.store.as_mut() {
                Some(s) => s.fault_in(r.object, offset),
                None => mem::commit(r.object, offset, PAGE_SIZE, true),
            };
            match result {
                Err(Error::QuotaExceeded) if self.evict_from(owner)? => {}
                other => return other,
            }
        }
        Err(Error::QuotaExceeded)
    }

    /// Despeja uma página de alguma região comprimida de `owner`.
    fn evict_from(&mut self, owner: u32) -> Result<bool, Error> {
        for r in self.regions.iter_mut().filter(|r| r.owner == owner) {
            if let Some(s) = r.store.as_mut()
                && s.evict_one(r.object)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Esquece todas as regiões de `owner` (processo encerrado).
    pub fn forget(&mut self, owner: u32) {
        self.regions.retain(|r| r.owner != owner);
    }

    /// Tipo da região de `owner` que contém `addr`.
    #[must_use]
    pub fn kind_at(&self, owner: u32, addr: u64) -> Option<Kind> {
        self.find(owner, addr).map(|r| r.kind)
    }

    fn find(&self, owner: u32, addr: u64) -> Option<&Region> {
        self.regions
            .iter()
            .find(|r| r.owner == owner && addr >= r.base && addr - r.base < r.len)
    }

    /// Decide o que fazer com a falta `vector`/`error` em `addr` de `owner`.
    #[must_use]
    pub fn decide(&self, owner: u32, vector: u64, error: u64, addr: u64) -> Decision {
        if vector != PAGE_FAULT {
            return Decision::Deny(Denial::NotPageFault);
        }
        if addr < NULL_LIMIT {
            return Decision::Deny(Denial::Null);
        }
        if error & PF_PRESENT != 0 {
            return Decision::Deny(Denial::Protection);
        }
        if error & PF_FETCH != 0 {
            return Decision::Deny(Denial::Exec);
        }
        match self.find(owner, addr) {
            Some(r) => Decision::Commit {
                object: r.object,
                offset: (addr - r.base) & !(PAGE_SIZE - 1),
            },
            None => Decision::Deny(Denial::Unmanaged),
        }
    }

    /// Atende uma falta e devolve o rótulo da resposta.
    pub fn handle(&mut self, badge: Badge, msg: &Message) -> u64 {
        let owner = owner_of(badge);
        let addr = msg.words[WORD_ADDR];
        let decision = self.decide(owner, msg.label, msg.words[WORD_ERROR], addr);
        let denial = match decision {
            Decision::Commit { offset, .. } => match self.resolve(owner, addr, offset) {
                Ok(()) => {
                    self.served += 1;
                    return REPLY_RESUME;
                }
                Err(e) => Denial::Commit(e),
            },
            Decision::Deny(d) => d,
        };
        self.denied += 1;
        self.last_denial = Some((owner, addr, denial));
        REPLY_KILL
    }
}

/// Atende faltas de `ep` (com o `Reply` `reply`) até `stop` devolver
/// `true` depois de uma falta ou depois de `idle_ns` sem faltas (0: sem
/// prazo), ou até o `recv` falhar.
///
/// # Errors
///
/// O erro do `recv` que encerrou o laço.
pub fn serve(
    pager: &mut Pager,
    ep: Handle,
    reply: Handle,
    idle_ns: u64,
    mut stop: impl FnMut(&Pager) -> bool,
) -> Result<(), Error> {
    let deadline = || {
        if idle_ns == 0 {
            0
        } else {
            ostd::time::now_ns() + idle_ns
        }
    };
    let mut got = ipc::recv(ep, reply, deadline());
    loop {
        let m = match got {
            Ok(m) => m,
            Err(Error::TimedOut) if stop(pager) => return Ok(()),
            Err(Error::TimedOut) => {
                got = ipc::recv(ep, reply, deadline());
                continue;
            }
            Err(e) => return Err(e),
        };
        let label = pager.handle(m.badge, &m.msg);
        if stop(pager) {
            return ipc::send(reply, &Message::new(label, &[]), 0);
        }
        got = ipc::reply_recv(ep, reply, &Message::new(label, &[]), deadline());
    }
}
