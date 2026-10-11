//! `CapSpace`: tabela radix de capabilities de um processo (T-203; seção 6.2).
//!
//! Dois níveis de `N` slots ([`CAPSPACE_SLOTS_PER_LEVEL`] = 4096 no kernel):
//! o índice de 24 bits do [`Handle`] se divide em folha (`índice / N`) e
//! posição na folha (`índice % N`). As folhas nascem sob demanda, na ordem
//! dos índices, e cada uma é cobrada da cota do `CapSpace` (`N` slots mais a
//! entrada na raiz) com alocação falível, devolvida quando a tabela morre.
//!
//! Cada slot guarda a capability ([`Cap`]: objeto contado, direitos e badge)
//! e uma geração de 8 bits. Liberar o slot avança a geração, então um handle
//! antigo deixa de resolver ([`Error::InvalidHandle`]) mesmo com o slot
//! reutilizado; o slot que chegaria à geração 255 é aposentado, nunca
//! reutilizado, e assim um par (índice, geração) nunca volta a valer depois
//! de liberado (o `MaxGen` da spec `CapRevoke.tla`). O índice 0 nunca é
//! entregue: o handle 0 é sempre inválido.
//!
//! Os slots livres formam uma lista encadeada por índice: alocar e liberar
//! custam O(1), sem varrer a folha.
//!
//! A árvore de derivação e a revogação fatiada (T-204) ficam em [`cdt`].

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::mem::size_of;

use kabi::{Badge, CAPSPACE_SLOTS_PER_LEVEL, Error, Handle, ObjectType, Rights};

use super::object::{Object, default_rights, obj_create, object_bytes};
use super::quota::{Charge, MemoryQuota};
use crate::sync::SpinLock;

pub mod cdt;
pub use cdt::{MAX_DERIVATION_DEPTH, Revoke};

/// Fim de lista.
const NIL: u32 = u32::MAX;
/// Geração em que o slot é aposentado.
pub const RETIRED_GENERATION: u8 = u8::MAX;

/// O que um slot referencia. No kernel é sempre [`Object`]; a tabela é
/// genérica só para as provas do Kani usarem um objeto sem destruição em
/// cadeia (a lógica de slots e da árvore não depende do objeto).
pub trait CapObject: Clone + Debug {
    /// Tipo do objeto.
    fn object_type(&self) -> ObjectType;
    /// Verdadeiro se as duas referências apontam para o mesmo objeto.
    fn same(&self, other: &Self) -> bool;
}

impl CapObject for Object {
    fn object_type(&self) -> ObjectType {
        Object::object_type(self)
    }

    fn same(&self, other: &Self) -> bool {
        Object::same(self, other)
    }
}

/// Uma capability: objeto, direitos e badge.
#[derive(Clone, Debug)]
pub struct Cap<O = Object> {
    /// Objeto referenciado (conta uma referência).
    pub object: O,
    /// Direitos sobre o objeto.
    pub rights: Rights,
    /// Badge entregue ao servidor junto com as mensagens (seção 6.2).
    pub badge: Badge,
}

/// O que `cap_info` revela de uma capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapInfo {
    /// Tipo do objeto.
    pub object_type: ObjectType,
    /// Direitos.
    pub rights: Rights,
    /// Badge (zero se nenhum).
    pub badge: Badge,
}

/// Um slot da tabela: a capability, a geração e os elos da árvore de
/// derivação, todos por índice (`NIL` = nenhum).
#[derive(Debug)]
struct Slot<O> {
    cap: Option<Cap<O>>,
    generation: u8,
    /// Pai na árvore de derivação (`NIL`: raiz, de `obj_create`/`insert`).
    parent: u32,
    first_child: u32,
    /// Próximo irmão; num slot livre, o próximo da lista livre.
    next: u32,
    prev: u32,
}

impl<O> Slot<O> {
    const fn empty() -> Self {
        Self {
            cap: None,
            generation: 0,
            parent: NIL,
            first_child: NIL,
            next: NIL,
            prev: NIL,
        }
    }
}

/// Tabela de capabilities com `N` slots por nível.
#[derive(Debug)]
pub struct CapSpace<const N: usize = CAPSPACE_SLOTS_PER_LEVEL, O: CapObject = Object> {
    /// Cobrança do objeto mais as folhas.
    charge: Charge,
    leaves: Vec<Box<[Slot<O>]>>,
    /// Primeiro índice nunca usado.
    fresh: u32,
    /// Topo da lista de slots livres.
    free: u32,
    live: u32,
    /// Slot cuja revogação está em andamento.
    revoking: Option<u32>,
}

impl<const N: usize, O: CapObject> CapSpace<N, O> {
    /// Slots ao todo: `N` folhas de `N` slots, cabendo nos 24 bits do handle.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "o assert limita N * N a 2^24"
    )]
    pub const CAPACITY: u32 = {
        assert!(N >= 2 && N * N <= Handle::MAX_INDEX as usize + 1);
        (N * N) as u32
    };
    /// Bytes cobrados por folha: os slots mais a entrada na raiz.
    pub const LEAF_BYTES: u64 = (N * size_of::<Slot<O>>() + size_of::<Box<[Slot<O>]>>()) as u64;

    /// Tabela vazia, cobrando de `quota` o tamanho do objeto.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem bytes na cota.
    pub fn new(quota: &Arc<MemoryQuota>) -> Result<Self, Error> {
        Ok(Self {
            charge: quota.charge(object_bytes::<SpinLock<Self>>())?,
            leaves: Vec::new(),
            fresh: 1,
            free: NIL,
            live: 0,
            revoking: None,
        })
    }

    /// Capabilities vivas.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.live
    }

    /// Verdadeiro sem capabilities.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.live == 0
    }

    /// Bytes cobrados da cota: objeto mais folhas.
    #[must_use]
    pub const fn charged(&self) -> u64 {
        self.charge.bytes()
    }

    fn slot(&self, index: u32) -> &Slot<O> {
        &self.leaves[index as usize / N][index as usize % N]
    }

    fn slot_mut(&mut self, index: u32) -> &mut Slot<O> {
        &mut self.leaves[index as usize / N][index as usize % N]
    }

    /// Índice do slot de `h`, se ele estiver ocupado na mesma geração.
    fn index_of(&self, h: Handle) -> Result<u32, Error> {
        let index = h.index();
        if index == 0 || index >= self.fresh {
            return Err(Error::InvalidHandle);
        }
        let slot = self.slot(index);
        if slot.cap.is_none() || slot.generation != h.generation() {
            return Err(Error::InvalidHandle);
        }
        Ok(index)
    }

    fn handle(&self, index: u32) -> Handle {
        Handle::new(index, self.slot(index).generation).unwrap_or(Handle::from_raw(0))
    }

    /// Acrescenta uma folha, cobrando-a da cota; falha sem mudar nada.
    fn grow(&mut self) -> Result<(), Error> {
        self.charge.grow(Self::LEAF_BYTES)?;
        let mut leaf = Vec::new();
        if leaf.try_reserve_exact(N).is_err() || self.leaves.try_reserve_exact(1).is_err() {
            self.charge.shrink(Self::LEAF_BYTES);
            return Err(Error::QuotaExceeded);
        }
        leaf.resize_with(N, Slot::empty);
        self.leaves.push(leaf.into_boxed_slice());
        Ok(())
    }

    /// Reserva um slot livre (sem capability ainda).
    fn alloc_slot(&mut self) -> Result<u32, Error> {
        if self.free != NIL {
            let index = self.free;
            self.free = self.slot(index).next;
            return Ok(index);
        }
        if self.fresh >= Self::CAPACITY {
            return Err(Error::QuotaExceeded);
        }
        if self.fresh as usize >= self.leaves.len() * N {
            self.grow()?;
        }
        self.fresh += 1;
        Ok(self.fresh - 1)
    }

    /// Ocupa um slot com `cap`, sem pai e sem filhos, e devolve o handle.
    fn occupy(&mut self, index: u32, cap: Cap<O>) -> Handle {
        let slot = self.slot_mut(index);
        *slot = Slot {
            cap: Some(cap),
            generation: slot.generation,
            ..Slot::empty()
        };
        self.live += 1;
        self.handle(index)
    }

    /// Esvazia o slot (já fora da árvore), avança a geração e o devolve à
    /// lista livre (ou o aposenta). Devolve a capability que estava nele.
    fn release(&mut self, index: u32) -> Option<Cap<O>> {
        let free = self.free;
        let slot = self.slot_mut(index);
        let cap = slot.cap.take()?;
        let generation = slot.generation + 1;
        let retired = generation == RETIRED_GENERATION;
        *slot = Slot {
            generation,
            next: if retired { NIL } else { free },
            ..Slot::empty()
        };
        if !retired {
            self.free = index;
        }
        self.live -= 1;
        Some(cap)
    }

    /// Guarda uma capability sem pai (a de `obj_create` ou uma inicial).
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] se a tabela estiver cheia ou a cota não
    /// cobrir uma folha nova.
    pub fn insert(&mut self, cap: Cap<O>) -> Result<Handle, Error> {
        let index = self.alloc_slot()?;
        Ok(self.occupy(index, cap))
    }

    /// A capability de `h`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`] se `h` não aponta para um slot ocupado na
    /// mesma geração.
    pub fn get(&self, h: Handle) -> Result<&Cap<O>, Error> {
        let index = self.index_of(h)?;
        self.slot(index).cap.as_ref().ok_or(Error::InvalidHandle)
    }

    /// `cap_info`: tipo, direitos e badge.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`] como em [`get`](Self::get).
    pub fn info(&self, h: Handle) -> Result<CapInfo, Error> {
        let cap = self.get(h)?;
        Ok(CapInfo {
            object_type: cap.object.object_type(),
            rights: cap.rights,
            badge: cap.badge,
        })
    }

    /// `cap_mint`: cópia de `src`, filha dela na árvore de derivação, com os
    /// direitos de `src` reduzidos por `mask` e, opcionalmente, um badge.
    ///
    /// Os direitos da cópia são `src.rights.derive(mask)`, sempre contidos
    /// nos de `src`. Só uma capability sem badge (badge 0) recebe badge:
    /// trocar o badge de outra forjaria a identidade que o servidor vê.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`] para `src` inválido; [`Error::Busy`] se `src`
    /// estiver numa subárvore em revogação; [`Error::InvalidArgument`] além
    /// de [`MAX_DERIVATION_DEPTH`]; [`Error::AccessDenied`] para badge sobre
    /// capability que já tem um; [`Error::QuotaExceeded`] sem slot.
    pub fn mint(
        &mut self,
        src: Handle,
        mask: Rights,
        badge: Option<Badge>,
    ) -> Result<Handle, Error> {
        let src = self.index_of(src)?;
        self.check_mint_parent(src)?;
        let parent = self.slot(src).cap.as_ref().ok_or(Error::InvalidHandle)?;
        let badge = match badge {
            Some(_) if parent.badge != 0 => return Err(Error::AccessDenied),
            Some(b) => b,
            None => parent.badge,
        };
        // O slot vem antes da cópia: falhar não cria nem destrói referência.
        let index = self.alloc_slot()?;
        let parent = self.slot(src).cap.as_ref().ok_or(Error::InvalidHandle)?;
        let cap = Cap {
            object: parent.object.clone(),
            rights: parent.rights.derive(mask),
            badge,
        };
        let h = self.occupy(index, cap);
        self.link_child(src, index);
        Ok(h)
    }

    /// `cap_delete`: libera o slot de `h` e devolve a capability, para quem
    /// chama destruí-la (e talvez o objeto) depois de soltar a trava. Os
    /// filhos sobem para o avô (ou viram raízes); os direitos deles seguem
    /// contidos nos do novo pai, por transitividade.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`] como em [`get`](Self::get); [`Error::Busy`]
    /// se `h` for o alvo de uma revogação em andamento.
    pub fn delete(&mut self, h: Handle) -> Result<Cap<O>, Error> {
        let index = self.index_of(h)?;
        if self.revoking == Some(index) {
            return Err(Error::Busy);
        }
        self.unlink_lifting_children(index);
        self.release(index).ok_or(Error::InvalidHandle)
    }
}

impl<const N: usize> CapSpace<N, Object> {
    /// `obj_create` pela capability `quota` desta tabela: cria o objeto e
    /// guarda a capability dele, com os direitos de [`default_rights`].
    ///
    /// Exige `CREATE` na cota, e também `SPLIT` para criar uma cota filha.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`], [`Error::WrongType`] se `quota` não for uma
    /// cota, [`Error::AccessDenied`] sem os direitos e os erros de
    /// [`obj_create`].
    pub fn obj_create(
        &mut self,
        quota: Handle,
        ty: ObjectType,
        args: u64,
    ) -> Result<Handle, Error> {
        let cap = self.get(quota)?;
        let q = Arc::clone(cap.object.as_quota()?);
        let needed = if ty == ObjectType::MemoryQuota {
            Rights::CREATE | Rights::SPLIT
        } else {
            Rights::CREATE
        };
        if !cap.rights.contains(needed) {
            return Err(Error::AccessDenied);
        }
        let object = obj_create(&q, ty, args)?;
        self.insert(Cap {
            object,
            rights: default_rights(ty),
            badge: 0,
        })
    }
}

#[cfg(kani)]
mod proofs;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_cdt;
