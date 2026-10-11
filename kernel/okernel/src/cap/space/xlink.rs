//! Elos remotos da árvore de derivação (ADR 0028).
//!
//! Uma cópia transferida por IPC é filha remota da original: o slot da
//! cópia guarda o pai ([`XRef`]: o `CapSpace` por referência fraca, o
//! índice e a geração do slot) e o da original, a lista dos filhos remotos.
//! Os elos ficam numa tabela à parte, ordenada por índice de slot, para não
//! aumentar todos os slots; cada entrada e cada filho remoto são cobrados
//! da cota do `CapSpace` que os guarda.
//!
//! Como um par (índice, geração) nunca volta a valer num `CapSpace`, um elo
//! vencido (o slot do outro lado foi liberado, ou a tabela morreu) é
//! reconhecido na hora de usá-lo, sem varredura. Quem mantém os dois lados
//! coerentes é [`crate::cap::xcdt`], sob a trava global da árvore; aqui só
//! ficam as operações sobre uma tabela.
//!
//! Um slot com filhos remotos não pode ser liberado sem perder esses
//! filhos: `cap_delete` o transforma em marcador ([`CapSpace::entomb`]),
//! que fica na árvore até os descendentes sumirem.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt;
use core::mem::size_of;

use kabi::{CAPSPACE_SLOTS_PER_LEVEL, Error, Handle};

use super::{Cap, CapObject, CapSpace, NIL};
use crate::cap::Object;
use crate::sync::SpinLock;

/// Um slot de outro `CapSpace`, como o elo o vê.
pub struct XRef<const N: usize = CAPSPACE_SLOTS_PER_LEVEL, O: CapObject = Object> {
    space: Weak<SpinLock<CapSpace<N, O>>>,
    index: u32,
    generation: u8,
}

impl<const N: usize, O: CapObject> Clone for XRef<N, O> {
    fn clone(&self) -> Self {
        Self {
            space: Weak::clone(&self.space),
            index: self.index,
            generation: self.generation,
        }
    }
}

impl<const N: usize, O: CapObject> fmt::Debug for XRef<N, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let space = self.space.as_ptr().addr();
        write!(f, "XRef({space:#x}, {}/{})", self.index, self.generation)
    }
}

impl<const N: usize, O: CapObject> XRef<N, O> {
    /// O slot `index`, na geração `generation`, de `space`.
    #[must_use]
    pub fn new(space: &Arc<SpinLock<CapSpace<N, O>>>, index: u32, generation: u8) -> Self {
        Self {
            space: Arc::downgrade(space),
            index,
            generation,
        }
    }

    /// O `CapSpace`, se ainda vivo.
    #[must_use]
    pub fn space(&self) -> Option<Arc<SpinLock<CapSpace<N, O>>>> {
        self.space.upgrade()
    }

    /// Índice do slot.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Geração do slot quando o elo foi feito.
    #[must_use]
    pub const fn generation(&self) -> u8 {
        self.generation
    }

    /// Verdadeiro se o elo aponta para esse slot de `space`.
    #[must_use]
    pub fn is(&self, space: &Arc<SpinLock<CapSpace<N, O>>>, index: u32, generation: u8) -> bool {
        core::ptr::eq(self.space.as_ptr(), Arc::as_ptr(space))
            && self.index == index
            && self.generation == generation
    }

    /// O `CapSpace` do outro lado morreu.
    fn dead(&self) -> bool {
        self.space.strong_count() == 0
    }
}

/// Elos remotos de um slot.
pub(super) struct XLinks<const N: usize, O: CapObject> {
    pub(super) index: u32,
    pub(super) parent: Option<XRef<N, O>>,
    pub(super) children: Vec<XRef<N, O>>,
}

impl<const N: usize, O: CapObject> fmt::Debug for XLinks<N, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {:?} -> {:?}",
            self.index, self.parent, self.children
        )
    }
}

impl<const N: usize, O: CapObject> CapSpace<N, O> {
    /// Bytes cobrados por entrada da tabela de elos remotos.
    const XENTRY_BYTES: u64 = size_of::<XLinks<N, O>>() as u64;
    /// Bytes cobrados por filho remoto.
    const XREF_BYTES: u64 = size_of::<XRef<N, O>>() as u64;

    fn xfind(&self, index: u32) -> Result<usize, usize> {
        self.xlinks.binary_search_by_key(&index, |e| e.index)
    }

    fn xget(&self, index: u32) -> Option<&XLinks<N, O>> {
        self.xfind(index).ok().map(|i| &self.xlinks[i])
    }

    /// A entrada de `index`, criada (e cobrada) se faltar.
    fn xentry(&mut self, index: u32) -> Result<&mut XLinks<N, O>, Error> {
        let at = match self.xfind(index) {
            Ok(at) => at,
            Err(at) => {
                self.charge.grow(Self::XENTRY_BYTES)?;
                if self.xlinks.try_reserve(1).is_err() {
                    self.charge.shrink(Self::XENTRY_BYTES);
                    return Err(Error::QuotaExceeded);
                }
                self.xlinks.insert(
                    at,
                    XLinks {
                        index,
                        parent: None,
                        children: Vec::new(),
                    },
                );
                at
            }
        };
        Ok(&mut self.xlinks[at])
    }

    /// Tira a entrada de `index` se ela ficou vazia.
    fn xprune(&mut self, index: u32) {
        if let Ok(at) = self.xfind(index)
            && self.xlinks[at].parent.is_none()
            && self.xlinks[at].children.is_empty()
        {
            self.xlinks.remove(at);
            self.charge.shrink(Self::XENTRY_BYTES);
        }
    }

    /// Índice do slot de `h` (só capabilities, não marcadores).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`] como em [`get`](Self::get).
    pub fn index(&self, h: Handle) -> Result<u32, Error> {
        self.index_of(h)
    }

    /// Geração atual do slot `index`.
    #[must_use]
    pub fn generation_of(&self, index: u32) -> u8 {
        self.slot(index).generation
    }

    /// Verdadeiro se o slot `index` está ocupado (capability ou marcador)
    /// na geração `generation`.
    #[must_use]
    pub fn holds(&self, index: u32, generation: u8) -> bool {
        index != 0
            && index < self.fresh
            && self.slot(index).generation == generation
            && (self.slot(index).cap.is_some() || self.slot(index).tomb)
    }

    /// Verdadeiro se `index` é o alvo da revogação em andamento.
    #[must_use]
    pub fn is_revoking(&self, index: u32) -> bool {
        self.revoking == Some(index)
    }

    /// Verdadeiro se o slot é um marcador.
    #[must_use]
    pub fn is_tomb(&self, index: u32) -> bool {
        self.slot(index).tomb
    }

    /// Pai local, se houver.
    #[must_use]
    pub fn local_parent(&self, index: u32) -> Option<u32> {
        let parent = self.slot(index).parent;
        (parent != NIL).then_some(parent)
    }

    /// Primeiro filho local, se houver.
    #[must_use]
    pub fn first_local_child(&self, index: u32) -> Option<u32> {
        let child = self.slot(index).first_child;
        (child != NIL).then_some(child)
    }

    /// O slot tem elos remotos (pai ou filhos).
    #[must_use]
    pub fn has_xlinks(&self, index: u32) -> bool {
        self.xfind(index).is_ok()
    }

    /// O slot tem filhos, locais ou remotos (vencidos inclusive).
    #[must_use]
    pub fn has_children(&self, index: u32) -> bool {
        self.slot(index).first_child != NIL
            || self.xget(index).is_some_and(|e| !e.children.is_empty())
    }

    /// Pai remoto, se houver.
    #[must_use]
    pub fn xparent(&self, index: u32) -> Option<XRef<N, O>> {
        self.xget(index).and_then(|e| e.parent.clone())
    }

    /// Primeiro filho remoto, se houver.
    #[must_use]
    pub fn first_xchild(&self, index: u32) -> Option<XRef<N, O>> {
        self.xget(index).and_then(|e| e.children.first().cloned())
    }

    /// Faz de `parent` o pai remoto de `index`, uma raiz local.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota ou memória para a entrada;
    /// [`Error::InvalidArgument`] se `index` tiver pai local.
    pub fn set_xparent(&mut self, index: u32, parent: XRef<N, O>) -> Result<(), Error> {
        if self.slot(index).parent != NIL {
            return Err(Error::InvalidArgument);
        }
        self.xentry(index)?.parent = Some(parent);
        Ok(())
    }

    /// Esquece o pai remoto de `index`.
    pub fn clear_xparent(&mut self, index: u32) {
        if let Ok(at) = self.xfind(index) {
            self.xlinks[at].parent = None;
            self.xprune(index);
        }
    }

    /// Acrescenta `child` aos filhos remotos de `index`, descartando antes
    /// os filhos em tabelas que já morreram.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota ou memória.
    pub fn add_xchild(&mut self, index: u32, child: XRef<N, O>) -> Result<(), Error> {
        let mut dead = 0;
        if let Ok(at) = self.xfind(index) {
            let children = &mut self.xlinks[at].children;
            let before = children.len();
            children.retain(|c| !c.dead());
            dead = before - children.len();
        }
        self.charge.shrink(dead as u64 * Self::XREF_BYTES);
        self.charge.grow(Self::XREF_BYTES)?;
        let entry = match self.xentry(index) {
            Ok(entry) => entry,
            Err(e) => {
                self.charge.shrink(Self::XREF_BYTES);
                return Err(e);
            }
        };
        if entry.children.try_reserve(1).is_err() {
            self.charge.shrink(Self::XREF_BYTES);
            self.xprune(index);
            return Err(Error::QuotaExceeded);
        }
        entry.children.push(child);
        Ok(())
    }

    /// Tira dos filhos remotos de `index` o elo para o slot `child` de
    /// `space` (na geração `generation`); falso se não estava lá.
    pub fn remove_xchild(
        &mut self,
        index: u32,
        space: &Arc<SpinLock<Self>>,
        child: u32,
        generation: u8,
    ) -> bool {
        let Ok(at) = self.xfind(index) else {
            return false;
        };
        let children = &mut self.xlinks[at].children;
        let Some(i) = children.iter().position(|c| c.is(space, child, generation)) else {
            return false;
        };
        children.swap_remove(i);
        self.charge.shrink(Self::XREF_BYTES);
        self.xprune(index);
        true
    }

    /// Tira dos filhos remotos de `index` o primeiro elo, se for `child`
    /// (elo vencido, achado ao percorrer a árvore).
    pub fn drop_first_xchild(&mut self, index: u32, child: &XRef<N, O>) {
        if let Ok(at) = self.xfind(index)
            && self.xlinks[at].children.first().is_some_and(|c| {
                core::ptr::eq(c.space.as_ptr(), child.space.as_ptr())
                    && c.index == child.index
                    && c.generation == child.generation
            })
        {
            self.xlinks[at].children.swap_remove(0);
            self.charge.shrink(Self::XREF_BYTES);
            self.xprune(index);
        }
    }

    /// `cap_delete` de um slot com descendentes remotos: tira a capability
    /// (para quem chama destruí-la sem a trava) e deixa um marcador no
    /// lugar, com os mesmos elos.
    pub fn entomb(&mut self, index: u32) -> Option<Cap<O>> {
        let slot = self.slot_mut(index);
        let cap = slot.cap.take()?;
        slot.tomb = true;
        self.live -= 1;
        Some(cap)
    }

    /// Libera o slot `index`, que não pode ter filhos (locais ou remotos):
    /// tira-o da lista de irmãos, esquece o pai remoto e encerra a
    /// revogação que o tinha como alvo. Devolve a capability (nenhuma num
    /// marcador).
    pub fn free_leaf(&mut self, index: u32) -> Option<Cap<O>> {
        debug_assert!(!self.has_children(index));
        if let Ok(at) = self.xfind(index) {
            let children = self.xlinks[at].children.len() as u64;
            self.xlinks.remove(at);
            self.charge
                .shrink(Self::XENTRY_BYTES + children * Self::XREF_BYTES);
        }
        if self.revoking == Some(index) {
            self.revoking = None;
        }
        self.unlink_lifting_children(index);
        self.release(index)
    }

    /// Confere a tabela de elos remotos (parte de `check_invariants`).
    pub(super) fn check_xlinks(&self) -> Result<(), &'static str> {
        for pair in self.xlinks.windows(2) {
            if pair[0].index >= pair[1].index {
                return Err("elos remotos fora de ordem");
            }
        }
        for e in &self.xlinks {
            if !self.holds(e.index, self.slot(e.index).generation) {
                return Err("elos remotos de slot livre");
            }
            if e.parent.is_none() && e.children.is_empty() {
                return Err("entrada de elos remotos vazia");
            }
            if e.parent.is_some() && self.slot(e.index).parent != NIL {
                return Err("pai remoto em slot com pai local");
            }
        }
        Ok(())
    }
}
