//! Árvore de derivação e `cap_revoke` fatiado (T-204; seção 6.2).
//!
//! Segue a spec `docs/spec/tla/CapRevoke.tla` (T-008): cada slot guarda o
//! pai, o primeiro filho e os irmãos, por índice. `cap_mint` pendura a cópia
//! sob a origem; `cap_delete` sobe os filhos para o avô; `cap_revoke(c)`
//! apaga todos os descendentes de `c`, folha por folha, em fatias com
//! orçamento de trabalho, e devolve [`Revoke::Continue`] até terminar. Uma
//! revogação por `CapSpace` fica em andamento entre as fatias e, enquanto
//! isso, `cap_mint` dentro da subárvore e `cap_delete` do alvo retornam
//! [`Error::Busy`], e outra revogação também (`RevokeStart` exige
//! `revoking = None`). Chamar `cap_revoke(c)` de novo retoma a mesma.
//!
//! A profundidade da árvore é limitada a [`MAX_DERIVATION_DEPTH`] (o SDD
//! não limita): conferir se a origem de um mint está em revogação sobe no
//! máximo esse número de pais, e cada fatia recomeça do alvo descendo no
//! máximo isso até uma folha, sem cursor que um delete concorrente possa
//! invalidar. Como delete só encurta caminhos, o limite vale sempre.

use kabi::{Error, Handle};

use super::{CapObject, CapSpace, NIL};

/// Maior profundidade de uma capability na árvore (raiz = 0).
pub const MAX_DERIVATION_DEPTH: u32 = 64;

/// Resultado de uma fatia de `cap_revoke`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revoke {
    /// Nenhum descendente sobrou; a revogação acabou.
    Done,
    /// O orçamento acabou; chamar de novo, depois de um ponto de
    /// preempção, para continuar.
    Continue,
}

impl<const N: usize, O: CapObject> CapSpace<N, O> {
    /// `Busy` se `src` estiver numa subárvore em revogação;
    /// `InvalidArgument` se um filho passaria de [`MAX_DERIVATION_DEPTH`].
    pub(super) fn check_mint_parent(&self, src: u32) -> Result<(), Error> {
        let mut node = src;
        let mut depth = 0;
        loop {
            if self.revoking == Some(node) {
                return Err(Error::Busy);
            }
            let parent = self.slot(node).parent;
            if parent == NIL {
                break;
            }
            node = parent;
            depth += 1;
        }
        if depth >= MAX_DERIVATION_DEPTH {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Pendura `child` (recém-ocupado) como primeiro filho de `parent`.
    pub(super) fn link_child(&mut self, parent: u32, child: u32) {
        let first = self.slot(parent).first_child;
        if first != NIL {
            self.slot_mut(first).prev = child;
        }
        let slot = self.slot_mut(child);
        slot.parent = parent;
        slot.next = first;
        slot.prev = NIL;
        self.slot_mut(parent).first_child = child;
    }

    /// Tira `node` da lista de filhos do pai; os filhos dele, se houver,
    /// tomam o lugar dele na lista, com o avô como pai (ou viram raízes).
    pub(super) fn unlink_lifting_children(&mut self, node: u32) {
        let (parent, prev, next, first) = {
            let s = self.slot(node);
            (s.parent, s.prev, s.next, s.first_child)
        };
        // Primeiro e último elo que ocupam o lugar de `node`.
        let (mut head, mut tail) = (next, prev);
        if first != NIL {
            let mut child = first;
            let mut last = first;
            while child != NIL {
                let slot = self.slot_mut(child);
                slot.parent = parent;
                if parent == NIL {
                    // Raízes não ficam em lista de irmãos.
                    let after = slot.next;
                    slot.next = NIL;
                    slot.prev = NIL;
                    child = after;
                } else {
                    last = child;
                    child = slot.next;
                }
            }
            if parent != NIL {
                self.slot_mut(first).prev = prev;
                self.slot_mut(last).next = next;
                (head, tail) = (first, last);
            }
        }
        if prev == NIL {
            if parent != NIL {
                self.slot_mut(parent).first_child = head;
            }
        } else {
            self.slot_mut(prev).next = head;
        }
        if next != NIL {
            self.slot_mut(next).prev = tail;
        }
        let slot = self.slot_mut(node);
        slot.parent = NIL;
        slot.first_child = NIL;
        slot.next = NIL;
        slot.prev = NIL;
    }

    /// `cap_revoke`: apaga os descendentes de `h` numa fatia de no máximo
    /// `max(budget, MAX_DERIVATION_DEPTH + 1)` passos (descer um nível ou
    /// apagar uma folha). Toda fatia apaga ao menos uma capability, então a
    /// revogação sempre termina. O alvo continua vivo.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`] para `h` inválido; [`Error::Busy`] se outra
    /// revogação estiver em andamento neste `CapSpace`.
    pub fn revoke(&mut self, h: Handle, budget: u32) -> Result<Revoke, Error> {
        let target = self.index_of(h)?;
        match self.revoking {
            Some(r) if r != target => return Err(Error::Busy),
            _ => self.revoking = Some(target),
        }
        let (mut work, mut freed) = (0, 0);
        let mut node = target;
        loop {
            loop {
                let first = self.slot(node).first_child;
                if first == NIL {
                    break;
                }
                node = first;
                work += 1;
            }
            if node == target {
                self.revoking = None;
                return Ok(Revoke::Done);
            }
            if freed > 0 && work >= budget {
                return Ok(Revoke::Continue);
            }
            let parent = self.slot(node).parent;
            self.unlink_lifting_children(node);
            // A capability (e o objeto, se era a última) morre aqui.
            drop(self.release(node));
            work += 1;
            freed += 1;
            node = parent;
        }
    }

    /// Handle do alvo da revogação em andamento, se houver.
    #[must_use]
    pub fn revoking(&self) -> Option<Handle> {
        self.revoking.map(|i| self.handle(i))
    }

    /// Profundidade de `h` na árvore de derivação (raiz = 0).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`] para `h` inválido.
    pub fn depth(&self, h: Handle) -> Result<u32, Error> {
        let mut node = self.index_of(h)?;
        let mut depth = 0;
        while self.slot(node).parent != NIL {
            node = self.slot(node).parent;
            depth += 1;
        }
        Ok(depth)
    }

    /// Handle do pai de `h` na árvore de derivação (`None` numa raiz).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidHandle`] para `h` inválido.
    pub fn parent(&self, h: Handle) -> Result<Option<Handle>, Error> {
        let parent = self.slot(self.index_of(h)?).parent;
        Ok((parent != NIL).then(|| self.handle(parent)))
    }

    /// Confere os invariantes da spec `CapRevoke.tla` e os elos da árvore
    /// (diagnóstico para testes; custa O(slots × profundidade)).
    ///
    /// # Errors
    ///
    /// O invariante violado.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        let mut live = 0;
        for index in 1..self.fresh {
            let slot = self.slot(index);
            let Some(cap) = &slot.cap else {
                if slot.parent != NIL || slot.first_child != NIL {
                    return Err("ParentValid: slot livre com elos");
                }
                continue;
            };
            live += 1;
            let mut children = 0;
            let (mut child, mut prev) = (slot.first_child, NIL);
            while child != NIL {
                let c = self.slot(child);
                if c.parent != index || c.prev != prev || c.cap.is_none() {
                    return Err("elos de filhos inconsistentes");
                }
                (prev, child) = (child, c.next);
                children += 1;
                if children > self.live {
                    return Err("lista de filhos em ciclo");
                }
            }
            if slot.parent == NIL {
                if slot.next != NIL || slot.prev != NIL {
                    return Err("raiz em lista de irmãos");
                }
                continue;
            }
            let Some(parent) = &self.slot(slot.parent).cap else {
                return Err("ParentValid: pai livre");
            };
            if !parent.rights.contains(cap.rights) {
                return Err("MintMonotonic: filho com direito que o pai não tem");
            }
            if !parent.object.same(&cap.object) {
                return Err("filho aponta para outro objeto");
            }
            let (mut node, mut depth) = (slot.parent, 1);
            while node != NIL {
                if node == index {
                    return Err("Acyclic: ciclo de pais");
                }
                if depth >= MAX_DERIVATION_DEPTH {
                    return Err("profundidade acima do limite");
                }
                node = self.slot(node).parent;
                depth += 1;
            }
        }
        if live != self.live {
            return Err("contagem de capabilities vivas errada");
        }
        if self.revoking.is_some_and(|r| self.slot(r).cap.is_none()) {
            return Err("alvo da revogação livre");
        }
        Ok(())
    }
}
