//! Árvore de derivação entre `CapSpace`s (ADR 0028).
//!
//! `cap_mint`, `cap_delete`, `cap_revoke` e a transferência por IPC passam
//! por aqui: tomam a trava global [`CDT`], que vem antes de todas as outras
//! (`CDT → CapSpace → objeto → AddressSpace → fila`), e com ela tocam um
//! `CapSpace` por vez. Como todo elo, local ou remoto, só muda com a `CDT`
//! na mão, o que uma tabela diz sobre a outra não muda entre duas travas;
//! só uma tabela que morreu (sem a `CDT`) deixa elos vencidos, e esses são
//! reconhecidos pela geração e descartados.
//!
//! Um nó da árvore é um slot de um `CapSpace` ([`Node`]). O pai de um nó é
//! o pai local, se houver, ou o remoto; os filhos são os locais e depois os
//! remotos. As capabilities soltas morrem com a `CDT` na mão (nenhum
//! destrutor a toma).

#![forbid(unsafe_code)]

use alloc::sync::Arc;

use kabi::{Badge, Error, Handle, Rights};

use super::space::{MAX_DERIVATION_DEPTH, Revoke, Walk, XRef};
use super::{Cap, SharedCapSpace};
use crate::sync::SpinLock;

/// Trava global da árvore de derivação.
pub static CDT: SpinLock<()> = SpinLock::new(());

/// Um nó da árvore: o slot `index` de `space`.
#[derive(Clone)]
struct Node {
    space: Arc<SharedCapSpace>,
    index: u32,
}

/// O nó do outro lado de `x`, se o elo ainda vale.
fn resolve(x: &XRef) -> Option<Node> {
    let space = x.space()?;
    let ok = space.lock().holds(x.index(), x.generation());
    ok.then_some(Node {
        space,
        index: x.index(),
    })
}

/// Pai de `n`: o local, o remoto (se o elo vale) ou nenhum.
fn parent(n: &Node) -> Option<Node> {
    let (local, remote) = {
        let s = n.space.lock();
        (s.local_parent(n.index), s.xparent(n.index))
    };
    match local {
        Some(index) => Some(Node {
            space: Arc::clone(&n.space),
            index,
        }),
        None => remote.as_ref().and_then(resolve),
    }
}

/// Primeiro filho de `n` (local, ou o primeiro remoto que ainda vale,
/// descartando os vencidos).
fn first_child(n: &Node) -> Option<Node> {
    loop {
        let (local, remote) = {
            let s = n.space.lock();
            (s.first_local_child(n.index), s.first_xchild(n.index))
        };
        if let Some(index) = local {
            return Some(Node {
                space: Arc::clone(&n.space),
                index,
            });
        }
        let x = remote?;
        if let Some(child) = resolve(&x) {
            return Some(child);
        }
        n.space.lock().drop_first_xchild(n.index, &x);
    }
}

/// `Busy` se `n` ou um ancestral for alvo de revogação; `InvalidArgument`
/// se um filho de `n` passaria de [`MAX_DERIVATION_DEPTH`].
fn check_parent(n: &Node) -> Result<(), Error> {
    let mut node = n.clone();
    let mut depth = 0;
    loop {
        if node.space.lock().is_revoking(node.index) {
            return Err(Error::Busy);
        }
        let Some(up) = parent(&node) else { break };
        node = up;
        depth += 1;
        if depth >= MAX_DERIVATION_DEPTH {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}

/// Libera o nó `n`, já sem filhos, e o tira do pai remoto; devolve o pai
/// e a capability (para quem chama destruí-la).
fn free(n: &Node) -> (Option<Node>, Option<Cap>) {
    let up = parent(n);
    let (generation, remote) = {
        let s = n.space.lock();
        let remote = s.local_parent(n.index).is_none();
        (s.generation_of(n.index), remote)
    };
    let cap = n.space.lock().free_leaf(n.index);
    if remote && let Some(p) = &up {
        p.space
            .lock()
            .remove_xchild(p.index, &n.space, n.index, generation);
    }
    (up, cap)
}

/// Libera, de `n` para cima, os marcadores que ficaram sem filhos.
fn reap(mut n: Option<Node>) {
    while let Some(node) = n {
        let tomb = {
            let s = node.space.lock();
            s.holds(node.index, s.generation_of(node.index)) && s.is_tomb(node.index)
        };
        // `first_child` descarta os filhos remotos vencidos; um filho que
        // vale mantém o marcador.
        if !tomb || first_child(&node).is_some() {
            return;
        }
        let (up, cap) = free(&node);
        debug_assert!(cap.is_none());
        n = up;
    }
}

/// `cap_mint` através das tabelas: como [`CapSpace::mint`](super::CapSpace::mint),
/// conferindo também os ancestrais remotos (revogação e profundidade).
///
/// # Errors
///
/// Os de `CapSpace::mint`.
pub fn mint(
    space: &Arc<SharedCapSpace>,
    src: Handle,
    mask: Rights,
    badge: Option<Badge>,
) -> Result<Handle, Error> {
    let _cdt = CDT.lock();
    let index = space.lock().index(src)?;
    check_parent(&Node {
        space: Arc::clone(space),
        index,
    })?;
    space.lock().mint(src, mask, badge)
}

/// `cap_delete` através das tabelas. Uma capability com descendentes
/// remotos (ou uma cópia remota com filhos) vira marcador; uma cópia
/// remota sem filhos sai da lista do pai; as demais, como em
/// [`CapSpace::delete`](super::CapSpace::delete). O pai que ficar marcador
/// sem filhos é liberado.
///
/// # Errors
///
/// Os de `CapSpace::delete`.
pub fn delete(space: &Arc<SharedCapSpace>, h: Handle) -> Result<(), Error> {
    let _cdt = CDT.lock();
    let n = Node {
        space: Arc::clone(space),
        index: space.lock().index(h)?,
    };
    let up = parent(&n);
    let mut s = space.lock();
    if s.revoking() == Some(h) {
        return Err(Error::Busy);
    }
    let (cap, reap_from) = if !s.has_xlinks(n.index) {
        (s.delete(h)?, up)
    } else if s.has_children(n.index) {
        // Os filhos remotos podem estar todos vencidos: `reap` confere.
        (s.entomb(n.index).ok_or(Error::InvalidHandle)?, Some(n))
    } else {
        drop(s);
        let (_, cap) = free(&n);
        drop(cap);
        reap(up);
        return Ok(());
    };
    drop(s);
    drop(cap);
    reap(reap_from);
    Ok(())
}

/// `cap_revoke` através das tabelas: apaga os descendentes de `h`, locais
/// e remotos, numa fatia de no máximo `max(budget, MAX_DERIVATION_DEPTH +
/// 1)` passos, recomeçando do alvo a cada fatia como
/// [`CapSpace::revoke`](super::CapSpace::revoke). Um descendente que era
/// alvo de outra revogação é apagado e encerra aquela revogação.
///
/// # Errors
///
/// [`Error::InvalidHandle`] para `h` inválido; [`Error::Busy`] se outra
/// revogação estiver em andamento neste `CapSpace`.
pub fn revoke(space: &Arc<SharedCapSpace>, h: Handle, budget: u32) -> Result<Revoke, Error> {
    let _cdt = CDT.lock();
    let target = space.lock().start_revoke(h)?;
    let (mut work, mut freed) = (0, 0);
    let mut node = Node {
        space: Arc::clone(space),
        index: target,
    };
    loop {
        // Dentro de um `CapSpace`, com uma trava só, como na revogação
        // local; as capabilities morrem com a trava na mão, como lá.
        let mine = Arc::ptr_eq(&node.space, space).then_some(target);
        let walk =
            node.space
                .lock()
                .revoke_walk(&mut node.index, mine, &mut work, &mut freed, budget);
        node = match walk {
            Walk::Done => return Ok(Revoke::Done),
            Walk::Continue => return Ok(Revoke::Continue),
            Walk::Down(x) => {
                work += 1;
                resolve(&x).unwrap_or_else(|| {
                    node.space.lock().drop_first_xchild(node.index, &x);
                    node
                })
            }
            Walk::Up(xparent, generation) => {
                drop(node.space.lock().free_leaf(node.index));
                let up = xparent.as_ref().and_then(resolve);
                if let Some(p) = &up {
                    let mut ps = p.space.lock();
                    ps.remove_xchild(p.index, &node.space, node.index, generation);
                }
                // O pai existe: o nó descende do alvo, que segue vivo.
                up.unwrap_or(Node {
                    space: Arc::clone(space),
                    index: target,
                })
            }
        };
    }
}

/// Transferência por IPC (ADR 0028): cópia de `src` (no `CapSpace`
/// `from`), com os mesmos direitos e badge, como filha dela, em `to`.
/// Na mesma tabela, é um `cap_mint` sem redução.
///
/// # Errors
///
/// Os de [`mint_into`].
pub fn transfer(
    from: &Arc<SharedCapSpace>,
    src: Handle,
    to: &Arc<SharedCapSpace>,
) -> Result<Handle, Error> {
    mint_into(from, src, Rights::ALL, None, to)
}

/// `cap_mint` para outro `CapSpace` (ADR 0029): cópia de `src` (no
/// `CapSpace` `from`) com os direitos reduzidos por `mask` e, se a
/// original não tiver badge, `badge`, em `to`, como filha remota dela
/// (ADR 0028): revogar a original apaga a cópia. Na mesma tabela, é
/// [`mint`].
///
/// # Errors
///
/// [`Error::InvalidHandle`] se `src` não vale mais; [`Error::Busy`] e
/// [`Error::InvalidArgument`] como em [`mint`]; [`Error::AccessDenied`]
/// para badge sobre capability que já tem um; [`Error::QuotaExceeded`]
/// sem slot em `to` ou cota para os elos.
pub fn mint_into(
    from: &Arc<SharedCapSpace>,
    src: Handle,
    mask: Rights,
    badge: Option<Badge>,
    to: &Arc<SharedCapSpace>,
) -> Result<Handle, Error> {
    let _cdt = CDT.lock();
    let (index, generation, cap) = {
        let s = from.lock();
        let index = s.index(src)?;
        let parent = s.get(src)?;
        let badge = match badge {
            Some(_) if parent.badge != 0 => return Err(Error::AccessDenied),
            Some(b) => b,
            None => parent.badge,
        };
        let cap = Cap {
            object: parent.object.clone(),
            rights: parent.rights.derive(mask),
            badge,
        };
        (index, s.generation_of(index), cap)
    };
    check_parent(&Node {
        space: Arc::clone(from),
        index,
    })?;
    if Arc::ptr_eq(from, to) {
        drop(cap);
        return from.lock().mint(src, mask, badge);
    }
    let (h, child) = {
        let mut t = to.lock();
        let h = t.insert(cap)?;
        let child = t.index(h)?;
        if let Err(e) = t.set_xparent(child, XRef::new(from, index, generation)) {
            drop(t.delete(h));
            return Err(e);
        }
        (h, XRef::new(to, child, h.generation()))
    };
    if let Err(e) = from.lock().add_xchild(index, child) {
        let cap = {
            let mut t = to.lock();
            let index = t.index(h)?;
            t.free_leaf(index)
        };
        drop(cap);
        return Err(e);
    }
    Ok(h)
}

#[cfg(test)]
mod tests;
