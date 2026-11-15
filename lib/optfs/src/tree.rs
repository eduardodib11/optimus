//! Árvore B+ copy-on-write (ADR 0052, item 3).
//!
//! Cada nó alterado é regravado num bloco novo; o bloco antigo é liberado
//! no txg corrente (ver [`Allocator`]). Os blocos novos ficam em memória
//! (`staged`) até o commit os gravar. No modo hash, todo filho é conferido
//! pelo SHA-256 guardado no ponteiro do pai antes de ser usado; falha vira
//! [`IoError::Integrity`], nunca dado.
//!
//! Esta etapa não funde nós quase vazios depois de remoções (só descarta
//! os vazios): é correto, só menos compacto.

use crate::alloc_map::Allocator;
use crate::io::{BlockIo, IoError};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use optfs_format::{
    BLOCK_SIZE, BlockPtr, Compression, Integrity, Key, NODE_HEADER_LEN, NodeHeader, PtrKind, Sha256,
};

/// Maior valor de uma folha (dados embutidos de até 1 KiB, ADR 0052).
pub const MAX_VALUE: usize = 1024;

enum Node {
    Leaf(Vec<(Key, Vec<u8>)>),
    Internal(Vec<(Key, BlockPtr)>),
}

impl Node {
    fn size(&self) -> usize {
        NODE_HEADER_LEN
            + match self {
                Node::Leaf(v) => v.iter().map(|(_, x)| Key::LEN + 2 + x.len()).sum::<usize>(),
                Node::Internal(v) => v.len() * (Key::LEN + 72),
            }
    }
    fn len(&self) -> usize {
        match self {
            Node::Leaf(v) => v.len(),
            Node::Internal(v) => v.len(),
        }
    }
    fn first_key(&self) -> Key {
        match self {
            Node::Leaf(v) => v[0].0,
            Node::Internal(v) => v[0].0,
        }
    }
}

/// Contexto de um txg: acesso ao disco, alocador e blocos ainda não gravados.
pub struct Tx<'a, IO: BlockIo, H: Sha256> {
    io: &'a mut IO,
    h: &'a H,
    alloc: &'a mut Allocator,
    /// Txg em andamento (o do commit que vem).
    pub txg: u64,
    tree: u64,
    staged: BTreeMap<u64, Box<[u8; BLOCK_SIZE]>>,
}

impl<'a, IO: BlockIo, H: Sha256> Tx<'a, IO, H> {
    /// Abre o txg `txg` para a árvore `tree`.
    pub fn new(io: &'a mut IO, h: &'a H, alloc: &'a mut Allocator, txg: u64, tree: u64) -> Self {
        Self {
            io,
            h,
            alloc,
            txg,
            tree,
            staged: BTreeMap::new(),
        }
    }

    /// Blocos novos para o commit.
    #[must_use]
    pub fn staged(&self) -> Vec<(u64, &[u8; BLOCK_SIZE])> {
        self.staged.iter().map(|(a, b)| (*a, &**b)).collect()
    }

    /// Confirma o txg: grava os blocos novos e o superbloco (ver
    /// [`crate::commit`]) e, só então, deixa o alocador reusar o que foi
    /// liberado até o txg anterior.
    ///
    /// # Errors
    /// Os de [`crate::commit`]; com erro, o txg não vale e o alocador não
    /// muda.
    pub fn commit(
        &mut self,
        prev: &optfs_format::Superblock,
        new: optfs_format::Superblock,
    ) -> Result<optfs_format::Superblock, IoError> {
        let blocks: Vec<(u64, &[u8; BLOCK_SIZE])> =
            self.staged.iter().map(|(a, b)| (*a, &**b)).collect();
        let sb = crate::txg::commit(self.io, self.h, prev, new, blocks)?;
        self.staged.clear();
        self.alloc.confirmed(self.txg);
        Ok(sb)
    }

    #[allow(clippy::many_single_char_names)]
    fn read(&mut self, p: &BlockPtr) -> Result<Node, IoError> {
        if p.kind != PtrKind::Node
            || p.integrity != Integrity::Hash
            || p.physical as usize != BLOCK_SIZE
        {
            return Err(IoError::Integrity);
        }
        let mut b = [0u8; BLOCK_SIZE];
        match self.staged.get(&p.addr) {
            Some(s) => b = **s,
            None => self.io.read(p.addr, &mut b)?,
        }
        if self.h.sha256(&b) != p.auth {
            return Err(IoError::Integrity);
        }
        let hd = NodeHeader::decode(&b).map_err(|_| IoError::Integrity)?;
        if hd.addr != p.addr || hd.level != p.level || hd.txg != p.birth || hd.tree != self.tree {
            return Err(IoError::Integrity);
        }
        let n = usize::from(hd.count);
        let mut at = NODE_HEADER_LEN;
        let bad = IoError::Integrity;
        if hd.level == 0 {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let k = Key::decode(b.get(at..at + Key::LEN).ok_or(bad)?).map_err(|_| bad)?;
                let l = usize::from(u16::from_le_bytes([
                    *b.get(at + 24).ok_or(bad)?,
                    *b.get(at + 25).ok_or(bad)?,
                ]));
                let val = b.get(at + 26..at + 26 + l).ok_or(bad)?;
                if l > MAX_VALUE || v.last().is_some_and(|(p, _): &(Key, Vec<u8>)| *p >= k) {
                    return Err(bad);
                }
                v.push((k, val.to_vec()));
                at += 26 + l;
            }
            Ok(Node::Leaf(v))
        } else {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let k = Key::decode(b.get(at..at + Key::LEN).ok_or(bad)?).map_err(|_| bad)?;
                let cp = BlockPtr::decode(b.get(at + 24..at + 96).ok_or(bad)?).map_err(|_| bad)?;
                if cp.level + 1 != hd.level
                    || v.last().is_some_and(|(p, _): &(Key, BlockPtr)| *p >= k)
                {
                    return Err(bad);
                }
                v.push((k, cp));
                at += 96;
            }
            if v.is_empty() {
                return Err(bad);
            }
            Ok(Node::Internal(v))
        }
    }

    #[allow(clippy::many_single_char_names, clippy::cast_possible_truncation)] // BLOCK_SIZE cabe em u32
    fn write(&mut self, node: &Node, level: u8) -> Result<BlockPtr, IoError> {
        if node.size() > BLOCK_SIZE {
            return Err(IoError::BadRequest);
        }
        let addr = self.alloc.alloc()?;
        let mut b = Box::new([0u8; BLOCK_SIZE]);
        let count = u16::try_from(node.len()).map_err(|_| IoError::BadRequest)?;
        let hd = NodeHeader {
            level,
            count,
            tree: self.tree,
            txg: self.txg,
            addr,
        };
        b[..NODE_HEADER_LEN].copy_from_slice(&hd.encode());
        let mut at = NODE_HEADER_LEN;
        match node {
            Node::Leaf(v) => {
                for (k, x) in v {
                    b[at..at + 24].copy_from_slice(&k.encode());
                    b[at + 24..at + 26]
                        .copy_from_slice(&u16::try_from(x.len()).unwrap_or(0).to_le_bytes());
                    b[at + 26..at + 26 + x.len()].copy_from_slice(x);
                    at += 26 + x.len();
                }
            }
            Node::Internal(v) => {
                for (k, p) in v {
                    b[at..at + 24].copy_from_slice(&k.encode());
                    b[at + 24..at + 96].copy_from_slice(&p.encode());
                    at += 96;
                }
            }
        }
        let auth = self.h.sha256(&*b);
        self.staged.insert(addr, b);
        Ok(BlockPtr {
            addr,
            birth: self.txg,
            logical: BLOCK_SIZE as u32,
            physical: BLOCK_SIZE as u32,
            level,
            kind: PtrKind::Node,
            compression: Compression::None,
            integrity: Integrity::Hash,
            nonce: [0; 12],
            auth,
        })
    }

    /// Grava um bloco de dados novo (ainda em memória até o commit).
    ///
    /// # Errors
    /// [`IoError::Full`] sem blocos livres.
    pub fn write_data(&mut self, data: &[u8; BLOCK_SIZE]) -> Result<BlockPtr, IoError> {
        let addr = self.alloc.alloc()?;
        let auth = self.h.sha256(data);
        self.staged.insert(addr, Box::new(*data));
        Ok(BlockPtr {
            addr,
            birth: self.txg,
            logical: 4096,
            physical: 4096,
            level: 0,
            kind: PtrKind::Data,
            compression: Compression::None,
            integrity: Integrity::Hash,
            nonce: [0; 12],
            auth,
        })
    }

    /// Lê um bloco de dados, conferido pelo hash do ponteiro.
    ///
    /// # Errors
    /// [`IoError::Integrity`] se o bloco não confere.
    pub fn read_data(&mut self, p: &BlockPtr) -> Result<[u8; BLOCK_SIZE], IoError> {
        if p.kind != PtrKind::Data || p.integrity != Integrity::Hash || p.physical != 4096 {
            return Err(IoError::Integrity);
        }
        let mut b = [0u8; BLOCK_SIZE];
        match self.staged.get(&p.addr) {
            Some(s) => b = **s,
            None => self.io.read(p.addr, &mut b)?,
        }
        if self.h.sha256(&b) != p.auth {
            return Err(IoError::Integrity);
        }
        Ok(b)
    }

    /// Depois da montagem, marca no alocador todo bloco que a árvore de
    /// arquivos alcança: nós e blocos de dados (itens `Extent` com tag 1).
    ///
    /// # Errors
    /// [`IoError::Integrity`] se algum nó não confere.
    pub fn mark_reachable(&mut self, root: &BlockPtr) -> Result<(), IoError> {
        if root.is_null() {
            return Ok(());
        }
        self.alloc.mark_used(root.addr);
        match self.read(root)? {
            Node::Internal(v) => {
                for (_, c) in &v {
                    self.mark_reachable(c)?;
                }
            }
            Node::Leaf(v) => {
                for (k, x) in &v {
                    if k.kind == optfs_format::KeyKind::Extent && x.first() == Some(&1) {
                        let p = BlockPtr::decode(&x[1..]).map_err(|_| IoError::Integrity)?;
                        self.alloc.mark_used(p.addr);
                    }
                }
            }
        }
        Ok(())
    }

    /// Blocos livres no alocador.
    #[must_use]
    pub fn free_blocks(&self) -> u64 {
        self.alloc.free_blocks()
    }

    /// Libera um bloco que a árvore deixou de usar (ver `release`).
    pub fn free_ptr(&mut self, p: &BlockPtr) {
        self.release(p);
    }

    fn release(&mut self, p: &BlockPtr) {
        if p.birth == self.txg && self.staged.remove(&p.addr).is_some() {
            // Nasceu neste txg e ainda não foi ao disco: nenhum superbloco
            // o alcança, então o bloco volta já.
            self.alloc.free_now(p.addr);
        } else {
            self.alloc.free(self.txg, p.addr);
        }
    }

    /// Valor de `key`.
    ///
    /// # Errors
    /// [`IoError::Integrity`] se algum nó do caminho não confere.
    pub fn get(&mut self, root: &BlockPtr, key: &Key) -> Result<Option<Vec<u8>>, IoError> {
        if root.is_null() {
            return Ok(None);
        }
        let mut p = *root;
        loop {
            match self.read(&p)? {
                Node::Leaf(v) => {
                    return Ok(v
                        .binary_search_by(|(k, _)| k.cmp(key))
                        .ok()
                        .map(|i| v[i].1.clone()));
                }
                Node::Internal(v) => p = v[child_index(&v, key)].1,
            }
        }
    }

    /// Menor chave maior ou igual a `key`, com o valor.
    ///
    /// # Errors
    /// [`IoError::Integrity`] se algum nó visitado não confere.
    pub fn first_ge(
        &mut self,
        root: &BlockPtr,
        key: &Key,
    ) -> Result<Option<(Key, Vec<u8>)>, IoError> {
        if root.is_null() {
            return Ok(None);
        }
        self.first_ge_in(root, key)
    }

    fn first_ge_in(&mut self, p: &BlockPtr, key: &Key) -> Result<Option<(Key, Vec<u8>)>, IoError> {
        match self.read(p)? {
            Node::Leaf(v) => Ok(v.into_iter().find(|(k, _)| k >= key)),
            Node::Internal(v) => {
                for (_, child) in &v[child_index(&v, key)..] {
                    if let Some(r) = self.first_ge_in(child, key)? {
                        return Ok(Some(r));
                    }
                }
                Ok(None)
            }
        }
    }

    /// Insere ou troca `key`. Devolve a nova raiz.
    ///
    /// # Errors
    /// [`IoError::BadRequest`] se o valor passa de [`MAX_VALUE`];
    /// [`IoError::Full`] sem blocos livres; [`IoError::Integrity`].
    pub fn insert(&mut self, root: &BlockPtr, key: Key, val: &[u8]) -> Result<BlockPtr, IoError> {
        if val.len() > MAX_VALUE {
            return Err(IoError::BadRequest);
        }
        if root.is_null() {
            return self.write(&Node::Leaf(alloc::vec![(key, val.to_vec())]), 0);
        }
        let parts = self.insert_in(root, key, val)?;
        self.join(parts, root.level)
    }

    /// Une as partes devolvidas por um nó numa raiz (nova se houve divisão).
    fn join(&mut self, mut parts: Vec<(Key, BlockPtr)>, level: u8) -> Result<BlockPtr, IoError> {
        match parts.len() {
            0 => Ok(BlockPtr::null()),
            1 => Ok(parts.remove(0).1),
            _ => self.write(&Node::Internal(parts), level + 1),
        }
    }

    fn insert_in(
        &mut self,
        p: &BlockPtr,
        key: Key,
        val: &[u8],
    ) -> Result<Vec<(Key, BlockPtr)>, IoError> {
        let node = match self.read(p)? {
            Node::Leaf(mut v) => {
                match v.binary_search_by(|(k, _)| k.cmp(&key)) {
                    Ok(i) => v[i].1 = val.to_vec(),
                    Err(i) => v.insert(i, (key, val.to_vec())),
                }
                Node::Leaf(v)
            }
            Node::Internal(mut v) => {
                let i = child_index(&v, &key);
                let parts = self.insert_in(&v[i].1, key, val)?;
                v.splice(i..=i, parts);
                Node::Internal(v)
            }
        };
        self.release(p);
        self.emit(node, p.level)
    }

    /// Grava o nó, dividindo-o ao meio se não cabe num bloco.
    fn emit(&mut self, node: Node, level: u8) -> Result<Vec<(Key, BlockPtr)>, IoError> {
        if node.len() == 0 {
            return Ok(Vec::new());
        }
        if node.size() <= BLOCK_SIZE {
            let k = node.first_key();
            return Ok(alloc::vec![(k, self.write(&node, level)?)]);
        }
        let (a, b) = match node {
            Node::Leaf(mut v) => {
                let r = v.split_off(v.len() / 2);
                (Node::Leaf(v), Node::Leaf(r))
            }
            Node::Internal(mut v) => {
                let r = v.split_off(v.len() / 2);
                (Node::Internal(v), Node::Internal(r))
            }
        };
        let mut out = Vec::new();
        for half in [a, b] {
            out.extend(self.emit(half, level)?);
        }
        Ok(out)
    }

    /// Remove `key` (nada acontece se não existe). Devolve a nova raiz,
    /// nula se a árvore ficou vazia.
    ///
    /// # Errors
    /// [`IoError::Integrity`] ou [`IoError::Full`].
    pub fn remove(&mut self, root: &BlockPtr, key: &Key) -> Result<BlockPtr, IoError> {
        if root.is_null() || self.get(root, key)?.is_none() {
            return Ok(*root);
        }
        let parts = self.remove_in(root, key)?;
        let mut r = self.join(parts, root.level)?;
        // Raiz interna com um filho só: sobe o filho.
        while !r.is_null() && r.level > 0 {
            let Node::Internal(v) = self.read(&r)? else {
                break;
            };
            if v.len() != 1 {
                break;
            }
            self.release(&r);
            r = v[0].1;
        }
        Ok(r)
    }

    fn remove_in(&mut self, p: &BlockPtr, key: &Key) -> Result<Vec<(Key, BlockPtr)>, IoError> {
        let node = match self.read(p)? {
            Node::Leaf(mut v) => {
                if let Ok(i) = v.binary_search_by(|(k, _)| k.cmp(key)) {
                    v.remove(i);
                }
                Node::Leaf(v)
            }
            Node::Internal(mut v) => {
                let i = child_index(&v, key);
                let parts = self.remove_in(&v[i].1, key)?;
                v.splice(i..=i, parts);
                Node::Internal(v)
            }
        };
        self.release(p);
        self.emit(node, p.level)
    }
}

/// Filho que cobre `key`: o último com chave `<= key`, ou o primeiro.
fn child_index(v: &[(Key, BlockPtr)], key: &Key) -> usize {
    v.partition_point(|(k, _)| k <= key).saturating_sub(1)
}
