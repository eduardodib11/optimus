//! Arquivos e diretórios sobre a árvore (ADR 0052, item 3: árvore de
//! arquivos de um dataset). O M5 tem um dataset só.
//!
//! Itens da árvore: `(0, Inode, 0)` guarda o contador de objetos;
//! `(obj, Inode, 0)` o inode; `(dir, Dirent, hash(nome))` uma lista de
//! entradas que colidiram no hash; `(obj, Extent, pos)` o conteúdo, um
//! item por bloco de 4 KiB (ponteiro de dados) ou, em arquivo de até
//! 1 KiB, os próprios bytes. O hash do nome é um BLAKE3 com chave do
//! volume, truncado a 64 bits.

// Alvo de 64 bits apenas (x86_64): `u64` cabe em `usize`.
#![allow(clippy::cast_possible_truncation)]

use crate::io::{BlockIo, IoError};
use crate::tree::{MAX_VALUE, Tx};
use alloc::string::String;
use alloc::vec::Vec;
use optfs_format::{BLOCK_SIZE, BlockPtr, Key, KeyKind, Sha256};

/// Raiz do dataset: sempre o objeto 1.
pub const ROOT_DIR: u64 = 1;
const MAX_NAME: usize = 255;
const BS: u64 = BLOCK_SIZE as u64;

/// Erro das operações de arquivo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsError {
    /// Erro do armazenamento ou de integridade.
    Io(IoError),
    /// Nome inexistente.
    NotFound,
    /// Nome já existe.
    Exists,
    /// O objeto não é um diretório.
    NotDir,
    /// O objeto é um diretório.
    IsDir,
    /// Diretório não vazio.
    NotEmpty,
    /// Nome vazio, longo demais ou com `/` ou NUL.
    BadName,
}

impl From<IoError> for FsError {
    fn from(e: IoError) -> Self {
        Self::Io(e)
    }
}

/// Tipo de objeto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjKind {
    /// Arquivo regular.
    File = 1,
    /// Diretório.
    Dir = 2,
}

/// Inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inode {
    /// Tipo.
    pub kind: ObjKind,
    /// Tamanho em bytes (zero para diretório).
    pub size: u64,
}

/// Um dataset: a raiz da árvore de arquivos viva.
#[derive(Clone, Copy, Debug)]
pub struct Fs {
    /// Raiz da árvore (muda a cada operação; o chamador a leva ao
    /// superbloco no commit).
    pub root: BlockPtr,
    /// Chave do hash de nomes (ADR 0053: derivada por volume).
    pub name_key: [u8; 32],
}

fn key(object: u64, kind: KeyKind, offset: u64) -> Key {
    Key {
        object,
        kind,
        offset,
    }
}

fn enc_inode(i: &Inode) -> [u8; 9] {
    let mut b = [0u8; 9];
    b[0] = i.kind as u8;
    b[1..9].copy_from_slice(&i.size.to_le_bytes());
    b
}

fn dec_inode(b: &[u8]) -> Result<Inode, IoError> {
    let kind = match b.first() {
        Some(1) => ObjKind::File,
        Some(2) => ObjKind::Dir,
        _ => return Err(IoError::Integrity),
    };
    let size = u64::from_le_bytes(
        b.get(1..9)
            .ok_or(IoError::Integrity)?
            .try_into()
            .map_err(|_| IoError::Integrity)?,
    );
    Ok(Inode { kind, size })
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, IoError> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or(IoError::Integrity)?
            .try_into()
            .map_err(|_| IoError::Integrity)?,
    ))
}

/// Entradas de uma lista de colisão: `(objeto, tipo, nome)`.
fn dec_dirents(mut b: &[u8]) -> Result<Vec<(u64, ObjKind, String)>, IoError> {
    let mut v = Vec::new();
    while !b.is_empty() {
        let obj = u64_at(b, 0)?;
        let kind = match b.get(8) {
            Some(1) => ObjKind::File,
            Some(2) => ObjKind::Dir,
            _ => return Err(IoError::Integrity),
        };
        let n = usize::from(*b.get(9).ok_or(IoError::Integrity)?);
        let name = core::str::from_utf8(b.get(10..10 + n).ok_or(IoError::Integrity)?)
            .map_err(|_| IoError::Integrity)?;
        v.push((obj, kind, String::from(name)));
        b = &b[10 + n..];
    }
    Ok(v)
}

fn enc_dirents(v: &[(u64, ObjKind, String)]) -> Vec<u8> {
    let mut b = Vec::new();
    for (obj, kind, name) in v {
        b.extend_from_slice(&obj.to_le_bytes());
        b.push(*kind as u8);
        b.push(u8::try_from(name.len()).unwrap_or(0));
        b.extend_from_slice(name.as_bytes());
    }
    b
}

fn check_name(name: &str) -> Result<(), FsError> {
    if name.is_empty() || name.len() > MAX_NAME || name.contains(['/', '\0']) {
        return Err(FsError::BadName);
    }
    Ok(())
}

impl Fs {
    /// Cria um dataset vazio, só com o diretório raiz.
    ///
    /// # Errors
    /// Erros da árvore.
    pub fn create<IO: BlockIo, H: Sha256>(
        tx: &mut Tx<'_, IO, H>,
        name_key: [u8; 32],
    ) -> Result<Self, FsError> {
        let mut fs = Self {
            root: BlockPtr::null(),
            name_key,
        };
        fs.put(tx, key(0, KeyKind::Inode, 0), &(ROOT_DIR + 1).to_le_bytes())?;
        fs.put(
            tx,
            key(ROOT_DIR, KeyKind::Inode, 0),
            &enc_inode(&Inode {
                kind: ObjKind::Dir,
                size: 0,
            }),
        )?;
        Ok(fs)
    }

    fn put<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        k: Key,
        v: &[u8],
    ) -> Result<(), FsError> {
        self.root = tx.insert(&self.root, k, v)?;
        Ok(())
    }

    fn del<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        k: &Key,
    ) -> Result<(), FsError> {
        self.root = tx.remove(&self.root, k)?;
        Ok(())
    }

    /// Inode de `obj`.
    ///
    /// # Errors
    /// [`FsError::NotFound`] ou erro de integridade.
    pub fn stat<IO: BlockIo, H: Sha256>(
        &self,
        tx: &mut Tx<'_, IO, H>,
        obj: u64,
    ) -> Result<Inode, FsError> {
        let v = tx
            .get(&self.root, &key(obj, KeyKind::Inode, 0))?
            .ok_or(FsError::NotFound)?;
        Ok(dec_inode(&v)?)
    }

    fn name_hash(&self, name: &str) -> u64 {
        let mut h = optcrypt::blake3::Hasher::new_keyed(&self.name_key);
        h.update(name.as_bytes());
        let d = h.finalize();
        u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
    }

    fn dirents<IO: BlockIo, H: Sha256>(
        &self,
        tx: &mut Tx<'_, IO, H>,
        dir: u64,
        name: &str,
    ) -> Result<Vec<(u64, ObjKind, String)>, FsError> {
        match tx.get(&self.root, &key(dir, KeyKind::Dirent, self.name_hash(name)))? {
            Some(v) => Ok(dec_dirents(&v)?),
            None => Ok(Vec::new()),
        }
    }

    /// Procura `name` em `dir`.
    ///
    /// # Errors
    /// [`FsError::NotDir`] se `dir` não é diretório.
    pub fn lookup<IO: BlockIo, H: Sha256>(
        &self,
        tx: &mut Tx<'_, IO, H>,
        dir: u64,
        name: &str,
    ) -> Result<Option<(u64, ObjKind)>, FsError> {
        if self.stat(tx, dir)?.kind != ObjKind::Dir {
            return Err(FsError::NotDir);
        }
        Ok(self
            .dirents(tx, dir, name)?
            .into_iter()
            .find(|e| e.2 == name)
            .map(|e| (e.0, e.1)))
    }

    fn add<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        dir: u64,
        name: &str,
        kind: ObjKind,
    ) -> Result<u64, FsError> {
        check_name(name)?;
        if self.lookup(tx, dir, name)?.is_some() {
            return Err(FsError::Exists);
        }
        let cnt = key(0, KeyKind::Inode, 0);
        let obj = u64_at(&tx.get(&self.root, &cnt)?.ok_or(IoError::Integrity)?, 0)?;
        self.put(tx, cnt, &(obj + 1).to_le_bytes())?;
        self.put(
            tx,
            key(obj, KeyKind::Inode, 0),
            &enc_inode(&Inode { kind, size: 0 }),
        )?;
        let mut list = self.dirents(tx, dir, name)?;
        list.push((obj, kind, String::from(name)));
        let v = enc_dirents(&list);
        if v.len() > MAX_VALUE {
            return Err(FsError::BadName);
        }
        self.put(tx, key(dir, KeyKind::Dirent, self.name_hash(name)), &v)?;
        Ok(obj)
    }

    /// Cria um arquivo vazio.
    ///
    /// # Errors
    /// [`FsError::Exists`], [`FsError::BadName`], [`FsError::NotDir`].
    pub fn create_file<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        dir: u64,
        name: &str,
    ) -> Result<u64, FsError> {
        self.add(tx, dir, name, ObjKind::File)
    }

    /// Cria um diretório vazio.
    ///
    /// # Errors
    /// Como [`Fs::create_file`].
    pub fn mkdir<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        dir: u64,
        name: &str,
    ) -> Result<u64, FsError> {
        self.add(tx, dir, name, ObjKind::Dir)
    }

    /// Lista `dir`, em ordem de hash do nome.
    ///
    /// # Errors
    /// [`FsError::NotDir`].
    pub fn readdir<IO: BlockIo, H: Sha256>(
        &self,
        tx: &mut Tx<'_, IO, H>,
        dir: u64,
    ) -> Result<Vec<(String, u64, ObjKind)>, FsError> {
        if self.stat(tx, dir)?.kind != ObjKind::Dir {
            return Err(FsError::NotDir);
        }
        let mut out = Vec::new();
        let mut at = key(dir, KeyKind::Dirent, 0);
        while let Some((k, v)) = tx.first_ge(&self.root, &at)? {
            if k.object != dir || k.kind != KeyKind::Dirent {
                break;
            }
            out.extend(dec_dirents(&v)?.into_iter().map(|(o, kd, n)| (n, o, kd)));
            if k.offset == u64::MAX {
                break;
            }
            at = key(dir, KeyKind::Dirent, k.offset + 1);
        }
        Ok(out)
    }

    /// Lê até `len` bytes a partir de `off` (menos se o arquivo acaba antes).
    ///
    /// # Errors
    /// [`FsError::IsDir`], [`FsError::NotFound`] ou erro de integridade.
    pub fn read<IO: BlockIo, H: Sha256>(
        &self,
        tx: &mut Tx<'_, IO, H>,
        obj: u64,
        off: u64,
        len: usize,
    ) -> Result<Vec<u8>, FsError> {
        let ino = self.stat(tx, obj)?;
        if ino.kind == ObjKind::Dir {
            return Err(FsError::IsDir);
        }
        let end = ino.size.min(off.saturating_add(len as u64));
        let mut out = Vec::new();
        let mut pos = off;
        while pos < end {
            let chunk = self.chunk(tx, obj, pos / BS * BS, ino.size)?;
            let from = usize::try_from(pos % BS).unwrap_or(0);
            let take = usize::try_from(end - pos)
                .unwrap_or(usize::MAX)
                .min(BLOCK_SIZE - from);
            out.extend_from_slice(&chunk[from..from + take]);
            pos += take as u64;
        }
        Ok(out)
    }

    /// Conteúdo do bloco que começa em `start` (zeros onde não há item).
    fn chunk<IO: BlockIo, H: Sha256>(
        &self,
        tx: &mut Tx<'_, IO, H>,
        obj: u64,
        start: u64,
        size: u64,
    ) -> Result<[u8; BLOCK_SIZE], FsError> {
        let mut b = [0u8; BLOCK_SIZE];
        let Some(v) = tx.get(&self.root, &key(obj, KeyKind::Extent, start))? else {
            return Ok(b);
        };
        match v.first() {
            Some(0) if start == 0 && size as usize <= MAX_VALUE => {
                let n = v.len() - 1;
                b[..n].copy_from_slice(&v[1..]);
            }
            Some(1) => {
                let p = BlockPtr::decode(&v[1..]).map_err(|_| IoError::Integrity)?;
                b = tx.read_data(&p)?;
            }
            _ => return Err(IoError::Integrity.into()),
        }
        Ok(b)
    }

    /// Escreve `data` em `off`, estendendo o arquivo se preciso.
    ///
    /// # Errors
    /// [`FsError::IsDir`], [`FsError::NotFound`], erros de espaço e de
    /// integridade.
    pub fn write<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        obj: u64,
        off: u64,
        data: &[u8],
    ) -> Result<(), FsError> {
        let ino = self.stat(tx, obj)?;
        if ino.kind == ObjKind::Dir {
            return Err(FsError::IsDir);
        }
        if data.is_empty() {
            return Ok(());
        }
        let new_size = ino.size.max(
            off.checked_add(data.len() as u64)
                .ok_or(IoError::BadRequest)?,
        );
        if new_size as usize <= MAX_VALUE && new_size < BS {
            // Arquivo pequeno: os bytes ficam no próprio item.
            let mut b = self.chunk(tx, obj, 0, ino.size)?;
            let o = off as usize;
            b[o..o + data.len()].copy_from_slice(data);
            let mut v = Vec::with_capacity(1 + new_size as usize);
            v.push(0);
            v.extend_from_slice(&b[..new_size as usize]);
            self.put(tx, key(obj, KeyKind::Extent, 0), &v)?;
        } else {
            // Se estava embutido (até 1 KiB), o item 0 vira bloco de dados.
            if ino.size as usize <= MAX_VALUE {
                self.promote(tx, obj, ino.size)?;
            }
            let mut pos = off;
            let end = off + data.len() as u64;
            while pos < end {
                let start = pos / BS * BS;
                let mut b = self.chunk(tx, obj, start, new_size)?;
                let from = usize::try_from(pos - start).unwrap_or(0);
                let take = usize::try_from(end - pos)
                    .unwrap_or(usize::MAX)
                    .min(BLOCK_SIZE - from);
                b[from..from + take]
                    .copy_from_slice(&data[usize::try_from(pos - off).unwrap_or(0)..][..take]);
                self.old_data_free(tx, obj, start)?;
                let p = tx.write_data(&b)?;
                let mut v = alloc::vec![1u8];
                v.extend_from_slice(&p.encode());
                self.put(tx, key(obj, KeyKind::Extent, start), &v)?;
                pos = start + BS;
            }
        }
        self.put(
            tx,
            key(obj, KeyKind::Inode, 0),
            &enc_inode(&Inode {
                kind: ObjKind::File,
                size: new_size,
            }),
        )?;
        Ok(())
    }

    /// Transforma o conteúdo embutido em bloco de dados (bloco 0).
    fn promote<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        obj: u64,
        size: u64,
    ) -> Result<(), FsError> {
        if size == 0 {
            return Ok(());
        }
        let b = self.chunk(tx, obj, 0, size)?;
        let p = tx.write_data(&b)?;
        let mut v = alloc::vec![1u8];
        v.extend_from_slice(&p.encode());
        self.put(tx, key(obj, KeyKind::Extent, 0), &v)
    }

    /// Libera o bloco de dados antigo de `start`, se houver.
    fn old_data_free<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        obj: u64,
        start: u64,
    ) -> Result<(), FsError> {
        if let Some(v) = tx.get(&self.root, &key(obj, KeyKind::Extent, start))?
            && v.first() == Some(&1)
        {
            let p = BlockPtr::decode(&v[1..]).map_err(|_| IoError::Integrity)?;
            tx.free_ptr(&p);
        }
        Ok(())
    }

    /// Remove o arquivo ou diretório vazio `name` de `dir` e libera os
    /// blocos dele.
    ///
    /// # Errors
    /// [`FsError::NotFound`], [`FsError::NotEmpty`].
    pub fn unlink<IO: BlockIo, H: Sha256>(
        &mut self,
        tx: &mut Tx<'_, IO, H>,
        dir: u64,
        name: &str,
    ) -> Result<(), FsError> {
        let (obj, kind) = self.lookup(tx, dir, name)?.ok_or(FsError::NotFound)?;
        if kind == ObjKind::Dir && !self.readdir(tx, obj)?.is_empty() {
            return Err(FsError::NotEmpty);
        }
        let mut at = key(obj, KeyKind::Extent, 0);
        while let Some((k, v)) = tx.first_ge(&self.root, &at)? {
            if k.object != obj || k.kind != KeyKind::Extent {
                break;
            }
            if v.first() == Some(&1) {
                tx.free_ptr(&BlockPtr::decode(&v[1..]).map_err(|_| IoError::Integrity)?);
            }
            self.del(tx, &k)?;
            at = key(obj, KeyKind::Extent, k.offset + 1);
        }
        self.del(tx, &key(obj, KeyKind::Inode, 0))?;
        let mut list = self.dirents(tx, dir, name)?;
        list.retain(|e| e.2 != name);
        let hk = key(dir, KeyKind::Dirent, self.name_hash(name));
        if list.is_empty() {
            self.del(tx, &hk)?;
        } else {
            self.put(tx, hk, &enc_dirents(&list))?;
        }
        Ok(())
    }
}
