//! Cache de blocos do `OptFS` (T-521; ADR 0056, item 7) sobre qualquer
//! [`BlockIo`]: lê do `obcache` quando pode, grava direto no dispositivo
//! (write-through, então a ordem escrita → `flush` → superbloco da ADR 0052
//! não muda) e guarda o que passou. O bloco no cache é o que está no disco
//! ou o que acabou de ser gravado, sempre em texto claro (o `OptFS` cifra
//! antes de chegar aqui, então o que passa por este `BlockIo` já é o texto
//! do disco; a decifra fica no `Tx`).

use crate::io::{BlockIo, IoError};
use obcache::BlockCache;
use optfs_format::BLOCK_SIZE;

/// `BlockIo` com cache LRU limitado pela cota do `optfs`.
pub struct CachedIo<IO> {
    inner: IO,
    cache: BlockCache,
}

impl<IO: BlockIo> CachedIo<IO> {
    /// Envolve `inner` com um cache de até `quota_bytes`.
    #[must_use]
    pub fn new(inner: IO, quota_bytes: usize) -> Self {
        Self {
            inner,
            cache: BlockCache::with_quota(quota_bytes),
        }
    }

    /// O cache, para ver contadores ou aplicar pressão (`trim`).
    pub fn cache_mut(&mut self) -> &mut BlockCache {
        &mut self.cache
    }

    /// O dispositivo de baixo.
    pub fn into_inner(self) -> IO {
        self.inner
    }
}

impl<IO: BlockIo> BlockIo for CachedIo<IO> {
    fn blocks(&self) -> u64 {
        self.inner.blocks()
    }

    fn read(&mut self, block: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), IoError> {
        if let Some(b) = self.cache.get(block) {
            buf.copy_from_slice(b);
            return Ok(());
        }
        self.inner.read(block, buf)?;
        self.cache.insert(block, buf);
        Ok(())
    }

    fn write(&mut self, block: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), IoError> {
        // Com erro o conteúdo do disco é incerto: sai do cache.
        if let Err(e) = self.inner.write(block, buf) {
            self.cache.invalidate(block);
            return Err(e);
        }
        self.cache.insert(block, buf);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        self.inner.flush()
    }
}
