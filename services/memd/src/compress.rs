//! Memória comprimida do `memd` (T-364; ADR 0038, item 6).
//!
//! Cada região com compressão ligada tem um [`Store`]: a visão `RAW` do
//! objeto no espaço do `memd`, as páginas residentes em ordem de relógio e
//! as páginas despejadas, comprimidas com `olz4`.
//!
//! - **Despejo** ([`Store::evict_one`]): relógio com `AGE` (segunda chance
//!   para página acessada desde a última volta), depois `HIDE`, cópia da
//!   visão `RAW`, compressão; se couber em [`MAX_PACKED`] bytes e no limite
//!   da região, guarda e faz `DECOMMIT`; senão a página volta com `PUBLISH`.
//! - **Restauração** ([`Store::fault_in`]): `COMMIT` sem `PUBLISH` (página
//!   oculta, outra thread do processo não a vê meio preenchida),
//!   descompressão na visão `RAW`, conferência do hash (8 bytes de
//!   BLAKE3) e `PUBLISH`.
//!
//! Os blocos comprimidos ficam no heap do `memd` (cota dele), contados pela
//! classe de tamanho (512, 1024, 2048 ou 3072 bytes).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};

use ostd::kabi::Error;
use ostd::kabi::Handle;
use ostd::kabi::mem::{AGE, DECOMMIT, HIDE, PUBLISH};
use ostd::kabi::vm::{PAGE_SIZE, RAW, WRITE};
use ostd::mem;
use ostd::vm::{Mapping, SELF};

/// Maior bloco comprimido guardado; acima disso a página é incompressível.
pub const MAX_PACKED: usize = 3072;
/// Classes de tamanho do repositório.
pub const CLASSES: [usize; 4] = [512, 1024, 2048, 3072];
const PAGE: usize = at(PAGE_SIZE);

/// Contadores de uma região, para o relatório.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Páginas despejadas.
    pub evicted: u64,
    /// Páginas restauradas.
    pub restored: u64,
    /// Tentativas de despejo desistidas (incompressível ou sem espaço).
    pub incompressible: u64,
    /// Bytes originais das páginas comprimidas guardadas hoje.
    pub original_bytes: u64,
    /// Bytes de repositório (por classe) das páginas guardadas hoje.
    pub packed_bytes: u64,
    /// Soma das latências de restauração, em ns.
    pub restore_ns: u64,
    /// Páginas com hash diferente na restauração.
    pub corrupt: u64,
}

struct Packed {
    data: Box<[u8]>,
    hash: u64,
    class: usize,
}

/// Estado de compressão de uma região.
pub struct Store {
    raw: Mapping,
    packed: BTreeMap<u64, Packed>,
    resident: VecDeque<u64>,
    max: u64,
    /// Contadores.
    pub stats: Stats,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

fn hash8(page: &[u8]) -> u64 {
    let h = optcrypt::blake3::hash(page);
    u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
}

fn class_of(n: usize) -> usize {
    CLASSES
        .iter()
        .copied()
        .find(|&c| n <= c)
        .unwrap_or(MAX_PACKED)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "deslocamentos da região cabem em usize"
)]
const fn at(off: u64) -> usize {
    off as usize
}

impl Store {
    /// Mapeia a visão `RAW` dos `len` primeiros bytes de `object` em
    /// `raw_va` e limita o repositório da região a `max` bytes.
    ///
    /// # Errors
    ///
    /// Os de `vm_map` (`AccessDenied` sem `EVICT`...).
    pub fn new(object: Handle, raw_va: u64, len: u64, max: u64) -> Result<Self, Error> {
        Ok(Self {
            raw: Mapping::new(SELF, object, raw_va, len, WRITE | RAW)?,
            packed: BTreeMap::new(),
            resident: VecDeque::new(),
            max,
            stats: Stats::default(),
        })
    }

    /// Resolve a falta na página `off`: restaura se estiver comprimida,
    /// senão compromete zerada.
    ///
    /// # Errors
    ///
    /// Os de `mem_op` (`QuotaExceeded` pede um despejo antes) e
    /// `InvalidArgument` se o conteúdo restaurado não bate com o hash.
    pub fn fault_in(&mut self, object: Handle, off: u64) -> Result<(), Error> {
        let Some(p) = self.packed.remove(&off) else {
            mem::commit(object, off, PAGE_SIZE, true)?;
            self.resident.push_back(off);
            return Ok(());
        };
        let t0 = ostd::time::now_ns();
        if let Err(e) = mem::commit(object, off, PAGE_SIZE, false) {
            self.packed.insert(off, p);
            return Err(e);
        }
        let page = &mut self.raw.bytes_mut().ok_or(Error::AccessDenied)?[at(off)..at(off) + PAGE];
        let ok = olz4::decompress(&p.data, page) == Ok(PAGE) && hash8(page) == p.hash;
        self.stats.original_bytes -= PAGE_SIZE;
        self.stats.packed_bytes -= p.class as u64;
        if !ok {
            self.stats.corrupt += 1;
            let _ = mem::op(object, DECOMMIT, off, PAGE_SIZE, 0);
            return Err(Error::InvalidArgument);
        }
        mem::op(object, PUBLISH, off, PAGE_SIZE, 0)?;
        self.resident.push_back(off);
        self.stats.restored += 1;
        self.stats.restore_ns += ostd::time::now_ns().saturating_sub(t0);
        Ok(())
    }

    /// Despeja a página residente mais fria. `Ok(false)` se nenhuma pôde ser
    /// despejada.
    ///
    /// # Errors
    ///
    /// Os de `mem_op`.
    pub fn evict_one(&mut self, object: Handle) -> Result<bool, Error> {
        let mut buf = [0u8; olz4::max_compressed_len(PAGE)];
        for _ in 0..2 * self.resident.len() {
            let Some(off) = self.resident.pop_front() else {
                break;
            };
            if mem::op(object, AGE, off, PAGE_SIZE, 0)? & 1 != 0 {
                self.resident.push_back(off);
                continue;
            }
            mem::op(object, HIDE, off, PAGE_SIZE, 0)?;
            let page = &self.raw.bytes()[at(off)..at(off) + PAGE];
            let n = olz4::compress(page, &mut buf).map_err(|_| Error::InvalidArgument)?;
            let class = class_of(n);
            if n > MAX_PACKED || self.stats.packed_bytes + class as u64 > self.max {
                mem::op(object, PUBLISH, off, PAGE_SIZE, 0)?;
                self.resident.push_back(off);
                self.stats.incompressible += 1;
                continue;
            }
            let packed = Packed {
                data: Box::from(&buf[..n]),
                hash: hash8(page),
                class,
            };
            mem::op(object, DECOMMIT, off, PAGE_SIZE, 0)?;
            self.packed.insert(off, packed);
            self.stats.evicted += 1;
            self.stats.original_bytes += PAGE_SIZE;
            self.stats.packed_bytes += class as u64;
            return Ok(true);
        }
        Ok(false)
    }
}
