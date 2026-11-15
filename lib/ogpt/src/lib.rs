//! `ogpt`: leitura da tabela de partições GPT (ADR 0056, item 11; T-520).
//!
//! O disco é dado não confiável. O parser confere o CRC32 do cabeçalho e da
//! tabela, tenta a cópia primária (LBA 1) e depois a de reserva (último
//! LBA), recusa partições sobrepostas, fora da área utilizável ou
//! invertidas, e nunca entra em pânico nem aloca. Com as duas cópias
//! inválidas devolve erro: o disco não expõe partições.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// Máximo de partições lidas (o padrão da UEFI reserva 128 entradas).
pub const MAX_PARTS: usize = 128;
const ENTRY_LEN: usize = 128;
const HEADER_LEN: usize = 92;

/// Acesso de leitura ao disco, em setores de 512 ou 4096 bytes.
pub trait Disk {
    /// Bytes por setor (512 ou 4096).
    fn sector_size(&self) -> usize;
    /// Total de setores.
    fn sectors(&self) -> u64;
    /// Lê o setor `lba` em `buf` (do tamanho de um setor). `false` em erro.
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool;
}

/// Motivo de o disco não expor partições.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Setor de tamanho não suportado ou disco pequeno demais.
    BadDisk,
    /// Erro de leitura.
    Io,
    /// As duas cópias do cabeçalho ou da tabela são inválidas.
    NoValidCopy,
}

/// Uma partição.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Part {
    /// GUID de tipo (formato de disco, misto-endian).
    pub type_guid: [u8; 16],
    /// GUID único.
    pub guid: [u8; 16],
    /// Primeiro setor.
    pub first: u64,
    /// Último setor (inclusive).
    pub last: u64,
    /// Atributos.
    pub attrs: u64,
    /// Nome em UTF-16LE, com zeros no fim.
    pub name: [u16; 36],
}

impl Part {
    /// Se o nome é igual a `s` (só ASCII é comparado como tal).
    #[must_use]
    pub fn name_is(&self, s: &str) -> bool {
        let n = self.name.iter().position(|c| *c == 0).unwrap_or(36);
        let mut it = s.chars();
        for c in &self.name[..n] {
            match it.next() {
                Some(x) if u32::from(*c) == x as u32 => {}
                _ => return false,
            }
        }
        it.next().is_none()
    }

    /// Setores da partição.
    #[must_use]
    pub fn sectors(&self) -> u64 {
        self.last - self.first + 1
    }

    /// Se a partição começa alinhada a 4 KiB (a ADR 0056 recusa as demais).
    #[must_use]
    pub fn aligned_4k(&self, sector_size: usize) -> bool {
        (self.first.saturating_mul(sector_size as u64)).is_multiple_of(4096)
    }
}

/// Tabela lida: as partições em uso, ordenadas pela posição na tabela.
#[derive(Clone, Debug)]
pub struct Table {
    /// GUID do disco.
    pub disk_guid: [u8; 16],
    parts: [Option<Part>; MAX_PARTS],
    /// Quantidade de partições.
    pub len: usize,
}

impl Table {
    /// As partições em uso.
    pub fn parts(&self) -> impl Iterator<Item = &Part> {
        self.parts.iter().flatten()
    }
}

/// CRC32 (IEEE, o da GPT), incremental.
struct Crc(u32);
impl Crc {
    fn new() -> Self {
        Self(!0)
    }
    fn update(&mut self, data: &[u8]) {
        for b in data {
            self.0 ^= u32::from(*b);
            for _ in 0..8 {
                self.0 = (self.0 >> 1) ^ (0xEDB8_8320 & 0u32.wrapping_sub(self.0 & 1));
            }
        }
    }
    fn finish(&self) -> u32 {
        !self.0
    }
}

/// CRC32 de `data`.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc::new();
    c.update(data);
    c.finish()
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4]))
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}

impl Table {
    /// Tabela vazia, para [`parse_into`].
    #[must_use]
    #[allow(clippy::large_stack_arrays)] // 17 KiB: o chamador escolhe onde fica
    pub const fn empty() -> Self {
        Self {
            disk_guid: [0; 16],
            parts: [None; MAX_PARTS],
            len: 0,
        }
    }
}

/// Lê a tabela do disco: cópia primária, depois a de reserva.
///
/// # Errors
/// [`Error::BadDisk`], [`Error::Io`] ou [`Error::NoValidCopy`].
pub fn parse(disk: &mut impl Disk) -> Result<Table, Error> {
    let mut table = Table::empty();
    parse_into(disk, &mut table)?;
    Ok(table)
}

/// Como [`parse`], mas escreve em `table`, que o chamador guarda onde a
/// pilha for pequena (a tabela passa de 17 KiB). Com erro, `table` fica
/// vazia.
///
/// # Errors
/// [`Error::BadDisk`], [`Error::Io`] ou [`Error::NoValidCopy`].
pub fn parse_into(disk: &mut impl Disk, table: &mut Table) -> Result<(), Error> {
    let ss = disk.sector_size();
    let total = disk.sectors();
    if (ss != 512 && ss != 4096) || total < 6 {
        return Err(Error::BadDisk);
    }
    let mut io_err = false;
    for lba in [1, total - 1] {
        match read_copy(disk, lba, ss, total, table) {
            Ok(()) => return Ok(()),
            Err(Error::Io) => io_err = true,
            Err(_) => {}
        }
    }
    clear(table);
    Err(if io_err {
        Error::Io
    } else {
        Error::NoValidCopy
    })
}

fn clear(table: &mut Table) {
    for p in &mut table.parts {
        *p = None;
    }
    table.len = 0;
}

#[allow(clippy::large_stack_arrays)] // 17 KiB, cabe na pilha de usuário
fn read_copy(
    disk: &mut impl Disk,
    lba: u64,
    ss: usize,
    total: u64,
    table: &mut Table,
) -> Result<(), Error> {
    clear(table);
    let mut sec = [0u8; 4096];
    let sec = &mut sec[..ss];
    if !disk.read(lba, sec) {
        return Err(Error::Io);
    }
    let h = &sec[..HEADER_LEN];
    let bad = Err(Error::NoValidCopy);
    if &h[0..8] != b"EFI PART" || u32le(h, 8) != 0x0001_0000 || u32le(h, 12) != 92 {
        return bad;
    }
    let mut hc = [0u8; HEADER_LEN];
    hc.copy_from_slice(h);
    hc[16..20].fill(0);
    if crc32(&hc) != u32le(h, 16) || u32le(h, 20) != 0 || u64le(h, 24) != lba {
        return bad;
    }
    let (first_usable, last_usable) = (u64le(h, 40), u64le(h, 48));
    let (entries_lba, count, size) = (u64le(h, 72), u32le(h, 80) as usize, u32le(h, 84) as usize);
    if size != ENTRY_LEN || count == 0 || count > MAX_PARTS {
        return bad;
    }
    if first_usable < 2 || last_usable >= total || first_usable > last_usable {
        return bad;
    }
    let bytes = count * size;
    let nsec = bytes.div_ceil(ss) as u64;
    // A tabela não pode invadir a área utilizável nem sair do disco.
    let end = entries_lba.checked_add(nsec).ok_or(Error::NoValidCopy)?;
    let ok_place =
        entries_lba >= 2 && end <= total && (end <= first_usable || entries_lba > last_usable);
    if !ok_place {
        return bad;
    }
    table.disk_guid = h[56..72].try_into().map_err(|_| Error::NoValidCopy)?;
    let want_crc = u32le(h, 88);
    let mut crc = Crc::new();
    let mut done = 0;
    for i in 0..nsec {
        if !disk.read(entries_lba + i, sec) {
            return Err(Error::Io);
        }
        let take = (bytes - done).min(ss);
        crc.update(&sec[..take]);
        for e in sec[..take].chunks_exact(ENTRY_LEN) {
            if e[..16].iter().all(|b| *b == 0) {
                continue;
            }
            let (first, last) = (u64le(e, 32), u64le(e, 40));
            if first > last || first < first_usable || last > last_usable {
                return bad;
            }
            let mut name = [0u16; 36];
            for (n, c) in name.iter_mut().zip(e[56..128].chunks_exact(2)) {
                *n = u16::from_le_bytes([c[0], c[1]]);
            }
            table.parts[table.len] = Some(Part {
                type_guid: e[..16].try_into().map_err(|_| Error::NoValidCopy)?,
                guid: e[16..32].try_into().map_err(|_| Error::NoValidCopy)?,
                first,
                last,
                attrs: u64le(e, 48),
                name,
            });
            table.len += 1;
        }
        done += take;
    }
    if crc.finish() != want_crc {
        return bad;
    }
    // Sobreposição: quadrático, mas são no máximo 128 entradas.
    let used = &table.parts[..table.len];
    for (i, a) in used.iter().flatten().enumerate() {
        if used
            .iter()
            .flatten()
            .skip(i + 1)
            .any(|b| a.first <= b.last && b.first <= a.last)
        {
            return bad;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
