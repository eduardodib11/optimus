//! `oelf`: validação e leitura de executáveis ELF64 x86-64 (SDD v1.0, seção 5).
//!
//! Sem alocação e sem `unsafe`. [`Elf::parse`] valida o arquivo inteiro de uma
//! vez; depois disso, [`Elf::segments`] só entrega segmentos `PT_LOAD` que já
//! passaram por todas as checagens. Entrada maliciosa vira [`Error`], nunca pânico.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use core::fmt;

/// Tamanho de página assumido para alinhamento e sobreposição de segmentos.
pub const PAGE_SIZE: u64 = 4096;
/// Primeiro endereço canônico da metade alta (x86-64, 48 bits).
pub const HIGHER_HALF: u64 = 0xffff_8000_0000_0000;
/// Limite de program headers aceitos; barra arquivos que pedem trabalho demais.
pub const MAX_PHDRS: usize = 64;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;

/// Motivo pelo qual um arquivo foi recusado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Arquivo menor que o cabeçalho ou que a tabela de program headers.
    Truncated,
    /// Não começa com `\x7fELF`.
    BadMagic,
    /// Não é ELF de 64 bits.
    NotElf64,
    /// Não é little-endian.
    NotLittleEndian,
    /// Versão do ELF diferente de 1.
    BadVersion,
    /// Não é `ET_EXEC`.
    NotExecutable,
    /// Não é `EM_X86_64`.
    BadMachine,
    /// Tamanho de cabeçalho ou de program header inesperado.
    BadHeaderSize,
    /// Zero ou mais de [`MAX_PHDRS`] program headers.
    BadPhdrCount,
    /// Dados do segmento além do fim do arquivo.
    SegmentOutOfFile,
    /// `p_filesz` maior que `p_memsz`.
    FileszExceedsMemsz,
    /// Alinhamento não é potência de dois ≥ [`PAGE_SIZE`] ou não casa com o offset.
    BadAlignment,
    /// Segmento fora da metade alta canônica.
    NotHigherHalf,
    /// Aritmética de endereço transbordaria.
    Overflow,
    /// Segmentos fora de ordem ou dividindo uma página.
    Overlap,
    /// Segmento gravável e executável ao mesmo tempo (W^X).
    WriteExecute,
    /// Nenhum `PT_LOAD` com memória.
    NoSegments,
    /// Ponto de entrada fora de um segmento executável.
    BadEntry,
}

/// Permissões de um segmento (`p_flags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flags(u32);

impl Flags {
    /// Leitura (`PF_R`).
    #[must_use]
    pub fn readable(self) -> bool {
        self.0 & 4 != 0
    }
    /// Escrita (`PF_W`).
    #[must_use]
    pub fn writable(self) -> bool {
        self.0 & 2 != 0
    }
    /// Execução (`PF_X`).
    #[must_use]
    pub fn executable(self) -> bool {
        self.0 & 1 != 0
    }
}

/// Escreve no formato `RWX`, com `-` para cada permissão ausente.
impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bit = |on, c| if on { c } else { '-' };
        write!(
            f,
            "{}{}{}",
            bit(self.readable(), 'R'),
            bit(self.writable(), 'W'),
            bit(self.executable(), 'X')
        )
    }
}

/// Segmento `PT_LOAD` validado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    /// Endereço virtual inicial.
    pub vaddr: u64,
    /// Tamanho em memória; o que passa de `data.len()` é zerado (BSS).
    pub memsz: u64,
    /// Permissões.
    pub flags: Flags,
    /// Bytes do arquivo (`p_filesz` bytes a partir de `p_offset`).
    pub data: &'a [u8],
}

/// Executável ELF64 x86-64 validado.
#[derive(Debug, Clone, Copy)]
pub struct Elf<'a> {
    data: &'a [u8],
    entry: u64,
    phoff: usize,
    phnum: usize,
}

struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

fn bytes<const N: usize>(d: &[u8], at: usize) -> Option<[u8; N]> {
    d.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    bytes(d, at).map(u16::from_le_bytes)
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    bytes(d, at).map(u32::from_le_bytes)
}

fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    bytes(d, at).map(u64::from_le_bytes)
}

fn phdr(d: &[u8], at: usize) -> Option<Phdr> {
    Some(Phdr {
        kind: u32_at(d, at)?,
        flags: u32_at(d, at + 4)?,
        offset: u64_at(d, at + 8)?,
        vaddr: u64_at(d, at + 16)?,
        filesz: u64_at(d, at + 32)?,
        memsz: u64_at(d, at + 40)?,
        align: u64_at(d, at + 48)?,
    })
}

/// Faixa de páginas `[início, fim)` que o segmento ocupa.
fn pages(p: &Phdr) -> Result<(u64, u64), Error> {
    let end = p.vaddr.checked_add(p.memsz).ok_or(Error::Overflow)?;
    let end = end
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(Error::Overflow)?;
    Ok((p.vaddr & !(PAGE_SIZE - 1), end))
}

fn check_segment<'a>(d: &'a [u8], p: &Phdr) -> Result<&'a [u8], Error> {
    let flags = Flags(p.flags);
    if flags.writable() && flags.executable() {
        return Err(Error::WriteExecute);
    }
    let start = usize::try_from(p.offset).map_err(|_| Error::SegmentOutOfFile)?;
    let len = usize::try_from(p.filesz).map_err(|_| Error::SegmentOutOfFile)?;
    let end = start.checked_add(len).ok_or(Error::SegmentOutOfFile)?;
    let bytes = d.get(start..end).ok_or(Error::SegmentOutOfFile)?;
    if p.filesz > p.memsz {
        return Err(Error::FileszExceedsMemsz);
    }
    if !p.align.is_power_of_two() || p.align < PAGE_SIZE || p.vaddr % p.align != p.offset % p.align
    {
        return Err(Error::BadAlignment);
    }
    if p.vaddr < HIGHER_HALF {
        return Err(Error::NotHigherHalf);
    }
    pages(p)?;
    Ok(bytes)
}

impl<'a> Elf<'a> {
    /// Valida cabeçalho e todos os `PT_LOAD` de `data`.
    ///
    /// # Errors
    ///
    /// Devolve o primeiro problema encontrado; veja [`Error`].
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let ident = data.get(..EHDR_SIZE).ok_or(Error::Truncated)?;
        if ident[..4] != *b"\x7fELF" {
            return Err(Error::BadMagic);
        }
        if ident[4] != 2 {
            return Err(Error::NotElf64);
        }
        if ident[5] != 1 {
            return Err(Error::NotLittleEndian);
        }
        let field16 = |at| u16_at(data, at).ok_or(Error::Truncated);
        if ident[6] != 1 || u32_at(data, 20) != Some(1) {
            return Err(Error::BadVersion);
        }
        if field16(16)? != ET_EXEC {
            return Err(Error::NotExecutable);
        }
        if field16(18)? != EM_X86_64 {
            return Err(Error::BadMachine);
        }
        if usize::from(field16(52)?) != EHDR_SIZE || usize::from(field16(54)?) != PHDR_SIZE {
            return Err(Error::BadHeaderSize);
        }
        let phnum = usize::from(field16(56)?);
        if phnum == 0 || phnum > MAX_PHDRS {
            return Err(Error::BadPhdrCount);
        }
        let phoff = u64_at(data, 32).ok_or(Error::Truncated)?;
        let phoff = usize::try_from(phoff).map_err(|_| Error::Truncated)?;
        let table_end = phoff.checked_add(phnum * PHDR_SIZE);
        if table_end.is_none_or(|end| end > data.len()) {
            return Err(Error::Truncated);
        }
        let elf = Self {
            data,
            entry: u64_at(data, 24).ok_or(Error::Truncated)?,
            phoff,
            phnum,
        };
        elf.validate()?;
        Ok(elf)
    }

    fn loads(&self) -> impl Iterator<Item = Phdr> + '_ {
        (0..self.phnum)
            .filter_map(|i| phdr(self.data, self.phoff + i * PHDR_SIZE))
            .filter(|p| p.kind == PT_LOAD && p.memsz > 0)
    }

    fn validate(&self) -> Result<(), Error> {
        let mut prev_end = 0;
        let mut entry_ok = false;
        let mut any = false;
        for p in self.loads() {
            check_segment(self.data, &p)?;
            let (start, end) = pages(&p)?;
            if start < prev_end {
                return Err(Error::Overlap);
            }
            prev_end = end;
            any = true;
            let inside = self.entry >= p.vaddr && self.entry - p.vaddr < p.memsz;
            entry_ok |= inside && Flags(p.flags).executable();
        }
        if !any {
            return Err(Error::NoSegments);
        }
        if !entry_ok {
            return Err(Error::BadEntry);
        }
        Ok(())
    }

    /// Endereço virtual do ponto de entrada.
    #[must_use]
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// Segmentos `PT_LOAD` com memória, em ordem crescente de endereço.
    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        self.loads().filter_map(|p| {
            Some(Segment {
                vaddr: p.vaddr,
                memsz: p.memsz,
                flags: Flags(p.flags),
                data: check_segment(self.data, &p).ok()?,
            })
        })
    }
}

#[cfg(test)]
mod tests;
