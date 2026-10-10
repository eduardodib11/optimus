//! Tabelas de página x86-64 de 4 níveis (T-107; SDD v1.0, seções 6.4 e 6.5).
//!
//! Lógica portável: mapear, desmapear, proteger e traduzir páginas de 4 KiB e
//! 2 MiB. O acesso às tabelas na memória física e a origem dos frames ficam
//! atrás de [`TableMemory`]; o kernel a implementa sobre o mapa direto e o
//! buddy, e os testes no host sobre um vetor.
//!
//! W^X é regra da API: nenhuma folha é gravável e executável ao mesmo tempo.
//! Os níveis intermediários liberam tudo (gravável, executável) e quem
//! restringe é a folha. Quem chama invalida a TLB (`invlpg`) depois de
//! [`PageTables::unmap`] e [`PageTables::protect`]. Tabelas intermediárias
//! que ficam vazias não são devolvidas (custo de no máximo 4 KiB por 2 MiB
//! já mapeados; a coleta entra com o `AddressSpace` do T-205).

#![forbid(unsafe_code)]

use super::{FRAME_SIZE, PhysAddr};

/// Entradas por tabela.
pub const ENTRIES: usize = 512;
/// Uma tabela de página.
pub type Table = [u64; ENTRIES];

/// Presente.
pub const PRESENT: u64 = 1;
/// Gravável.
pub const WRITABLE: u64 = 1 << 1;
/// Acessível no anel 3.
pub const USER: u64 = 1 << 2;
/// Write-through.
pub const WRITE_THROUGH: u64 = 1 << 3;
/// Sem cache.
pub const NO_CACHE: u64 = 1 << 4;
/// Folha de 2 MiB no nível 2.
pub const HUGE: u64 = 1 << 7;
/// Global (sobrevive à troca de CR3).
pub const GLOBAL: u64 = 1 << 8;
/// PAT de uma folha de 2 MiB (na de 4 KiB o bit 7 faz esse papel).
const PAT_2M: u64 = 1 << 12;
/// Não executável.
pub const NO_EXECUTE: u64 = 1 << 63;
const ADDR_4K: u64 = 0x000f_ffff_ffff_f000;
const ADDR_2M: u64 = 0x000f_ffff_ffe0_0000;

/// Tamanho de página.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageSize {
    /// 4 KiB, folha no nível 1.
    Size4K,
    /// 2 MiB, folha no nível 2.
    Size2M,
}

impl PageSize {
    /// Bytes da página.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size4K => FRAME_SIZE,
            Self::Size2M => 2 << 20,
        }
    }

    const fn level(self) -> u32 {
        match self {
            Self::Size4K => 1,
            Self::Size2M => 2,
        }
    }

    const fn addr_mask(self) -> u64 {
        match self {
            Self::Size4K => ADDR_4K,
            Self::Size2M => ADDR_2M,
        }
    }
}

/// Permissões e atributos de uma folha. Leitura é sempre permitida.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "cada bool é um bit da folha")]
pub struct Flags {
    /// Gravável.
    pub write: bool,
    /// Executável.
    pub exec: bool,
    /// Acessível no anel 3.
    pub user: bool,
    /// Global.
    pub global: bool,
    /// Sem cache (MMIO).
    pub uncached: bool,
}

impl Flags {
    /// Só leitura, NX.
    pub const READ: Self = Self {
        write: false,
        exec: false,
        user: false,
        global: false,
        uncached: false,
    };
    /// Leitura e escrita, NX.
    pub const RW: Self = Self {
        write: true,
        ..Self::READ
    };
    /// Leitura e execução.
    pub const RX: Self = Self {
        exec: true,
        ..Self::READ
    };

    /// Bits da folha de tamanho `size`.
    #[must_use]
    pub const fn bits(self, size: PageSize) -> u64 {
        let mut bits = PRESENT;
        if self.write {
            bits |= WRITABLE;
        }
        if !self.exec {
            bits |= NO_EXECUTE;
        }
        if self.user {
            bits |= USER;
        }
        if self.global {
            bits |= GLOBAL;
        }
        if self.uncached {
            bits |= NO_CACHE | WRITE_THROUGH;
        }
        if matches!(size, PageSize::Size2M) {
            bits |= HUGE;
        }
        bits
    }

    /// Permissões de uma folha.
    #[must_use]
    pub const fn from_bits(entry: u64) -> Self {
        Self {
            write: entry & WRITABLE != 0,
            exec: entry & NO_EXECUTE == 0,
            user: entry & USER != 0,
            global: entry & GLOBAL != 0,
            uncached: entry & NO_CACHE != 0,
        }
    }
}

/// Erros das operações; nenhuma entra em pânico.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// Gravável e executável ao mesmo tempo (W^X).
    WriteExec,
    /// Endereço virtual ou físico não alinhado ao tamanho da página.
    Unaligned,
    /// Endereço virtual fora da forma canônica de 48 bits.
    NonCanonical,
    /// Já existe mapeamento (ou tabela de páginas menores) no lugar.
    AlreadyMapped,
    /// Nada mapeado no endereço.
    NotMapped,
    /// O endereço está mapeado com outro tamanho de página.
    SizeMismatch,
    /// Faltou frame para uma tabela.
    OutOfFrames,
}

/// Onde as tabelas moram: acesso por endereço físico e frames novos.
pub trait TableMemory {
    /// A tabela no frame físico `phys`.
    fn table(&mut self, phys: PhysAddr) -> &mut Table;
    /// Um frame zerado para uma tabela nova.
    fn alloc_table(&mut self) -> Option<PhysAddr>;
}

/// Uma folha encontrada por [`PageTables::translate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Endereço físico correspondente ao endereço virtual pedido.
    pub phys: PhysAddr,
    /// Tamanho da folha.
    pub size: PageSize,
    /// Permissões da folha.
    pub flags: Flags,
}

/// Hierarquia de tabelas com raiz (PML4) em `root`.
pub struct PageTables<M> {
    root: PhysAddr,
    mem: M,
}

/// Índice de `virt` na tabela do nível `level` (4 = PML4).
const fn slot(virt: u64, level: u32) -> usize {
    ((virt >> (12 + 9 * (level - 1))) & 0x1ff) as usize
}

/// Os bits 63..47 são todos iguais.
const fn canonical(virt: u64) -> bool {
    let top = virt >> 47;
    top == 0 || top == 0x1_ffff
}

impl<M: TableMemory> PageTables<M> {
    /// Usa a hierarquia existente em `root`.
    pub const fn new(root: PhysAddr, mem: M) -> Self {
        Self { root, mem }
    }

    /// Endereço físico do PML4.
    pub const fn root(&self) -> PhysAddr {
        self.root
    }

    /// Acesso direto à memória das tabelas.
    pub fn memory(&mut self) -> &mut M {
        &mut self.mem
    }

    /// Mapeia a página `virt` em `phys`.
    ///
    /// # Errors
    ///
    /// W^X, alinhamento, endereço não canônico, lugar ocupado ou falta de frame.
    pub fn map(
        &mut self,
        virt: u64,
        phys: PhysAddr,
        size: PageSize,
        flags: Flags,
    ) -> Result<(), MapError> {
        if flags.write && flags.exec {
            return Err(MapError::WriteExec);
        }
        check(virt, size)?;
        if !phys.0.is_multiple_of(size.bytes()) {
            return Err(MapError::Unaligned);
        }
        let (table, index) = self.walk(virt, size.level(), Some(flags.user))?;
        let leaf = &mut self.mem.table(table)[index];
        if *leaf & PRESENT != 0 {
            return Err(MapError::AlreadyMapped);
        }
        *leaf = phys.0 | flags.bits(size);
        Ok(())
    }

    /// Desfaz o mapeamento da página `virt` e devolve o frame físico.
    /// Uma página de 4 KiB dentro de uma de 2 MiB divide a grande antes.
    ///
    /// # Errors
    ///
    /// Endereço inválido, nada mapeado, tamanho diferente ou falta de frame
    /// para a divisão.
    pub fn unmap(&mut self, virt: u64, size: PageSize) -> Result<PhysAddr, MapError> {
        let (table, index) = self.leaf(virt, size)?;
        let leaf = &mut self.mem.table(table)[index];
        let phys = PhysAddr(*leaf & size.addr_mask());
        *leaf = 0;
        Ok(phys)
    }

    /// Troca as permissões da página `virt`, mantendo o frame. Uma página de
    /// 4 KiB dentro de uma de 2 MiB divide a grande antes.
    ///
    /// # Errors
    ///
    /// W^X, endereço inválido, nada mapeado, tamanho diferente ou falta de
    /// frame para a divisão.
    pub fn protect(&mut self, virt: u64, size: PageSize, flags: Flags) -> Result<(), MapError> {
        if flags.write && flags.exec {
            return Err(MapError::WriteExec);
        }
        let (table, index) = self.leaf(virt, size)?;
        let leaf = &mut self.mem.table(table)[index];
        *leaf = (*leaf & size.addr_mask()) | flags.bits(size);
        Ok(())
    }

    /// A folha que mapeia `virt`, se houver.
    pub fn translate(&mut self, virt: u64) -> Option<Mapping> {
        if !canonical(virt) {
            return None;
        }
        let mut table = self.root;
        for level in (1..=4).rev() {
            let entry = self.mem.table(table)[slot(virt, level)];
            if entry & PRESENT == 0 {
                return None;
            }
            let size = match level {
                1 => PageSize::Size4K,
                2 if entry & HUGE != 0 => PageSize::Size2M,
                3 if entry & HUGE != 0 => return None,
                _ => {
                    table = PhysAddr(entry & ADDR_4K);
                    continue;
                }
            };
            let offset = virt & (size.bytes() - 1);
            return Some(Mapping {
                phys: PhysAddr((entry & size.addr_mask()) + offset),
                size,
                flags: Flags::from_bits(entry),
            });
        }
        None
    }

    /// Chama `f(virt, folha)` para cada folha de 4 KiB ou 2 MiB presente, em
    /// ordem crescente de endereço (para auditar W^X, por exemplo).
    pub fn for_each_leaf(&mut self, f: &mut dyn FnMut(u64, Mapping)) {
        self.visit(self.root, 4, 0, f);
    }

    fn visit(&mut self, table: PhysAddr, level: u32, base: u64, f: &mut dyn FnMut(u64, Mapping)) {
        for i in 0..ENTRIES {
            let entry = self.mem.table(table)[i];
            if entry & PRESENT == 0 {
                continue;
            }
            let mut virt = base | ((i as u64) << (12 + 9 * (level - 1)));
            if level == 4 && i >= ENTRIES / 2 {
                virt |= 0xffff_0000_0000_0000;
            }
            let size = match (level, entry & HUGE != 0) {
                (1, _) => PageSize::Size4K,
                (2, true) => PageSize::Size2M,
                (3, true) => continue,
                _ => {
                    self.visit(PhysAddr(entry & ADDR_4K), level - 1, virt, f);
                    continue;
                }
            };
            let phys = PhysAddr(entry & size.addr_mask());
            f(
                virt,
                Mapping {
                    phys,
                    size,
                    flags: Flags::from_bits(entry),
                },
            );
        }
    }

    /// Tabela e índice da folha presente de tamanho `size` em `virt`,
    /// dividindo uma página de 2 MiB se `size` for 4 KiB.
    fn leaf(&mut self, virt: u64, size: PageSize) -> Result<(PhysAddr, usize), MapError> {
        check(virt, size)?;
        let (table, index) = match self.walk(virt, size.level(), None) {
            Err(MapError::SizeMismatch) if size == PageSize::Size4K => {
                self.split(virt)?;
                self.walk(virt, 1, None)?
            }
            other => other?,
        };
        let entry = self.mem.table(table)[index];
        if entry & PRESENT == 0 {
            return Err(MapError::NotMapped);
        }
        if size == PageSize::Size2M && entry & HUGE == 0 {
            return Err(MapError::SizeMismatch);
        }
        Ok((table, index))
    }

    /// Troca a folha de 2 MiB que cobre `virt` por uma tabela de 512 folhas
    /// de 4 KiB com o mesmo frame e as mesmas permissões.
    fn split(&mut self, virt: u64) -> Result<(), MapError> {
        let (table, index) = self.walk(virt, 2, None)?;
        let entry = self.mem.table(table)[index];
        if entry & (PRESENT | HUGE) != PRESENT | HUGE {
            return Err(MapError::NotMapped);
        }
        let base = entry & ADDR_2M;
        let bits = entry & !ADDR_2M & !HUGE & !PAT_2M;
        let new = self.mem.alloc_table().ok_or(MapError::OutOfFrames)?;
        let small = self.mem.table(new);
        for (i, e) in (0u64..).zip(small.iter_mut()) {
            *e = (base + i * FRAME_SIZE) | bits;
        }
        self.mem.table(table)[index] = new.0 | PRESENT | WRITABLE | (entry & USER);
        Ok(())
    }

    /// Desce do PML4 até a tabela do nível `level` que contém `virt`.
    /// Com `create = Some(user)`, cria tabelas que faltarem. Uma folha
    /// grande no caminho dá [`MapError::SizeMismatch`].
    fn walk(
        &mut self,
        virt: u64,
        level: u32,
        create: Option<bool>,
    ) -> Result<(PhysAddr, usize), MapError> {
        let mut table = self.root;
        for l in (level + 1..=4).rev() {
            let index = slot(virt, l);
            let entry = self.mem.table(table)[index];
            table = if entry & PRESENT == 0 {
                let user = create.ok_or(MapError::NotMapped)?;
                let new = self.mem.alloc_table().ok_or(MapError::OutOfFrames)?;
                let user_bit = if user { USER } else { 0 };
                self.mem.table(table)[index] = new.0 | PRESENT | WRITABLE | user_bit;
                new
            } else if entry & HUGE != 0 {
                return Err(if create.is_some() {
                    MapError::AlreadyMapped
                } else {
                    MapError::SizeMismatch
                });
            } else {
                PhysAddr(entry & ADDR_4K)
            };
        }
        Ok((table, slot(virt, level)))
    }
}

fn check(virt: u64, size: PageSize) -> Result<(), MapError> {
    if !canonical(virt) {
        return Err(MapError::NonCanonical);
    }
    if !virt.is_multiple_of(size.bytes()) {
        return Err(MapError::Unaligned);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
