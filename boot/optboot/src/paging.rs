//! Tabelas de página iniciais de 4 níveis (SDD v1.0, seções 5.1 e 6.4).
//!
//! O espaço entregue ao kernel tem:
//!
//! - identidade da memória física baixa, RWX, só para a transição (o código do
//!   optboot continua executando no endereço físico depois do `mov cr3`); o
//!   kernel a remove em T-107;
//! - mapa direto da mesma faixa numa base sorteada (ADR 0026), RW e NX;
//! - a imagem do kernel no endereço deslocado, com a permissão de cada
//!   segmento (W^X: texto R-X, só leitura R--, dados RW- e NX);
//! - a pilha inicial do kernel em [`STACK_BASE`], RW e NX, com uma página de
//!   guarda não mapeada embaixo.
//!
//! A memória física até [`identity_limit`] vai em páginas de 2 MiB; o resto em
//! páginas de 4 KiB. Todas as tabelas vêm de um bloco reservado de antemão.

use kabi::boot::{MemKind, MemRegion};

use crate::Error;

const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const HUGE: u64 = 1 << 7;
const NO_EXECUTE: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const ENTRIES: usize = 512;
const HUGE_SIZE: u64 = 2 << 20;

/// Base da pilha inicial (área de pilhas do kernel, seção 6.4); a primeira
/// página fica sem mapear, como guarda.
pub const STACK_BASE: u64 = 0xffff_e000_0000_0000;
/// Tamanho da pilha inicial.
pub const STACK_BYTES: usize = 64 << 10;
/// [`STACK_BYTES`] como endereço.
pub const STACK_SIZE: u64 = STACK_BYTES as u64;

/// Uma tabela de página: 512 entradas de 64 bits, alinhada a 4 KiB.
#[repr(C, align(4096))]
pub struct Table([u64; ENTRIES]);

/// Fim da faixa física mapeada em identidade e no mapa direto: toda a RAM, ACPI e
/// bootfs do mapa, e ao menos os 4 GiB baixos (onde ficam o framebuffer, o
/// APIC e o IOAPIC), arredondado para 1 GiB.
pub fn identity_limit(map: &[MemRegion]) -> u64 {
    let ram = map
        .iter()
        .filter(|r| {
            matches!(
                r.kind(),
                MemKind::Usable | MemKind::Acpi | MemKind::Kernel | MemKind::Bootfs
            )
        })
        .map(MemRegion::end)
        .max()
        .unwrap_or(0);
    ram.max(4 << 30).next_multiple_of(1 << 30)
}

/// Tabelas necessárias para mapear `limit` bytes duas vezes, uma imagem de
/// `kernel_size` bytes e a pilha, com folga.
pub fn tables_needed(limit: u64, kernel_size: u64) -> usize {
    let gib = usize::try_from(limit >> 30).unwrap_or(usize::MAX);
    let kernel = usize::try_from(kernel_size / HUGE_SIZE).unwrap_or(usize::MAX);
    // O mapa direto numa base sorteada pode cruzar uma fronteira de 512 GiB
    // e precisar de um PDPT a mais.
    1 + 2 * (1 + gib) + 1 + (2 + kernel + 2) + 3 + 4
}

/// Construtor de tabelas sobre um bloco de páginas físicas zeradas.
pub struct PageTables {
    pool: &'static mut [Table],
    used: usize,
}

impl PageTables {
    /// Usa `pool` (zerado, em memória física com identidade) para as tabelas;
    /// a primeira vira o PML4.
    pub fn new(pool: &'static mut [Table]) -> Self {
        Self { pool, used: 1 }
    }

    fn phys(&self, index: usize) -> u64 {
        (&raw const self.pool[index]).addr() as u64
    }

    /// Endereço físico do PML4, para o CR3.
    pub fn root(&self) -> u64 {
        self.phys(0)
    }

    /// Tabela do próximo nível sob `table[index]`, criada se faltar.
    fn child(&mut self, table: usize, index: usize) -> Result<usize, Error> {
        let entry = self.pool[table].0[index];
        if entry & PRESENT != 0 {
            let offset = (entry & ADDR_MASK) - self.phys(0);
            return usize::try_from(offset / 4096).map_err(|_| Error::Paging);
        }
        let new = self.used;
        if new >= self.pool.len() {
            return Err(Error::Paging);
        }
        self.used += 1;
        // Níveis intermediários liberam tudo; quem restringe é a folha.
        self.pool[table].0[index] = self.phys(new) | PRESENT | WRITABLE;
        Ok(new)
    }

    /// Desce até o nível `depth` (1 = PT, 2 = PD) e grava a folha.
    fn map(&mut self, virt: u64, entry: u64, depth: u32) -> Result<(), Error> {
        let mut table = 0;
        for level in (depth + 1..=4).rev() {
            table = self.child(table, slot(virt, level))?;
        }
        let leaf = &mut self.pool[table].0[slot(virt, depth)];
        if *leaf & PRESENT != 0 {
            return Err(Error::Paging);
        }
        *leaf = entry;
        Ok(())
    }

    /// Mapeia `[0, limit)` em identidade (RWX) e no mapa direto em `base`
    /// (RW, NX).
    pub fn map_physical(&mut self, limit: u64, base: u64) -> Result<(), Error> {
        for phys in (0..limit / HUGE_SIZE).map(|i| i * HUGE_SIZE) {
            let entry = phys | PRESENT | WRITABLE | HUGE;
            self.map(phys, entry, 2)?;
            self.map(base + phys, entry | NO_EXECUTE, 2)?;
        }
        Ok(())
    }

    /// Mapeia `len` bytes (múltiplo de 4 KiB) de `phys` em `virt`, em
    /// páginas de 4 KiB; sem `write`, só leitura; sem `exec`, NX.
    pub fn map_range(
        &mut self,
        virt: u64,
        phys: u64,
        len: u64,
        write: bool,
        exec: bool,
    ) -> Result<(), Error> {
        let mut bits = PRESENT;
        if write {
            bits |= WRITABLE;
        }
        if !exec {
            bits |= NO_EXECUTE;
        }
        for off in (0..len).step_by(4096) {
            self.map(virt + off, (phys + off) | bits, 1)?;
        }
        Ok(())
    }
}

/// Índice da entrada de `virt` na tabela do nível `level` (4 = PML4).
fn slot(virt: u64, level: u32) -> usize {
    ((virt >> (12 + 9 * (level - 1))) & 0x1ff) as usize
}
