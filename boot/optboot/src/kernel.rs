//! Carga do kernel com KASLR (SDD v1.0, seção 5.1, passo 6).
//!
//! O `okernel` é PIE estático ligado em `kabi::boot::KERNEL_LINK_BASE`. O optboot copia
//! todos os `PT_LOAD` para um bloco físico contíguo, com a mesma disposição
//! relativa dos endereços virtuais, e aplica as relocações
//! `R_X86_64_RELATIVE` somando o deslocamento escolhido. Um `ET_EXEC` ainda é
//! aceito, mas fica com deslocamento zero.

use core::fmt::Write;

use oelf::{Elf, Flags, PAGE_SIZE};

use crate::firmware::{self, KERNEL_MEMORY};
use crate::{BootServices, Console, Error, alloc_zeroed};

/// Granularidade do deslocamento: uma página grande.
pub const SLIDE_ALIGN: u64 = 2 << 20;
/// Posições possíveis: o kernel cai em algum lugar do primeiro 1 GiB dos 2 GiB
/// do topo, o que dá 9 bits de entropia e folga para imagens de até 1 GiB.
const SLIDE_SLOTS: u64 = (1 << 30) / SLIDE_ALIGN;

/// Kernel carregado na memória física, pronto para mapear.
pub struct Kernel {
    /// ELF validado; os segmentos dizem o que mapear e com que permissão.
    pub elf: Elf<'static>,
    /// Endereço físico da primeira página da imagem.
    pub phys: u64,
    /// Endereço virtual de ligação da primeira página (sem deslocamento).
    pub link_start: u64,
    /// Bytes da imagem, múltiplo de 4 KiB.
    pub size: u64,
    /// Deslocamento de KASLR aplicado.
    pub slide: u64,
}

impl Kernel {
    /// Ponto de entrada já deslocado.
    pub fn entry(&self) -> u64 {
        self.elf.entry() + self.slide
    }

    /// Segmentos como `(virtual deslocado, físico, bytes, permissões)`, com
    /// início e fim arredondados para páginas.
    pub fn mappings(&self) -> impl Iterator<Item = (u64, u64, u64, Flags)> + '_ {
        self.elf.segments().map(|s| {
            let start = s.vaddr & !(PAGE_SIZE - 1);
            let end = (s.vaddr + s.memsz).next_multiple_of(PAGE_SIZE);
            let phys = self.phys + (start - self.link_start);
            (start + self.slide, phys, end - start, s.flags)
        })
    }
}

/// Sorteia o deslocamento com 8 bytes próprios, separados da semente do kernel.
fn choose_slide(bs: &BootServices) -> u64 {
    let mut rand = [0u8; 8];
    firmware::entropy(bs, &mut rand);
    (u64::from_le_bytes(rand) % SLIDE_SLOTS) * SLIDE_ALIGN
}

/// Copia os segmentos para memória física contígua e aplica as relocações.
pub fn load(out: &mut Console, bs: &BootServices, file: &'static [u8]) -> Result<Kernel, Error> {
    let elf = Elf::parse(file).map_err(Error::Elf)?;
    let mut segments = elf.segments();
    let first = segments.next().ok_or(Error::Elf(oelf::Error::NoSegments))?;
    let link_start = first.vaddr & !(PAGE_SIZE - 1);
    let last = elf.segments().last().unwrap_or(first);
    let size = (last.vaddr + last.memsz).next_multiple_of(PAGE_SIZE) - link_start;
    let len = usize::try_from(size).map_err(|_| Error::BadSize(size))?;
    // SAFETY: zero é um `u8` válido.
    let image = unsafe { alloc_zeroed::<u8>(bs, KERNEL_MEMORY, len) }?;
    let slide = if elf.is_relocatable() {
        choose_slide(bs)
    } else {
        0
    };
    let offset = |vaddr: u64| usize::try_from(vaddr - link_start).unwrap_or(usize::MAX);
    let phys = image.as_ptr().addr() as u64;
    for seg in elf.segments() {
        let at = offset(seg.vaddr);
        if let Some(slot) = image.get_mut(at..at + seg.data.len()) {
            slot.copy_from_slice(seg.data);
        }
        let _ = write!(
            out,
            "optboot: seg {:#x} -> {:#x} {:#x} {}\r\n",
            seg.vaddr + slide,
            phys + (seg.vaddr - link_start),
            seg.memsz,
            seg.flags
        );
    }
    let mut count = 0;
    for r in elf.relocations() {
        // `oelf` garante que os 8 bytes do alvo caem dentro de um segmento.
        let at = offset(r.vaddr);
        if let Some(slot) = image.get_mut(at..at + 8) {
            slot.copy_from_slice(&r.addend.wrapping_add(slide).to_le_bytes());
            count += 1;
        }
    }
    let _ = write!(
        out,
        "optboot: KASLR: deslocamento {slide:#x}, base {:#x}, {count} relocações\r\n",
        link_start + slide
    );
    Ok(Kernel {
        elf,
        phys,
        link_start,
        size,
        slide,
    })
}
