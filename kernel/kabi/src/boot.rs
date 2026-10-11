//! `BootInfo` v1: o que o `optboot` entrega ao kernel (SDD v1.0, seção 5.2).
//!
//! Tudo é `#[repr(C)]` e só usa inteiros e ponteiros crus, porque a estrutura
//! atravessa a fronteira entre dois binários (`x86_64-unknown-uefi` e
//! `x86_64-unknown-none`). Campos opcionais usam zero como "ausente", e os
//! métodos devolvem `Option`.
//!
//! Os ponteiros (`memory_map`) e o endereço da própria `BootInfo` são endereços
//! virtuais no mapa direto da memória física, que começa em
//! [`BootInfo::direct_map_base`] (ADR 0026), válidos depois que o kernel
//! desfizer o mapa de identidade temporário.

use crate::UnknownValue;

/// `"OPTIMUS!"` em ASCII, lido como `u64` big-endian.
pub const BOOT_MAGIC: u64 = 0x4F50_5449_4D55_5321;
/// Versão desta estrutura.
pub const BOOT_VERSION: u32 = 1;
/// Tamanho máximo da linha de comando do kernel, em bytes.
pub const CMDLINE_MAX: usize = 1024;
/// Bytes da semente inicial do CSPRNG.
pub const RNG_SEED_LEN: usize = 64;
/// Início da faixa onde o mapa direto da memória física pode ficar (seção
/// 6.4; ADR 0026).
pub const DIRECT_MAP_START: u64 = 0xffff_8000_0000_0000;
/// Fim (exclusivo) da faixa do mapa direto: começam aí os objetos do kernel.
pub const DIRECT_MAP_END: u64 = 0xffff_c000_0000_0000;
/// Passo do deslocamento aleatório do mapa direto: 1 GiB (ADR 0026).
pub const DIRECT_MAP_ALIGN: u64 = 1 << 30;

/// Posições possíveis do mapa direto para `limit` bytes de memória física:
/// toda base alinhada a [`DIRECT_MAP_ALIGN`] com `[base, base + limit)` dentro
/// da faixa. `limit` é arredondado para 1 GiB; zero se não couber.
#[must_use]
pub const fn direct_map_slots(limit: u64) -> u64 {
    let span = DIRECT_MAP_END - DIRECT_MAP_START;
    let Some(limit) = limit.checked_next_multiple_of(DIRECT_MAP_ALIGN) else {
        return 0;
    };
    if limit > span {
        0
    } else {
        (span - limit) / DIRECT_MAP_ALIGN + 1
    }
}

/// Base do mapa direto sorteada com `random` para `limit` bytes de memória
/// física (ADR 0026); `None` se a memória não couber na faixa.
#[must_use]
pub const fn choose_direct_map_base(random: u64, limit: u64) -> Option<u64> {
    let slots = direct_map_slots(limit);
    if slots == 0 {
        return None;
    }
    Some(DIRECT_MAP_START + (random % slots) * DIRECT_MAP_ALIGN)
}

/// `base` é uma base válida de mapa direto para `limit` bytes: alinhada a
/// 1 GiB e com o mapa inteiro dentro da faixa.
#[must_use]
pub const fn direct_map_base_valid(base: u64, limit: u64) -> bool {
    base >= DIRECT_MAP_START
        && base.is_multiple_of(DIRECT_MAP_ALIGN)
        && (base - DIRECT_MAP_START) / DIRECT_MAP_ALIGN < direct_map_slots(limit)
}
/// Endereço de ligação da imagem do kernel, antes do deslocamento de KASLR.
pub const KERNEL_LINK_BASE: u64 = 0xffff_ffff_8000_0000;

abi_enum! {
/// Tipo normalizado de uma faixa de memória física.
pub enum MemKind: u32, raw(n) => u64::from(n);
    Usable = 0 => "RAM livre para o alocador de frames.",
    Reserved = 1 => "Não usar: firmware, runtime services, memória com defeito.",
    Acpi = 2 => "Tabelas ACPI e memória NVS do firmware.",
    Mmio = 3 => "E/S mapeada em memória.",
    Bootfs = 4 => "Imagem do bootfs (seção 5.3).",
    Kernel = 5 => "Imagem, pilha, tabelas de página e `BootInfo` do kernel.",
}

/// Faixa de memória física `[base, base + len)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct MemRegion {
    /// Primeiro endereço físico.
    pub base: u64,
    /// Tamanho em bytes.
    pub len: u64,
    /// Valor de [`MemKind`]; use [`MemRegion::kind`].
    pub kind: u32,
    /// Sempre zero.
    pub reserved: u32,
}

impl MemRegion {
    /// Faixa nova do tipo `kind`.
    #[must_use]
    pub const fn new(base: u64, len: u64, kind: MemKind) -> Self {
        Self {
            base,
            len,
            kind: kind.number(),
            reserved: 0,
        }
    }

    /// Tipo da faixa; valores desconhecidos contam como reservados.
    #[must_use]
    pub fn kind(&self) -> MemKind {
        MemKind::try_from(u64::from(self.kind)).unwrap_or(MemKind::Reserved)
    }

    /// Fim exclusivo da faixa (satura em `u64::MAX`).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.len)
    }
}

/// Ordena por base e funde faixas vizinhas do mesmo tipo; devolve quantas sobram.
///
/// Faixas vazias são descartadas. Faixas sobrepostas não são corrigidas: o
/// firmware não as produz, e o kernel recusa o mapa se encontrar alguma.
pub fn normalize(regions: &mut [MemRegion]) -> usize {
    // Ordenação por inserção: sem alocação e com poucas centenas de faixas.
    for i in 1..regions.len() {
        let mut j = i;
        while j > 0 && regions[j - 1].base > regions[j].base {
            regions.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut out = 0;
    for i in 0..regions.len() {
        let r = regions[i];
        if r.len == 0 {
            continue;
        }
        if out > 0 && regions[out - 1].kind == r.kind && regions[out - 1].end() == r.base {
            regions[out - 1].len += r.len;
        } else {
            regions[out] = r;
            out += 1;
        }
    }
    out
}

/// Formato dos pixels do framebuffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    /// Byte 0 vermelho, 1 verde, 2 azul, 3 reservado.
    Rgb = 0,
    /// Byte 0 azul, 1 verde, 2 vermelho, 3 reservado.
    Bgr = 1,
}

/// Framebuffer linear deixado pelo GOP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Framebuffer {
    /// Endereço físico; zero significa "sem framebuffer".
    pub base: u64,
    /// Tamanho em bytes.
    pub size: u64,
    /// Largura visível, em pixels.
    pub width: u32,
    /// Altura visível, em pixels.
    pub height: u32,
    /// Pixels por linha (≥ `width`).
    pub stride: u32,
    /// Valor de [`PixelFormat`].
    pub format: u32,
}

/// Região física opcional; `len == 0` significa ausente.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct PhysRange {
    /// Endereço físico inicial.
    pub base: u64,
    /// Tamanho em bytes.
    pub len: u64,
}

/// `BootInfo` v1 (tabela 5.2).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BootInfo {
    /// Sempre [`BOOT_MAGIC`].
    pub magic: u64,
    /// Sempre [`BOOT_VERSION`].
    pub version: u32,
    /// Sempre zero.
    pub reserved: u32,
    /// Endereço virtual (mapa direto) do vetor de [`MemRegion`], já normalizado.
    pub memory_map: *const MemRegion,
    /// Quantidade de faixas em `memory_map`.
    pub memory_map_len: u64,
    /// Framebuffer do GOP; `base == 0` se não houver.
    pub framebuffer: Framebuffer,
    /// Endereço físico do RSDP da ACPI 2.0; zero se não houver.
    pub acpi_rsdp: u64,
    /// Imagem do bootfs; vazia até T-211.
    pub bootfs: PhysRange,
    /// Bytes da linha de comando (UTF-8, sem terminador).
    pub cmdline: [u8; CMDLINE_MAX],
    /// Quantos bytes de `cmdline` valem.
    pub cmdline_len: u64,
    /// Semente inicial do CSPRNG.
    pub rng_seed: [u8; RNG_SEED_LEN],
    /// Deslocamento de KASLR somado ao endereço de ligação do kernel.
    pub kaslr_slide: u64,
    /// Endereço virtual onde o optboot mapeou o endereço físico 0 (ADR 0026).
    pub direct_map_base: u64,
    /// Log de medições do TPM; vazio enquanto não houver medição (seção 5.1).
    pub tpm_event_log: PhysRange,
    /// Instante da entrega ao kernel, em ns desde o reset da CPU.
    pub boot_time_ns: u64,
}

impl BootInfo {
    /// `BootInfo` vazia, com magic e versão corretos.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            magic: BOOT_MAGIC,
            version: BOOT_VERSION,
            reserved: 0,
            memory_map: core::ptr::null(),
            memory_map_len: 0,
            framebuffer: Framebuffer {
                base: 0,
                size: 0,
                width: 0,
                height: 0,
                stride: 0,
                format: 0,
            },
            acpi_rsdp: 0,
            bootfs: PhysRange { base: 0, len: 0 },
            cmdline: [0; CMDLINE_MAX],
            cmdline_len: 0,
            rng_seed: [0; RNG_SEED_LEN],
            kaslr_slide: 0,
            direct_map_base: DIRECT_MAP_START,
            tpm_event_log: PhysRange { base: 0, len: 0 },
            boot_time_ns: 0,
        }
    }

    /// Magic e versão conferem.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == BOOT_MAGIC && self.version == BOOT_VERSION
    }

    /// Framebuffer, se o GOP existir.
    #[must_use]
    pub const fn framebuffer(&self) -> Option<&Framebuffer> {
        if self.framebuffer.base == 0 {
            None
        } else {
            Some(&self.framebuffer)
        }
    }

    /// RSDP da ACPI, se houver.
    #[must_use]
    pub const fn acpi_rsdp(&self) -> Option<u64> {
        if self.acpi_rsdp == 0 {
            None
        } else {
            Some(self.acpi_rsdp)
        }
    }

    /// Linha de comando; `None` se não for UTF-8 ou se o tamanho for inválido.
    #[must_use]
    pub fn cmdline(&self) -> Option<&str> {
        let len = usize::try_from(self.cmdline_len).ok()?;
        core::str::from_utf8(self.cmdline.get(..len)?).ok()
    }

    /// Copia `text` para `cmdline`, truncando em [`CMDLINE_MAX`] bytes sem
    /// cortar um caractere ao meio.
    pub fn set_cmdline(&mut self, text: &str) {
        let mut len = text.len().min(CMDLINE_MAX);
        while !text.is_char_boundary(len) {
            len -= 1;
        }
        self.cmdline[..len].copy_from_slice(&text.as_bytes()[..len]);
        self.cmdline_len = len as u64;
    }
}

#[cfg(test)]
mod tests;
