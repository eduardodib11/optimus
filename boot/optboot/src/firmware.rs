//! Coleta do firmware o que vai na `BootInfo` (SDD v1.0, seção 5.1, passo 5):
//! mapa de memória, GOP, RSDP e entropia.

use core::ffi::c_void;
use core::ptr::{null, null_mut};

use kabi::boot::{Framebuffer, MemKind, MemRegion, PixelFormat};

use crate::arch::x86_64::{HwRng, hw_random, rdtsc};
use crate::{BootServices, Error, Guid, Status, SystemTable, efi};

/// Tipo de memória UEFI da faixa do SO (`0x8000_0000` em diante) que o optboot
/// usa para tudo o que passa a ser do kernel: imagem, pilha, tabelas de página
/// e `BootInfo`. Assim o mapa do firmware já separa essas faixas.
pub const KERNEL_MEMORY: u32 = 0x8000_0000;

/// `EFI_MEMORY_DESCRIPTOR`.
#[repr(C)]
struct MemoryDescriptor {
    kind: u32,
    physical_start: u64,
    virtual_start: u64,
    pages: u64,
    attribute: u64,
}

/// `EFI_CONFIGURATION_TABLE`.
#[repr(C)]
struct ConfigTable {
    guid: Guid,
    table: *const c_void,
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL`.
#[repr(C)]
struct Gop {
    query_mode: usize,
    set_mode: usize,
    blt: usize,
    mode: *const GopMode,
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE`.
#[repr(C)]
struct GopMode {
    max_mode: u32,
    mode: u32,
    info: *const GopModeInfo,
    size_of_info: usize,
    framebuffer_base: u64,
    framebuffer_size: usize,
}

/// `EFI_GRAPHICS_OUTPUT_MODE_INFORMATION`.
#[repr(C)]
struct GopModeInfo {
    version: u32,
    width: u32,
    height: u32,
    pixel_format: u32,
    pixel_bitmask: [u32; 4],
    stride: u32,
}

/// `EFI_RNG_PROTOCOL`.
#[repr(C)]
struct Rng {
    get_info: usize,
    get_rng: unsafe extern "efiapi" fn(
        this: *mut Rng,
        algorithm: *const Guid,
        len: usize,
        out: *mut u8,
    ) -> Status,
}

const ACPI_20_GUID: Guid = Guid(
    0x8868_e871,
    0xe4f1,
    0x11d3,
    [0xbc, 0x22, 0, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);
const GOP_GUID: Guid = Guid(
    0x9042_a9de,
    0x23dc,
    0x4a38,
    [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
);
const RNG_GUID: Guid = Guid(
    0x3152_bca5,
    0xeade,
    0x433d,
    [0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44],
);

/// `EFI_BUFFER_TOO_SMALL`.
const BUFFER_TOO_SMALL: Status = (1 << 63) | 5;

/// Localiza um protocolo pelo GUID, se algum handle o tiver.
fn locate(bs: &BootServices, guid: &Guid) -> Option<*mut c_void> {
    let mut iface = null_mut();
    // SAFETY: LocateProtocol só escreve a interface encontrada em `iface`.
    let status = unsafe { (bs.locate_protocol)(guid, null(), &raw mut iface) };
    (status == 0 && !iface.is_null()).then_some(iface)
}

/// Framebuffer linear do GOP; `None` sem GOP ou em modo só-Blt.
pub fn framebuffer(bs: &BootServices) -> Option<Framebuffer> {
    let gop = locate(bs, &GOP_GUID)?.cast::<Gop>();
    // SAFETY: o firmware mantém `Mode` e `Info` válidos enquanto o GOP existe,
    // e só os lemos antes de ExitBootServices.
    let (mode, info) = unsafe {
        let mode = &*(*gop).mode;
        (mode, &*mode.info)
    };
    let format = match info.pixel_format {
        0 => PixelFormat::Rgb,
        1 => PixelFormat::Bgr,
        _ => return None,
    };
    Some(Framebuffer {
        base: mode.framebuffer_base,
        size: mode.framebuffer_size as u64,
        width: info.width,
        height: info.height,
        stride: info.stride,
        format: format as u32,
    })
}

/// Endereço do RSDP da ACPI 2.0 na tabela de configuração.
pub fn acpi_rsdp(st: &SystemTable) -> Option<u64> {
    // SAFETY: o firmware garante `number_of_table_entries` entradas válidas.
    let tables = unsafe {
        core::slice::from_raw_parts(
            st.configuration_table.cast::<ConfigTable>(),
            st.number_of_table_entries,
        )
    };
    tables
        .iter()
        .find(|t| t.guid == ACPI_20_GUID)
        .map(|t| t.table.addr() as u64)
}

/// De onde veio a semente.
#[derive(Clone, Copy)]
pub enum Entropy {
    /// `EFI_RNG_PROTOCOL`, misturado com RDSEED/RDRAND quando existirem.
    Efi(Option<HwRng>),
    /// Só a CPU.
    Cpu(HwRng),
    /// Nenhuma fonte boa: só variação do TSC. Fraca; o kernel precisa reforçar.
    TscOnly,
}

impl core::fmt::Display for Entropy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Efi(None) => f.write_str("EFI_RNG_PROTOCOL"),
            Self::Efi(Some(hw)) => write!(f, "EFI_RNG_PROTOCOL + {hw:?}"),
            Self::Cpu(hw) => write!(f, "{hw:?}"),
            Self::TscOnly => f.write_str("TSC (fraca)"),
        }
    }
}

/// Preenche `seed` com o `EFI_RNG_PROTOCOL` e mistura RDSEED/RDRAND por XOR,
/// para que uma fonte ruim sozinha não determine a semente.
pub fn entropy(bs: &BootServices, seed: &mut [u8]) -> Entropy {
    let efi_ok = locate(bs, &RNG_GUID).is_some_and(|rng| {
        let rng = rng.cast::<Rng>();
        // SAFETY: `rng` é uma interface válida; GetRNG escreve `seed.len()` bytes.
        unsafe { ((*rng).get_rng)(rng, null(), seed.len(), seed.as_mut_ptr()) == 0 }
    });
    let mut hw = [0u8; 64];
    let hw_ok = hw_random(&mut hw[..seed.len().min(64)]);
    if hw_ok.is_some() {
        for (s, h) in seed.iter_mut().zip(hw) {
            *s ^= h;
        }
    }
    match (efi_ok, hw_ok) {
        (true, hw) => Entropy::Efi(hw),
        (false, Some(hw)) => Entropy::Cpu(hw),
        (false, None) => {
            for s in seed.iter_mut() {
                let t = rdtsc();
                *s ^= (t ^ (t >> 7) ^ (t >> 13)).to_le_bytes()[0];
            }
            Entropy::TscOnly
        }
    }
}

/// Converte um tipo de memória UEFI no tipo normalizado.
fn kind(efi_type: u32) -> MemKind {
    match efi_type {
        // LoaderCode/Data, BootServicesCode/Data e Conventional ficam livres
        // depois de ExitBootServices.
        1..=4 | 7 => MemKind::Usable,
        9 | 10 => MemKind::Acpi,
        11 | 12 => MemKind::Mmio,
        KERNEL_MEMORY => MemKind::Kernel,
        _ => MemKind::Reserved,
    }
}

/// Mapa de memória cru devolvido por `GetMemoryMap`.
pub struct RawMap {
    /// Bytes válidos em `buf`.
    pub size: usize,
    /// Tamanho de cada descritor (pode ser maior que `MemoryDescriptor`).
    pub desc_size: usize,
}

/// Chama `GetMemoryMap` em `buf`; recusa se não couber.
pub fn memory_map(bs: &BootServices, buf: &mut [u8]) -> Result<RawMap, Error> {
    let (mut size, mut key, mut desc_size, mut version) = (buf.len(), 0, 0, 0);
    // SAFETY: GetMemoryMap escreve no máximo `size` bytes em `buf` e os
    // escalares de saída.
    let status = unsafe {
        (bs.get_memory_map)(
            &raw mut size,
            buf.as_mut_ptr(),
            &raw mut key,
            &raw mut desc_size,
            &raw mut version,
        )
    };
    if status == BUFFER_TOO_SMALL {
        return Err(Error::BadSize(size as u64));
    }
    efi("GetMemoryMap", status)?;
    if desc_size < size_of::<MemoryDescriptor>() {
        return Err(Error::BadSize(desc_size as u64));
    }
    Ok(RawMap { size, desc_size })
}

/// Tamanho de buffer suficiente para o mapa atual mais folga para alocações.
pub fn memory_map_size(bs: &BootServices) -> usize {
    let (mut size, mut key, mut desc_size, mut version) = (0, 0, 0, 0);
    // SAFETY: com `size == 0` o firmware só preenche os escalares de saída.
    unsafe {
        (bs.get_memory_map)(
            &raw mut size,
            null_mut(),
            &raw mut key,
            &raw mut desc_size,
            &raw mut version,
        )
    };
    size + 16 * desc_size.max(size_of::<MemoryDescriptor>())
}

/// Converte os descritores de `raw` em `out` e normaliza; devolve quantos ficaram.
pub fn normalize(buf: &[u8], raw: &RawMap, out: &mut [MemRegion]) -> usize {
    let descs = buf[..raw.size].chunks_exact(raw.desc_size);
    let mut n = 0;
    for (slot, d) in out.iter_mut().zip(descs) {
        // SAFETY: cada bloco tem `desc_size >= size_of::<MemoryDescriptor>()`
        // bytes escritos pelo firmware; `read_unaligned` dispensa alinhamento.
        let d = unsafe { d.as_ptr().cast::<MemoryDescriptor>().read_unaligned() };
        *slot = MemRegion::new(d.physical_start, d.pages * 4096, kind(d.kind));
        n += 1;
    }
    kabi::boot::normalize(&mut out[..n])
}
