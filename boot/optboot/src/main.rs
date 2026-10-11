//! `optboot`: bootloader UEFI do Optimus OS.
//!
//! T-101: lê `\EFI\optimus\okernel.elf` da ESP de onde foi carregado, valida o
//! ELF64 com `oelf` e copia cada segmento para páginas físicas próprias.
//! T-102: monta a `BootInfo` v1 (`kabi::boot`) com mapa de memória, GOP, RSDP
//! e semente aleatória ([`firmware`]).
//! T-103: aplica KASLR ao kernel PIE ([`kernel`]), monta as tabelas de página
//! iniciais ([`paging`]), chama `ExitBootServices` e salta para
//! `kernel_entry(&BootInfo)` com interrupções desligadas.
//!
//! Só declara os campos da especificação UEFI 2.10 que usa; nenhuma crate externa
//! entra na imagem (ADR 0003).

#![no_std]
#![no_main]

mod arch;
mod firmware;
mod kernel;
mod paging;

use core::convert::Infallible;
use core::ffi::c_void;
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::ptr::{self, null_mut};

use kabi::boot::{BootInfo, CMDLINE_MAX, DIRECT_MAP_BASE, MemKind, MemRegion};

use arch::x86_64::{disable_interrupts, enter_kernel, rdtsc};
use firmware::{Entropy, KERNEL_MEMORY, RawMap};
use paging::{PageTables, STACK_BASE, STACK_BYTES, STACK_SIZE, Table};

type Status = usize;
type Handle = *mut c_void;

/// `EFI_GUID`.
#[derive(PartialEq, Eq)]
#[repr(C)]
struct Guid(u32, u16, u16, [u8; 8]);

/// `EFI_TABLE_HEADER`.
#[repr(C)]
struct TableHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
}

/// Início de `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL`.
#[repr(C)]
struct SimpleTextOutput {
    reset: usize,
    output_string: extern "efiapi" fn(this: *mut SimpleTextOutput, string: *const u16) -> Status,
}

/// Início de `EFI_RUNTIME_SERVICES`, até `ResetSystem`.
#[repr(C)]
struct RuntimeServices {
    hdr: TableHeader,
    unused: [usize; 10],
    reset_system:
        extern "efiapi" fn(kind: u32, status: Status, size: usize, data: *const c_void) -> !,
}

/// Início de `EFI_BOOT_SERVICES`, até `LocateProtocol`.
#[allow(clippy::struct_field_names, reason = "nomes da especificação UEFI")]
#[repr(C)]
struct BootServices {
    hdr: TableHeader,
    tpl: [usize; 2],
    allocate_pages:
        unsafe extern "efiapi" fn(kind: u32, mem: u32, pages: usize, addr: *mut u64) -> Status,
    free_pages: usize,
    get_memory_map: unsafe extern "efiapi" fn(
        size: *mut usize,
        map: *mut u8,
        key: *mut usize,
        desc_size: *mut usize,
        desc_version: *mut u32,
    ) -> Status,
    allocate_pool: unsafe extern "efiapi" fn(mem: u32, size: usize, buf: *mut *mut u8) -> Status,
    free_pool: usize,
    events: [usize; 6],
    protocol_interfaces: [usize; 3],
    handle_protocol:
        unsafe extern "efiapi" fn(h: Handle, guid: *const Guid, out: *mut *mut c_void) -> Status,
    reserved_to_unload_image: [usize; 9],
    exit_boot_services: unsafe extern "efiapi" fn(image: Handle, map_key: usize) -> Status,
    monotonic_count: usize,
    stall: unsafe extern "efiapi" fn(microseconds: usize) -> Status,
    watchdog_to_locate_handle_buffer: [usize; 8],
    locate_protocol: unsafe extern "efiapi" fn(
        guid: *const Guid,
        registration: *const c_void,
        out: *mut *mut c_void,
    ) -> Status,
}

/// `EFI_SYSTEM_TABLE`.
#[repr(C)]
struct SystemTable {
    hdr: TableHeader,
    firmware_vendor: *const u16,
    firmware_revision: u32,
    console_in_handle: Handle,
    con_in: *mut c_void,
    console_out_handle: Handle,
    con_out: *mut SimpleTextOutput,
    standard_error_handle: Handle,
    std_err: *mut c_void,
    runtime_services: *const RuntimeServices,
    boot_services: *const BootServices,
    number_of_table_entries: usize,
    configuration_table: *const c_void,
}

/// Início de `EFI_LOADED_IMAGE_PROTOCOL`, até `DeviceHandle`.
#[repr(C)]
struct LoadedImage {
    revision: u32,
    parent_handle: Handle,
    system_table: *const SystemTable,
    device_handle: Handle,
}

/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`.
#[repr(C)]
struct SimpleFileSystem {
    revision: u64,
    open_volume: unsafe extern "efiapi" fn(this: *mut Self, root: *mut *mut File) -> Status,
}

/// Início de `EFI_FILE_PROTOCOL`, até `SetPosition`.
#[repr(C)]
struct File {
    revision: u64,
    open: unsafe extern "efiapi" fn(
        this: *mut Self,
        new: *mut *mut Self,
        name: *const u16,
        mode: u64,
        attributes: u64,
    ) -> Status,
    close: unsafe extern "efiapi" fn(this: *mut Self) -> Status,
    delete: usize,
    read: unsafe extern "efiapi" fn(this: *mut Self, size: *mut usize, buf: *mut c_void) -> Status,
    write: usize,
    get_position: unsafe extern "efiapi" fn(this: *mut Self, pos: *mut u64) -> Status,
    set_position: unsafe extern "efiapi" fn(this: *mut Self, pos: u64) -> Status,
}

const LOADED_IMAGE_GUID: Guid = Guid(
    0x5b1b_31a1,
    0x9562,
    0x11d2,
    [0x8e, 0x3f, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
const SIMPLE_FS_GUID: Guid = Guid(
    0x964e_5b22,
    0x6459,
    0x11d2,
    [0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);

/// `EfiResetShutdown`.
const RESET_SHUTDOWN: u32 = 2;
/// `AllocateAnyPages`.
const ALLOCATE_ANY_PAGES: u32 = 0;
/// `EfiLoaderData`.
const LOADER_DATA: u32 = 2;
/// `EFI_FILE_MODE_READ`.
const FILE_MODE_READ: u64 = 1;

// TODO(boot A/B): ler de \EFI\optimus\slot-{a,b}\ e verificar as assinaturas
// híbridas (SDD 5.1, passos 2 e 3), em tarefa posterior ao backlog M0-M2.
const KERNEL_PATH: &str = "\\EFI\\optimus\\okernel.elf";
/// Teto do arquivo do kernel, contra ESPs com arquivos absurdos.
const MAX_KERNEL_SIZE: u64 = 64 << 20;
/// Linha de comando do kernel (opcional), texto UTF-8 de até 1 KiB.
const CMDLINE_PATH: &str = "\\EFI\\optimus\\cmdline.txt";

/// Falha ao carregar o kernel.
enum Error {
    /// Serviço UEFI devolveu erro.
    Efi(&'static str, Status),
    /// Arquivo vazio, grande demais ou lido pela metade.
    BadSize(u64),
    /// O ELF foi recusado.
    Elf(oelf::Error),
    /// Faltou tabela de página reservada ou houve mapeamento duplicado.
    Paging,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Efi(what, status) => write!(f, "{what} devolveu {status:#x}"),
            Self::BadSize(size) => write!(f, "tamanho inválido {size:#x}"),
            Self::Elf(e) => write!(f, "ELF inválido: {e:?}"),
            Self::Paging => f.write_str("erro ao montar as tabelas de página"),
        }
    }
}

fn efi(what: &'static str, status: Status) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Efi(what, status))
    }
}

/// Console UEFI, que o OVMF espelha na serial.
struct Console<'a>(&'a SystemTable);

impl Write for Console<'_> {
    /// Converte para UCS-2 em blocos terminados em zero.
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut buf = [0u16; 64];
        let mut len = 0;
        for unit in text.encode_utf16() {
            buf[len] = unit;
            len += 1;
            if len == buf.len() - 1 {
                self.flush(&mut buf, &mut len);
            }
        }
        self.flush(&mut buf, &mut len);
        Ok(())
    }
}

impl Console<'_> {
    fn flush(&self, buf: &mut [u16], len: &mut usize) {
        buf[*len] = 0;
        // SAFETY: o firmware entregou `con_out` válido e ele segue válido até
        // ExitBootServices, que esta versão nunca chama; `buf` termina em zero.
        unsafe { ((*self.0.con_out).output_string)(self.0.con_out, buf.as_ptr()) };
        *len = 0;
    }
}

/// Lê um arquivo inteiro e não vazio de até `max` bytes da ESP para um
/// buffer de pool que nunca é liberado.
fn read_file(
    bs: &BootServices,
    image: Handle,
    name: &str,
    max: u64,
) -> Result<&'static [u8], Error> {
    let mut path = [0u16; 32];
    for (dst, unit) in path.iter_mut().zip(name.encode_utf16()) {
        *dst = unit;
    }
    let (mut loaded, mut sfs, mut root, mut file) =
        (null_mut(), null_mut(), null_mut(), null_mut());
    // SAFETY: `image` é o handle desta aplicação, que tem LoadedImage.
    efi("LoadedImage", unsafe {
        (bs.handle_protocol)(image, &LOADED_IMAGE_GUID, &raw mut loaded)
    })?;
    // SAFETY: HandleProtocol devolveu uma interface LoadedImage válida.
    let device = unsafe { (*loaded.cast::<LoadedImage>()).device_handle };
    // SAFETY: `device` é o volume de onde o firmware leu o optboot.
    efi("SimpleFileSystem", unsafe {
        (bs.handle_protocol)(device, &SIMPLE_FS_GUID, &raw mut sfs)
    })?;
    let sfs = sfs.cast::<SimpleFileSystem>();
    // SAFETY: `sfs` é uma interface válida devolvida por HandleProtocol.
    efi("OpenVolume", unsafe {
        ((*sfs).open_volume)(sfs, &raw mut root)
    })?;
    // SAFETY: `root` foi aberto acima e `path` termina em zero.
    efi("Open", unsafe {
        ((*root).open)(root, &raw mut file, path.as_ptr(), FILE_MODE_READ, 0)
    })?;
    let mut size = 0;
    // SAFETY: `file` está aberto; u64::MAX leva ao fim do arquivo (UEFI 13.5).
    unsafe {
        efi("SetPosition", ((*file).set_position)(file, u64::MAX))?;
        efi("GetPosition", ((*file).get_position)(file, &raw mut size))?;
        efi("SetPosition", ((*file).set_position)(file, 0))?;
    }
    let len = usize::try_from(size)
        .ok()
        .filter(|&n| n > 0 && size <= max)
        .ok_or(Error::BadSize(size))?;
    let mut buf = null_mut();
    // SAFETY: AllocatePool só escreve o ponteiro devolvido em `buf`.
    efi("AllocatePool", unsafe {
        (bs.allocate_pool)(LOADER_DATA, len, &raw mut buf)
    })?;
    let mut done = 0;
    while done < len {
        let mut chunk = len - done;
        // SAFETY: `buf` tem `len` bytes e `done + chunk <= len`.
        efi("Read", unsafe {
            ((*file).read)(file, &raw mut chunk, buf.add(done).cast())
        })?;
        if chunk == 0 {
            return Err(Error::BadSize(done as u64));
        }
        done += chunk;
    }
    // SAFETY: `file` e `root` estão abertos e não são mais usados. Falha ao
    // fechar um arquivo só de leitura não afeta o que já foi lido.
    unsafe {
        ((*file).close)(file);
        ((*root).close)(root);
    }
    // SAFETY: Read preencheu os `len` bytes de `buf`, que fica alocado até o
    // kernel assumir a memória.
    Ok(unsafe { core::slice::from_raw_parts(buf, len) })
}

/// Vetor de `T` zerado em páginas físicas novas do tipo de memória `kind`,
/// com ao menos `count` elementos (o resto da última página também entra).
///
/// # Safety
///
/// Todos os bits zero precisam formar um `T` válido, e o alinhamento de `T`
/// não pode passar de 4 KiB.
unsafe fn alloc_zeroed<T>(
    bs: &BootServices,
    kind: u32,
    count: usize,
) -> Result<&'static mut [T], Error> {
    let pages = (count * size_of::<T>()).div_ceil(4096).max(1);
    let mut phys = 0;
    // SAFETY: AllocatePages só escreve o endereço devolvido em `phys`.
    efi("AllocatePages", unsafe {
        (bs.allocate_pages)(ALLOCATE_ANY_PAGES, kind, pages, &raw mut phys)
    })?;
    let start = usize::try_from(phys).map_err(|_| Error::BadSize(phys))?;
    let base = ptr::with_exposed_provenance_mut::<T>(start);
    // SAFETY: as páginas são só nossas, alinhadas a 4 KiB e mapeadas em
    // identidade pelo firmware; zero é um `T` válido (contrato do chamador).
    unsafe {
        base.cast::<u8>().write_bytes(0, pages * 4096);
        Ok(core::slice::from_raw_parts_mut(
            base,
            pages * 4096 / size_of::<T>(),
        ))
    }
}

/// Aloca a `BootInfo` e preenche o que vem do firmware (seção 5.1, passo 5).
fn gather(
    out: &mut Console,
    bs: &BootServices,
    st: &SystemTable,
) -> Result<&'static mut BootInfo, Error> {
    // SAFETY: `BootInfo` só tem inteiros e um ponteiro cru; zero é válido.
    let info = &mut unsafe { alloc_zeroed::<BootInfo>(bs, KERNEL_MEMORY, 1) }?[0];
    *info = BootInfo::empty();
    if let Some(fb) = firmware::framebuffer(bs) {
        let _ = write!(
            out,
            "optboot: GOP {}x{} em {:#x}\r\n",
            fb.width, fb.height, fb.base
        );
        info.framebuffer = fb;
    } else {
        let _ = out.write_str("optboot: sem GOP\r\n");
    }
    info.acpi_rsdp = firmware::acpi_rsdp(st).unwrap_or(0);
    let _ = write!(out, "optboot: RSDP {:#x}\r\n", info.acpi_rsdp);
    let source = firmware::entropy(bs, &mut info.rng_seed);
    if matches!(source, Entropy::TscOnly) {
        let _ = out.write_str("optboot: AVISO: sem RNG do firmware nem da CPU\r\n");
    }
    let _ = write!(out, "optboot: semente de 64 bytes via {source}\r\n");
    Ok(info)
}

/// Imprime o resumo do mapa de memória normalizado.
fn summarize(out: &mut Console, map: &[MemRegion]) {
    let total = |kind| -> u64 { map.iter().filter(|r| r.kind() == kind).map(|r| r.len).sum() };
    let _ = write!(
        out,
        "optboot: mapa de memória: {} regiões, {} KiB usáveis, {} KiB do kernel\r\n",
        map.len(),
        total(MemKind::Usable) >> 10,
        total(MemKind::Kernel) >> 10
    );
}

/// Frequência do TSC medida contra `Stall` de 10 ms.
fn tsc_hz(bs: &BootServices) -> u64 {
    let start = rdtsc();
    // SAFETY: Stall só espera; o firmware o oferece até ExitBootServices.
    unsafe { (bs.stall)(10_000) };
    (rdtsc() - start).saturating_mul(100).max(1)
}

/// Chama `ExitBootServices` com a chave do mapa lido logo antes. Se a chave
/// tiver mudado (o firmware alocou algo entre as chamadas), lê o mapa de novo
/// e tenta outra vez, como manda a especificação.
fn exit_boot_services(bs: &BootServices, image: Handle, buf: &mut [u8]) -> Result<RawMap, Error> {
    let mut status = 0;
    for _ in 0..4 {
        let raw = firmware::memory_map(bs, buf)?;
        // SAFETY: `image` é este optboot e `raw.key` veio do último GetMemoryMap.
        status = unsafe { (bs.exit_boot_services)(image, raw.key) };
        if status == 0 {
            return Ok(raw);
        }
    }
    Err(Error::Efi("ExitBootServices", status))
}

/// Endereço no mapa direto de algo que está na memória física com identidade.
fn direct<T: ?Sized>(object: &T) -> u64 {
    DIRECT_MAP_BASE + ptr::from_ref(object).addr() as u64
}

/// Carrega o kernel, monta `BootInfo` e tabelas de página, encerra os serviços
/// de boot e salta para `kernel_entry` (seção 5.1, passos 5 a 7). Só volta com
/// erro, e sempre antes de `ExitBootServices`.
fn boot(
    out: &mut Console,
    bs: &BootServices,
    st: &SystemTable,
    image: Handle,
) -> Result<Infallible, Error> {
    let file = read_file(bs, image, KERNEL_PATH, MAX_KERNEL_SIZE)?;
    let kernel = kernel::load(out, bs, file)?;
    let entry = kernel.entry();
    let _ = write!(out, "optboot: kernel carregado, entrada {entry:#x}\r\n");
    let info = gather(out, bs, st)?;
    info.kaslr_slide = kernel.slide;
    // Arquivo ausente, vazio ou inválido vale como linha de comando vazia.
    let cmdline = read_file(bs, image, CMDLINE_PATH, CMDLINE_MAX as u64)
        .ok()
        .and_then(|bytes| core::str::from_utf8(bytes).ok())
        .unwrap_or("");
    info.set_cmdline(cmdline.trim());
    let _ = write!(out, "optboot: cmdline \"{}\"\r\n", cmdline.trim());
    let hz = tsc_hz(bs);
    // Tudo o que precisa de memória é reservado agora: depois do último
    // GetMemoryMap não se pode mais alocar.
    let size = firmware::memory_map_size(bs);
    // SAFETY: zero é válido para bytes, `MemRegion` e `Table` (só inteiros).
    let (raw_buf, regions) = unsafe {
        (
            alloc_zeroed::<u8>(bs, LOADER_DATA, size)?,
            // Cada descritor UEFI tem ao menos 40 bytes; uma `MemRegion` tem 24.
            alloc_zeroed::<MemRegion>(bs, KERNEL_MEMORY, size / size_of::<MemRegion>())?,
        )
    };
    let raw = firmware::memory_map(bs, raw_buf)?;
    let n = firmware::normalize(raw_buf, &raw, regions);
    summarize(out, &regions[..n]);
    let limit = paging::identity_limit(&regions[..n]);
    let needed = paging::tables_needed(limit, kernel.size);
    // SAFETY: idem.
    let (stack, pool) = unsafe {
        (
            alloc_zeroed::<u8>(bs, KERNEL_MEMORY, STACK_BYTES)?,
            alloc_zeroed::<Table>(bs, KERNEL_MEMORY, needed)?,
        )
    };
    let mut tables = PageTables::new(pool);
    tables.map_physical(limit)?;
    for (virt, phys, len, flags) in kernel.mappings() {
        tables.map_range(virt, phys, len, flags.writable(), flags.executable())?;
    }
    let stack_phys = stack.as_ptr().addr() as u64;
    tables.map_range(STACK_BASE + 4096, stack_phys, STACK_SIZE, true, false)?;
    let _ = write!(
        out,
        "optboot: tabelas de página prontas, mapa direto até {limit:#x}; saindo dos serviços de boot\r\n"
    );
    let raw = exit_boot_services(bs, image, raw_buf)?;
    // Daqui em diante não há console nem serviços de boot: nada pode falhar.
    disable_interrupts();
    let n = firmware::normalize(raw_buf, &raw, regions);
    info.memory_map = ptr::with_exposed_provenance(usize::try_from(direct(regions)).unwrap_or(0));
    info.memory_map_len = n as u64;
    let ns = u128::from(rdtsc()) * 1_000_000_000 / u128::from(hz);
    info.boot_time_ns = u64::try_from(ns).unwrap_or(u64::MAX);
    let stack_top = STACK_BASE + 4096 + STACK_SIZE;
    // SAFETY: as tabelas mapeiam em identidade toda a RAM (onde estão o código
    // e a pilha do optboot), a imagem do kernel com `entry` executável e a pilha
    // gravável; os serviços de boot acabaram e as interrupções estão desligadas.
    unsafe { enter_kernel(tables.root(), stack_top, entry, direct(info)) }
}

/// Ponto de entrada chamado pelo firmware UEFI.
#[unsafe(export_name = "efi_main")]
extern "efiapi" fn efi_main(image: Handle, st: *const SystemTable) -> Status {
    // SAFETY: o firmware passa um ponteiro válido para a System Table.
    let st = unsafe { &*st };
    let mut out = Console(st);
    let _ = out.write_str("Optimus OS \u{2014} optboot\r\n");
    // SAFETY: `boot_services` vem da System Table e vale até ExitBootServices.
    let bs = unsafe { &*st.boot_services };
    let Err(e) = boot(&mut out, bs, st, image);
    let _ = write!(out, "optboot: erro: {e}\r\n");
    // SAFETY: `runtime_services` vem da System Table e é válido durante todo o boot.
    let rt = unsafe { &*st.runtime_services };
    (rt.reset_system)(RESET_SHUTDOWN, 0, 0, ptr::null())
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
