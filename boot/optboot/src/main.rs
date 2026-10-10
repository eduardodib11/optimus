//! `optboot`: bootloader UEFI do Optimus OS.
//!
//! T-101: lê `\EFI\optimus\okernel.elf` da ESP de onde foi carregado, valida o
//! ELF64 com `oelf` e copia cada segmento para páginas físicas próprias. Tabelas
//! de página, `ExitBootServices` e o salto para o kernel vêm em T-103; por ora,
//! depois de carregar, desliga a máquina.
//!
//! Só declara os campos da especificação UEFI 2.10 que usa; nenhuma crate externa
//! entra na imagem (ADR 0003).

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::ptr::{self, null_mut};

use oelf::{Elf, PAGE_SIZE};

type Status = usize;
type Handle = *mut c_void;

/// `EFI_GUID`.
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

/// Início de `EFI_BOOT_SERVICES`, até `HandleProtocol`.
#[repr(C)]
struct BootServices {
    hdr: TableHeader,
    tpl: [usize; 2],
    allocate_pages:
        unsafe extern "efiapi" fn(kind: u32, mem: u32, pages: usize, addr: *mut u64) -> Status,
    free_pages_and_memory_map: [usize; 2],
    allocate_pool: unsafe extern "efiapi" fn(mem: u32, size: usize, buf: *mut *mut u8) -> Status,
    free_pool: usize,
    events: [usize; 6],
    protocol_interfaces: [usize; 3],
    handle_protocol:
        unsafe extern "efiapi" fn(h: Handle, guid: *const Guid, out: *mut *mut c_void) -> Status,
}

/// Início de `EFI_SYSTEM_TABLE`, até `BootServices`.
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
/// `EfiLoaderCode` e `EfiLoaderData`.
const LOADER_CODE: u32 = 1;
const LOADER_DATA: u32 = 2;
/// `EFI_FILE_MODE_READ`.
const FILE_MODE_READ: u64 = 1;

// TODO(boot A/B): ler de \EFI\optimus\slot-{a,b}\ e verificar as assinaturas
// híbridas (SDD 5.1, passos 2 e 3), em tarefa posterior ao backlog M0-M2.
const KERNEL_PATH: &str = "\\EFI\\optimus\\okernel.elf";
/// Teto do arquivo do kernel, contra ESPs com arquivos absurdos.
const MAX_KERNEL_SIZE: u64 = 64 << 20;

/// Falha ao carregar o kernel.
enum Error {
    /// Serviço UEFI devolveu erro.
    Efi(&'static str, Status),
    /// Arquivo vazio, grande demais ou lido pela metade.
    BadSize(u64),
    /// O ELF foi recusado.
    Elf(oelf::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Efi(what, status) => write!(f, "{what} devolveu {status:#x}"),
            Self::BadSize(size) => write!(f, "tamanho inválido {size:#x}"),
            Self::Elf(e) => write!(f, "ELF inválido: {e:?}"),
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

/// Lê o kernel inteiro para um buffer de pool que nunca é liberado.
fn read_kernel(bs: &BootServices, image: Handle) -> Result<&'static [u8], Error> {
    let mut path = [0u16; 32];
    for (dst, unit) in path.iter_mut().zip(KERNEL_PATH.encode_utf16()) {
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
        .filter(|&n| n > 0 && size <= MAX_KERNEL_SIZE)
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

/// Copia cada `PT_LOAD` para páginas físicas novas e zera o resto (BSS).
fn load_segments(out: &mut Console, bs: &BootServices, elf: &Elf) -> Result<(), Error> {
    for seg in elf.segments() {
        let offset = seg.vaddr % PAGE_SIZE;
        let pages = (offset + seg.memsz).div_ceil(PAGE_SIZE);
        let bytes = usize::try_from(pages * PAGE_SIZE).map_err(|_| Error::BadSize(seg.memsz))?;
        let kind = if seg.flags.executable() {
            LOADER_CODE
        } else {
            LOADER_DATA
        };
        let mut phys = 0;
        // SAFETY: AllocatePages só escreve o endereço devolvido em `phys`.
        efi("AllocatePages", unsafe {
            (bs.allocate_pages)(ALLOCATE_ANY_PAGES, kind, bytes / 4096, &raw mut phys)
        })?;
        let start = usize::try_from(phys).map_err(|_| Error::BadSize(phys))?;
        // SAFETY: AllocatePages reservou `bytes` bytes em `phys` só para nós, e o
        // firmware mapeia a memória física em identidade até ExitBootServices.
        let dst = unsafe {
            core::slice::from_raw_parts_mut(ptr::with_exposed_provenance_mut::<u8>(start), bytes)
        };
        dst.fill(0);
        let at = usize::try_from(offset).unwrap_or_default();
        if let Some(slot) = dst.get_mut(at..at + seg.data.len()) {
            slot.copy_from_slice(seg.data);
        }
        let _ = write!(
            out,
            "optboot: seg {:#x} -> {:#x} {:#x} {}\r\n",
            seg.vaddr,
            phys + offset,
            seg.memsz,
            seg.flags
        );
    }
    Ok(())
}

fn load_kernel(out: &mut Console, bs: &BootServices, image: Handle) -> Result<u64, Error> {
    let file = read_kernel(bs, image)?;
    let elf = Elf::parse(file).map_err(Error::Elf)?;
    load_segments(out, bs, &elf)?;
    Ok(elf.entry())
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
    let _ = match load_kernel(&mut out, bs, image) {
        Ok(entry) => write!(out, "optboot: kernel carregado, entrada {entry:#x}\r\n"),
        Err(e) => write!(out, "optboot: erro ao carregar o kernel: {e}\r\n"),
    };
    // TODO(T-103): tabelas de página, ExitBootServices e salto para kernel_entry.
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
