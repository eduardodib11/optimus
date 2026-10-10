//! `optboot`: bootloader UEFI do Optimus OS.
//!
//! Versão mínima (T-007): escreve a saudação no console UEFI, que o OVMF espelha
//! na serial, e desliga a máquina. Verificar e carregar o kernel vem no M1 (T-101).
//!
//! Só declara os campos da especificação UEFI 2.10 que usa; nenhuma crate externa
//! entra na imagem (ADR 0003).

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

type Status = usize;
type Handle = *mut c_void;

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

/// Início de `EFI_SYSTEM_TABLE`, até `RuntimeServices`.
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
}

/// `EfiResetShutdown`.
const RESET_SHUTDOWN: u32 = 2;

/// Escreve `text` no console de saída, convertendo para UCS-2 em blocos.
fn print(st: &SystemTable, text: &str) {
    let mut buf = [0u16; 64];
    let mut len = 0;
    for unit in text.encode_utf16() {
        buf[len] = unit;
        len += 1;
        if len == buf.len() - 1 {
            flush(st, &mut buf, &mut len);
        }
    }
    flush(st, &mut buf, &mut len);
}

fn flush(st: &SystemTable, buf: &mut [u16], len: &mut usize) {
    buf[*len] = 0;
    // SAFETY: o firmware entregou `con_out` válido e ele segue válido até
    // ExitBootServices, que esta versão nunca chama; `buf` termina em zero.
    unsafe { ((*st.con_out).output_string)(st.con_out, buf.as_ptr()) };
    *len = 0;
}

/// Ponto de entrada chamado pelo firmware UEFI.
#[unsafe(export_name = "efi_main")]
extern "efiapi" fn efi_main(_image: Handle, st: *const SystemTable) -> Status {
    // SAFETY: o firmware passa um ponteiro válido para a System Table.
    let st = unsafe { &*st };
    print(st, "Optimus OS \u{2014} optboot\r\n");
    // SAFETY: `runtime_services` vem da System Table e é válido durante todo o boot.
    let rt = unsafe { &*st.runtime_services };
    (rt.reset_system)(RESET_SHUTDOWN, 0, 0, core::ptr::null())
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
