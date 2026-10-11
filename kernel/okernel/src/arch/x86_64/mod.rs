//! Suporte a x86-64: entrada, GDT/TSS/IDT, portas de E/S, serial, parada e
//! saída do QEMU.

use core::arch::{asm, global_asm};

pub mod gdt;
pub mod idt;
pub mod serial;

global_asm!(include_str!("entry.S"));
global_asm!(include_str!("vectors.S"));

/// Carrega GDT, TSS e IDT.
///
/// # Safety
///
/// Só pode rodar uma vez, no boot, com interrupções desligadas.
pub unsafe fn init() {
    // SAFETY: contrato acima, que é o de `gdt::init` e `idt::init`; a GDT
    // vem antes porque a IDT usa o seletor de código e as ISTs dela.
    unsafe {
        gdt::init();
        idt::init();
    }
}

/// Executa `ud2` para provocar a exceção #UD (teste do T-105).
pub fn trigger_invalid_opcode() {
    // SAFETY: UD2 só levanta #UD, que o tratador da IDT despeja e congela.
    unsafe { asm!("ud2", options(nomem, nostack)) };
}

/// Porta do dispositivo `isa-debug-exit` do QEMU (`iobase=0xf4`).
const QEMU_EXIT_PORT: u16 = 0xf4;

/// Código de saída pedido ao QEMU; o processo termina com `(código << 1) | 1`.
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum QemuExit {
    /// Termina com 33.
    Success = 0x10,
    /// Termina com 35.
    Failure = 0x11,
}

/// Escreve um byte numa porta de E/S.
///
/// # Safety
///
/// A escrita precisa ser válida para o dispositivo em `port`.
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: contrato do chamador; OUT não acessa memória.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack)) };
}

/// Lê um byte de uma porta de E/S.
///
/// # Safety
///
/// A leitura precisa ser válida (e sem efeito indesejado) para `port`.
pub unsafe fn inb(port: u16) -> u8 {
    let value;
    // SAFETY: contrato do chamador; IN não acessa memória.
    unsafe { asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack)) };
    value
}

/// Para a CPU para sempre, com interrupções desligadas.
pub fn halt() -> ! {
    loop {
        // SAFETY: CLI e HLT só param esta CPU; nada depende dela continuar.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Desliga o QEMU pelo `isa-debug-exit`; fora do QEMU, para a CPU.
pub fn qemu_exit(code: QemuExit) -> ! {
    // SAFETY: escrever em 0xf4 só tem efeito com o `isa-debug-exit` do QEMU;
    // em hardware real a porta não é usada.
    unsafe {
        asm!("out dx, eax", in("dx") QEMU_EXIT_PORT, in("eax") code as u32,
             options(nomem, nostack));
    }
    halt()
}
