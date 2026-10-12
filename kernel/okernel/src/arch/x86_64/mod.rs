//! Suporte a x86-64: entrada, GDT/TSS/IDT, portas de E/S, serial, parada e
//! saída do QEMU.

use core::arch::{asm, global_asm};

pub mod ap;
pub mod apic;
pub mod cpu;
pub mod cpustate;
pub mod fpu;
pub mod gdt;
pub mod hpet;
pub mod idt;
pub mod percpu;
pub mod probe;
pub mod serial;
pub mod syscall;
mod tests;

pub use tests::TESTS;

global_asm!(include_str!("entry.S"));
global_asm!(include_str!("vectors.S"));
global_asm!(include_str!("probe.S"));
global_asm!(include_str!("syscall.S"));
global_asm!(include_str!("user.S"));
global_asm!(include_str!("ap.S"));

/// Instala a área por CPU do BSP (GDT, TSS e GS), carrega a IDT e liga
/// SYSCALL/SYSRET.
///
/// # Safety
///
/// Só pode rodar uma vez, no boot, com interrupções desligadas.
pub unsafe fn init() {
    // SAFETY: contrato acima, que é o de `percpu::init_bsp`, `idt::init` e
    // `syscall::init`; a GDT vem antes porque a IDT e o STAR usam os
    // seletores e as ISTs dela.
    unsafe {
        percpu::init_bsp();
        idt::init();
        syscall::init();
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

/// Reinicia a máquina: reset pela porta 0xcf9 (chipsets Intel e q35), pelo
/// controlador de teclado e, se nada disso funcionar, por falta tripla.
pub fn reset() -> ! {
    // SAFETY: 0xcf9 e 0x64 só pedem reset; a falta tripla com IDT vazia
    // também só reinicia. Nada depois disso precisa continuar.
    unsafe {
        outb(0xcf9, 0x02);
        outb(0xcf9, 0x06);
        outb(0x64, 0xfe);
        let empty = gdt::Pointer { limit: 0, base: 0 };
        asm!("lidt [{}]", "int3", in(reg) &raw const empty, options(nostack));
    }
    halt()
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
