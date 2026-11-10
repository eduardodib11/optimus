//! `in` e `out` nas portas que a thread ligou (ADR 0049). Sem a faixa no
//! mapa de E/S da TSS, a instrução dá `#GP` e o kernel trata como falta da
//! thread: nenhum efeito fora do que o kernel deixou.

use core::arch::asm;

/// Lê um byte da porta.
pub fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: `in` só lê a porta; sem permissão, a CPU recusa (`#GP`).
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags));
    };
    v
}

/// Escreve um byte na porta.
pub fn outb(port: u16, v: u8) {
    // SAFETY: como em `inb`; a porta é de um dispositivo, não da memória.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags));
    };
}

/// Lê 16 bits da porta.
pub fn inw(port: u16) -> u16 {
    let v: u16;
    // SAFETY: como em `inb`.
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack, preserves_flags));
    };
    v
}

/// Escreve 16 bits na porta.
pub fn outw(port: u16, v: u16) {
    // SAFETY: como em `outb`.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags));
    };
}

/// Lê 32 bits da porta.
pub fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: como em `inb`.
    unsafe {
        asm!("in eax, dx", in("dx") port, out("eax") v, options(nomem, nostack, preserves_flags));
    };
    v
}

/// Escreve 32 bits na porta.
pub fn outl(port: u16, v: u32) {
    // SAFETY: como em `outb`.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags));
    };
}
