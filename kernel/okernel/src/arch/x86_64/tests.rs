//! Testes de kernel de x86-64 (T-111): o que a CPU carregou confere com as
//! tabelas do kernel.

use core::arch::asm;

use super::gdt::{self, KERNEL_CODE, Pointer};
use super::idt;
use crate::ktest::{Outcome, Test};

/// Testes de kernel de x86-64.
pub const TESTS: &[Test] = &[
    Test {
        name: "arch.gdt_idt_e_tss_carregadas",
        run: tabelas_carregadas,
    },
    Test {
        name: "arch.segmento_de_codigo_do_kernel",
        run: segmento_de_codigo,
    },
];

fn tabelas_carregadas() -> Outcome {
    let mut gdtr = Pointer { limit: 0, base: 0 };
    let mut idtr = Pointer { limit: 0, base: 0 };
    let tr: u16;
    // SAFETY: SGDT, SIDT e STR só gravam nos operandos dados.
    unsafe {
        asm!(
            "sgdt [{g}]", "sidt [{i}]", "str {t:x}",
            g = in(reg) &raw mut gdtr,
            i = in(reg) &raw mut idtr,
            t = out(reg) tr,
            options(nostack),
        );
    }
    let (gdt_base, gdt_limit) = (gdtr.base, gdtr.limit);
    let (idt_base, idt_limit) = (idtr.base, idtr.limit);
    ensure!(gdt_base == gdt::table_addr() && usize::from(gdt_limit) == gdt::GDT_ENTRIES * 8 - 1);
    ensure!(idt_base == idt::table_addr() && idt_limit == 256 * 16 - 1);
    ensure!(tr == gdt::TSS_SELECTOR);
    Ok(())
}

fn segmento_de_codigo() -> Outcome {
    let cs: u16;
    // SAFETY: ler CS não tem efeito colateral.
    unsafe { asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack)) };
    ensure!(cs == KERNEL_CODE);
    Ok(())
}
