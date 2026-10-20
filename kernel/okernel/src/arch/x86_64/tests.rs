//! Testes de kernel de x86-64 (T-111): o que a CPU carregou confere com as
//! tabelas do kernel.

use core::arch::asm;

use super::gdt::{self, KERNEL_CODE, Pointer};
use super::{cpu, idt, percpu, syscall};
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
    Test {
        name: "arch.sysret_volta_com_os_seletores_de_usuario",
        run: seletores_da_sysret,
    },
    Test {
        name: "percpu.bsp_e_a_cpu_zero",
        run: bsp_e_a_cpu_zero,
    },
    Test {
        name: "percpu.tss_e_ists_sao_desta_cpu",
        run: tss_e_ists_desta_cpu,
    },
];

fn bsp_e_a_cpu_zero() -> Outcome {
    ensure!(percpu::cpu_id() == 0);
    let (id, apic_id, online) = percpu::with(|p| (p.cpu_id(), p.apic_id(), p.online()));
    ensure!(id == 0 && online);
    ensure!(apic_id == super::apic::id_and_version().0);
    let gs = gs_base();
    // SAFETY: `gs:[0]` é o endereço da própria área.
    let this: u64;
    unsafe { asm!("mov {}, gs:[0]", out(reg) this, options(nostack, readonly)) };
    ensure!(gs == this && gs.is_multiple_of(4096));
    Ok(())
}

fn tss_e_ists_desta_cpu() -> Outcome {
    let (gdt, tss) = percpu::with(|p| (p.gdt_addr(), p.tss_addr()));
    // SAFETY: a GDT desta CPU tem 8 entradas; as 6 e 7 são o descritor da
    // TSS, e a TSS tem os topos IST nos bytes 36 a 92.
    let (low, high, ist) = unsafe {
        let g = gdt as *const u64;
        let ist = (tss as *const u8)
            .add(36)
            .cast::<[u64; 3]>()
            .read_unaligned();
        (g.add(6).read(), g.add(7).read(), ist)
    };
    let base = ((low >> 16) & 0xff_ffff) | (((low >> 56) & 0xff) << 24) | (high << 32);
    ensure!(base == tss);
    for top in ist {
        ensure!(top % 16 == 0);
        // SAFETY: `top` é o rsp inicial de uma pilha IST preparada.
        let owner = unsafe { percpu::from_ist_rsp(top - 64) };
        ensure!(core::ptr::from_ref(owner).addr() as u64 == gs_base());
    }
    Ok(())
}

fn gs_base() -> u64 {
    // SAFETY: ler GS_BASE só lê um MSR.
    unsafe { super::cpu::rdmsr(0xc000_0101) }
}

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
    ensure!(
        gdt_base == percpu::with(percpu::PerCpu::gdt_addr)
            && usize::from(gdt_limit) == gdt::GDT_ENTRIES * 8 - 1
    );
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

/// O STAR desta CPU dá à SYSRET os seletores de usuário com RPL 3, nos dois
/// fabricantes: a AMD copia o RPL do STAR para o SS, sem forçá-lo.
fn seletores_da_sysret() -> Outcome {
    // SAFETY: o STAR existe em toda CPU x86-64; ler não tem efeito.
    let star = unsafe { cpu::rdmsr(syscall::MSR_STAR) };
    #[allow(clippy::cast_possible_truncation, reason = "campo de 16 bits do STAR")]
    let base = (star >> 48) as u16;
    ensure!(base + 8 == gdt::USER_DATA && base + 16 == gdt::USER_CODE);
    #[allow(clippy::cast_possible_truncation, reason = "campo de 16 bits do STAR")]
    let kernel = (star >> 32) as u16;
    ensure!(kernel == KERNEL_CODE);
    Ok(())
}
