//! Testes de kernel da memória (T-107): W^X, NX, identidade removida,
//! endurecimento da CPU e mapeamentos sobre frames do buddy.

use okernel::mm::PhysAddr;
use okernel::mm::paging::{Flags, PageSize};

use super::{
    alloc_frames, direct, for_each_leaf, frame_stats, free_frames, hardening_features,
    kernel_rodata, kernel_text, map, protect, translate, unmap,
};
use crate::arch::x86_64::cpu;
use crate::arch::x86_64::probe::{self, Fault, PF_FETCH, PF_PRESENT, PF_WRITE};
use crate::ktest::{Outcome, Test};

mod smp;

/// Testes de kernel da memória.
pub const TESTS: &[Test] = &[
    Test {
        name: "mm.escrita_em_codigo_gera_pf",
        run: escrita_em_codigo,
    },
    Test {
        name: "mm.escrita_em_rodata_gera_pf",
        run: escrita_em_rodata,
    },
    Test {
        name: "mm.texto_so_leitura_no_mapa_direto",
        run: texto_no_mapa_direto,
    },
    Test {
        name: "mm.dados_e_pilha_nao_executaveis",
        run: dados_e_pilha_nx,
    },
    Test {
        name: "mm.identidade_temporaria_removida",
        run: identidade_removida,
    },
    Test {
        name: "mm.w_xor_x_em_todo_o_espaco",
        run: w_xor_x,
    },
    Test {
        name: "mm.endurecimento_da_cpu",
        run: endurecimento,
    },
    Test {
        name: "mm.folhas_do_kernel_globais",
        run: kernel_global,
    },
    Test {
        name: "mm.buddy_aloca_e_libera",
        run: buddy,
    },
    Test {
        name: "mm.mapear_proteger_desmapear",
        run: mapear_proteger_desmapear,
    },
    Test {
        name: "mm.frames_concorrentes_sem_perda_nem_repeticao",
        run: smp::frames_concorrentes,
    },
    Test {
        name: "mm.frames_escala_de_1_a_4_cpus",
        run: smp::escala,
    },
];

/// Área de teste dentro da faixa de objetos do kernel (seção 6.4).
const TEST_VA: u64 = 0xffff_c0ff_ff00_0000;

static RODATA: [u8; 4] = [0x5a; 4];
static mut RET: [u8; 1] = [0xc3];

/// Regrava o byte que já está em `addr`, esperando uma falta de proteção.
fn write_fault(addr: u64) -> Result<Fault, &'static str> {
    let byte = probe::read_byte(addr).map_err(|_| "leitura faltou")?;
    // SAFETY: regrava o mesmo valor; se a escrita passar, nada muda.
    match unsafe { probe::write_byte(addr, byte) } {
        Ok(()) => Err("a escrita passou"),
        Err(f) => Ok(f),
    }
}

fn is_write_pf(f: Fault, addr: u64) -> bool {
    f.vector == 14 && f.error & (PF_PRESENT | PF_WRITE) == PF_PRESENT | PF_WRITE && f.addr == addr
}

fn escrita_em_codigo() -> Outcome {
    let target = escrita_em_codigo as *const () as u64;
    let (start, end) = kernel_text();
    ensure!((start..end).contains(&target));
    let fault = write_fault(target)?;
    ensure!(is_write_pf(fault, target));
    Ok(())
}

fn escrita_em_rodata() -> Outcome {
    let target = RODATA.as_ptr().addr() as u64 + 1;
    let (start, end) = kernel_rodata();
    ensure!((start..end).contains(&target));
    ensure!(is_write_pf(write_fault(target)?, target));
    Ok(())
}

fn texto_no_mapa_direto() -> Outcome {
    let code = escrita_em_codigo as *const () as u64;
    let alias = direct(translate(code).ok_or("texto sem mapeamento")?.phys);
    ensure!(translate(alias).is_some_and(|m| !m.flags.write && !m.flags.exec));
    ensure!(is_write_pf(write_fault(alias)?, alias));
    Ok(())
}

fn dados_e_pilha_nx() -> Outcome {
    let ret_on_stack = core::hint::black_box([0xc3u8; 1]);
    for target in [
        (&raw const RET).addr() as u64,
        ret_on_stack.as_ptr().addr() as u64,
    ] {
        // SAFETY: o destino contém só `ret`; se executar, volta na hora.
        let fault = unsafe { probe::exec(target) }.err().ok_or("executou")?;
        ensure!(fault.vector == 14 && fault.error & PF_FETCH != 0 && fault.addr == target);
    }
    Ok(())
}

fn identidade_removida() -> Outcome {
    for addr in [0x10_0000, 0x1000_0000] {
        let fault = probe::read_byte(addr)
            .err()
            .ok_or("leitura em identidade passou")?;
        ensure!(fault.vector == 14 && fault.error & PF_PRESENT == 0 && fault.addr == addr);
    }
    Ok(())
}

fn w_xor_x() -> Outcome {
    let (start, end) = kernel_text();
    let (mut leaves, mut low, mut wx, mut stray_exec) = (0, 0, 0, 0);
    for_each_leaf(&mut |virt, m| {
        leaves += 1;
        low += usize::from(virt >> 63 == 0);
        wx += usize::from(m.flags.write && m.flags.exec);
        let in_text = virt >= start && virt + m.size.bytes() <= end.next_multiple_of(4096);
        stray_exec += usize::from(m.flags.exec && !in_text);
    });
    ensure!(leaves > 0);
    ensure!(low == 0);
    ensure!(wx == 0);
    ensure!(stray_exec == 0);
    Ok(())
}

fn endurecimento() -> Outcome {
    let cr4 = cpu::read_cr4();
    for (_, present, bit) in hardening_features() {
        ensure!((cr4 & bit != 0) == present);
    }
    // SAFETY: EFER existe em toda CPU x86-64.
    ensure!(unsafe { cpu::rdmsr(cpu::MSR_EFER) } & cpu::EFER_NXE != 0);
    ensure!(cpu::read_cr0() & cpu::CR0_WP != 0);
    Ok(())
}

/// Toda folha do kernel é global e o CR4.PGE está ligado (ADR 0031, item
/// 7), inclusive a mapeada depois do boot.
fn kernel_global() -> Outcome {
    ensure!(cpu::read_cr4() & (1 << 7) != 0);
    let (mut leaves, mut local) = (0, 0);
    for_each_leaf(&mut |_, m| {
        leaves += 1;
        local += usize::from(!m.flags.global);
    });
    ensure!(leaves > 0 && local == 0);
    let frame = alloc_frames(0).ok_or("sem frames")?;
    ensure!(map(TEST_VA, frame, PageSize::Size4K, Flags::RW).is_ok());
    let global = translate(TEST_VA).is_some_and(|m| m.flags.global);
    ensure!(protect(TEST_VA, PageSize::Size4K, Flags::READ).is_ok());
    let still = translate(TEST_VA).is_some_and(|m| m.flags.global);
    ensure!(unmap(TEST_VA, PageSize::Size4K) == Ok(frame));
    free_frames(frame, 0);
    ensure!(global && still);
    Ok(())
}

fn buddy() -> Outcome {
    let before = frame_stats();
    ensure!(before.0 > 0);
    let blocks = [0, 1, 5].map(|order| (alloc_frames(order), order));
    for (frame, order) in blocks {
        let frame = frame.ok_or("sem frames")?;
        ensure!(frame.0.is_multiple_of(4096 << order));
    }
    ensure!(frame_stats().0 == before.0 - (1 + 2 + 32));
    for (frame, order) in blocks {
        free_frames(frame.unwrap_or(PhysAddr(0)), order);
    }
    ensure!(frame_stats() == before);
    Ok(())
}

fn mapear_proteger_desmapear() -> Outcome {
    for (size, order) in [(PageSize::Size4K, 0), (PageSize::Size2M, 9)] {
        let frame = alloc_frames(order).ok_or("sem frames")?;
        let virt = TEST_VA + (2 << 20) * u64::from(order == 9);
        let addr = virt + size.bytes() - 1;
        ensure!(map(virt, frame, size, Flags::RW).is_ok());
        // SAFETY: a página é do teste e acabou de ser mapeada gravável.
        ensure!(unsafe { probe::write_byte(addr, 0xab) }.is_ok());
        ensure!(probe::read_byte(addr) == Ok(0xab));
        ensure!(probe::read_byte(direct(frame) + size.bytes() - 1) == Ok(0xab));
        ensure!(protect(virt, size, Flags::READ).is_ok());
        ensure!(is_write_pf(write_fault(addr)?, addr));
        ensure!(unmap(virt, size) == Ok(frame));
        let fault = probe::read_byte(addr)
            .err()
            .ok_or("leitura depois de desmapear passou")?;
        ensure!(fault.error & PF_PRESENT == 0 && fault.addr == addr);
        free_frames(frame, order);
    }
    Ok(())
}
