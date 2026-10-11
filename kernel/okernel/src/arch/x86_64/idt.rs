//! IDT e tratadores das exceções 0 a 31 (T-105).
//!
//! Toda exceção despeja os registradores na serial e congela a CPU: o kernel
//! nunca segue em estado inconsistente (SDD v1.0, seção 6.5). Faltas de
//! usuário viram mensagens ao endpoint de exceções em T-210; o registro
//! persistente e a reinicialização do pânico vêm em T-110.

#![allow(
    clippy::cast_possible_truncation,
    reason = "descritores x86 repartem endereços e limites em campos de 16 e 32 bits"
)]

use core::arch::asm;
use core::fmt::Write;
use core::mem::size_of;

use super::gdt::{IST_DOUBLE_FAULT, IST_MACHINE_CHECK, IST_NMI, KERNEL_CODE, Pointer};
use super::halt;
use super::serial::Serial;

/// Quadro montado por `isr_common` (`vectors.S`), na ordem da memória.
#[repr(C)]
pub struct TrapFrame {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    vector: u64,
    error: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

/// Entrada de 16 bytes da IDT.
#[derive(Clone, Copy)]
#[repr(C)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

/// Porta de interrupção de 64 bits, presente, anel 0 (desliga IF na entrada).
const INTERRUPT_GATE: u8 = 0x8e;

impl Gate {
    const EMPTY: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        attributes: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn new(handler: u64, ist: u8) -> Self {
        Self {
            offset_low: handler as u16,
            selector: KERNEL_CODE,
            ist,
            attributes: INTERRUPT_GATE,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

static mut IDT: [Gate; 256] = [Gate::EMPTY; 256];

unsafe extern "C" {
    /// Endereços das portas 0 a 31, definidos em `vectors.S`.
    static isr_table: [u64; 32];
}

/// Mnemônico e descrição de cada exceção (Intel SDM vol. 3, tabela 6-1).
const NAMES: [(&str, &str); 32] = [
    ("#DE", "divisão por zero"),
    ("#DB", "depuração"),
    ("NMI", "interrupção não mascarável"),
    ("#BP", "breakpoint"),
    ("#OF", "overflow"),
    ("#BR", "BOUND fora da faixa"),
    ("#UD", "opcode inválido"),
    ("#NM", "dispositivo indisponível"),
    ("#DF", "falta dupla"),
    ("---", "segment overrun do coprocessador"),
    ("#TS", "TSS inválida"),
    ("#NP", "segmento ausente"),
    ("#SS", "falta de segmento de pilha"),
    ("#GP", "proteção geral"),
    ("#PF", "falta de página"),
    ("---", "reservada"),
    ("#MF", "erro de ponto flutuante x87"),
    ("#AC", "verificação de alinhamento"),
    ("#MC", "verificação de máquina"),
    ("#XM", "exceção SIMD"),
    ("#VE", "exceção de virtualização"),
    ("#CP", "proteção de controle de fluxo"),
    ("---", "reservada"),
    ("---", "reservada"),
    ("---", "reservada"),
    ("---", "reservada"),
    ("---", "reservada"),
    ("---", "reservada"),
    ("#HV", "injeção do hipervisor"),
    ("#VC", "comunicação com VMM"),
    ("#SX", "segurança"),
    ("---", "reservada"),
];

/// Preenche as portas 0 a 31 e carrega a IDT.
///
/// # Safety
///
/// Só pode rodar uma vez, no boot, com interrupções desligadas e depois de
/// [`super::gdt::init`] (as portas usam o seletor e as ISTs dela).
pub unsafe fn init() {
    // SAFETY: contrato acima; `isr_table` é só leitura e foi relocada pelo
    // optboot, e ninguém mais acessa `IDT` agora.
    unsafe {
        let idt = &raw mut IDT;
        for (vector, &handler) in isr_table.iter().enumerate() {
            let ist = match vector {
                2 => IST_NMI,
                8 => IST_DOUBLE_FAULT,
                18 => IST_MACHINE_CHECK,
                _ => 0,
            };
            (*idt)[vector] = Gate::new(handler, ist);
        }
        let pointer = Pointer {
            limit: (size_of::<[Gate; 256]>() - 1) as u16,
            base: idt.addr() as u64,
        };
        asm!("lidt [{}]", in(reg) &raw const pointer, options(nostack));
    }
}

/// Lê CR0, CR2, CR3 e CR4.
fn control_registers() -> [u64; 4] {
    let (cr0, cr2, cr3, cr4): (u64, u64, u64, u64);
    // SAFETY: ler registradores de controle no anel 0 não tem efeito colateral.
    unsafe {
        asm!(
            "mov {}, cr0", "mov {}, cr2", "mov {}, cr3", "mov {}, cr4",
            out(reg) cr0, out(reg) cr2, out(reg) cr3, out(reg) cr4,
            options(nomem, nostack),
        );
    }
    [cr0, cr2, cr3, cr4]
}

/// Chamado por `isr_common`: despeja o estado da CPU na serial e congela.
#[unsafe(no_mangle)]
extern "sysv64" fn exception_handler(frame: &TrapFrame) -> ! {
    let f = frame;
    let (name, what) = usize::try_from(f.vector)
        .ok()
        .and_then(|v| NAMES.get(v))
        .copied()
        .unwrap_or(("???", "vetor desconhecido"));
    let [cr0, cr2, cr3, cr4] = control_registers();
    let regs = [
        ("rax", f.rax),
        ("rbx", f.rbx),
        ("rcx", f.rcx),
        ("rdx", f.rdx),
        ("rsi", f.rsi),
        ("rdi", f.rdi),
        ("rbp", f.rbp),
        ("r8 ", f.r8),
        ("r9 ", f.r9),
        ("r10", f.r10),
        ("r11", f.r11),
        ("r12", f.r12),
        ("r13", f.r13),
        ("r14", f.r14),
        ("r15", f.r15),
        ("cr0", cr0),
        ("cr2", cr2),
        ("cr3", cr3),
        ("cr4", cr4),
    ];
    // Escreve direto na serial, sem a trava do logger: quem a segurava pode
    // ter sido justamente o código que faltou.
    let mut out = Serial::com1();
    let _ = writeln!(
        out,
        "okernel: FALTA {name} ({what}), vetor {}, erro {:#x}",
        f.vector, f.error
    );
    let _ = writeln!(
        out,
        "  rip {:#018x}  cs  {:#06x}  rflags {:#010x}\n  rsp {:#018x}  ss  {:#06x}",
        f.rip, f.cs, f.rflags, f.rsp, f.ss
    );
    for (i, (reg, value)) in regs.iter().enumerate() {
        let _ = write!(out, "  {reg} {value:#018x}");
        if i % 4 == 3 || i == regs.len() - 1 {
            let _ = writeln!(out);
        }
    }
    let _ = writeln!(out, "okernel: CPU congelada");
    halt()
}
