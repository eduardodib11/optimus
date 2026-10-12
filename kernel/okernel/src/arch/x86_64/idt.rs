//! IDT e tratadores das exceções 0 a 31 (T-105) e das interrupções 32 a 255
//! (T-109, despachadas para [`super::apic::dispatch`]).
//!
//! Toda exceção despeja os registradores na serial e congela a CPU: o kernel
//! nunca segue em estado inconsistente (SDD v1.0, seção 6.5). A única
//! exceção são as faltas das sondas de memória ([`super::probe`]), que voltam
//! a quem sondou com a falta registrada, e as exceções vindas do anel 3,
//! que viram mensagens ao endpoint de exceções da thread (T-210,
//! [`crate::kfault`]). O registro persistente e a reinicialização do
//! pânico vêm em T-110.

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
#[allow(missing_docs, reason = "registradores salvos, na ordem do quadro")]
#[derive(Clone, Copy, Default)]
pub struct TrapFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
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
    /// Portas dos vetores 32 a 255, 16 bytes cada.
    static irq_stubs: u8;
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

/// Mnemônico e descrição da exceção `vector`.
pub fn exception_name(vector: u64) -> (&'static str, &'static str) {
    usize::try_from(vector)
        .ok()
        .and_then(|v| NAMES.get(v))
        .copied()
        .unwrap_or(("???", "vetor desconhecido"))
}

/// Preenche as portas 0 a 255 e carrega a IDT (uma só, imutável depois do
/// boot).
///
/// # Safety
///
/// Só pode rodar uma vez, no boot, com interrupções desligadas e depois de
/// [`super::percpu::init_bsp`] (as portas usam o seletor e as ISTs da GDT).
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
        let stubs = (&raw const irq_stubs).addr() as u64;
        for vector in 32..256 {
            (*idt)[vector] = Gate::new(stubs + (vector as u64 - 32) * 16, 0);
        }
        let pointer = Pointer {
            limit: (size_of::<[Gate; 256]>() - 1) as u16,
            base: idt.addr() as u64,
        };
        asm!("lidt [{}]", in(reg) &raw const pointer, options(nostack));
    }
}

/// Endereço virtual da IDT, para conferir o que a CPU carregou.
pub fn table_addr() -> u64 {
    (&raw const IDT).addr() as u64
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

/// Chamado por `isr_common`: retoma a falta de uma sonda ou despeja o estado
/// da CPU na serial e congela.
#[unsafe(no_mangle)]
extern "sysv64" fn exception_handler(frame: &mut TrapFrame) {
    if frame.vector >= 32 {
        if crate::kirq::fire(frame.vector) {
            // Linha de um objeto `Interrupt` (T-209): a notificação ligada
            // pode ter acordado alguém mais prioritário.
            super::apic::eoi();
            crate::kthread::preempt();
        } else if super::apic::dispatch(frame.vector) {
            crate::kthread::on_timer();
        }
        crate::ksync::assert_none_held("fim de interrupção");
        return;
    }
    if frame.vector == 2 && super::apic::frozen() {
        // NMI do pânico de outra CPU: para sem despejar nada.
        halt();
    }
    if frame.cs & 3 == 3 && kabi::fault::user_vector(frame.vector) {
        crate::kfault::user_exception(frame, control_registers()[1]);
        crate::ksync::assert_none_held("volta ao usuário");
        return;
    }
    if super::probe::fixup(frame, control_registers()[1]) {
        return;
    }
    let f = &*frame;
    let (name, what) = exception_name(f.vector);
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
