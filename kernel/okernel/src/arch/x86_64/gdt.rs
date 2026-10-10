//! GDT e TSS com pilhas IST (T-105).
//!
//! No modo longo a segmentação quase não importa: a GDT tem só o código e os
//! dados do kernel e o descritor da TSS. A TSS serve para as pilhas IST, que
//! dão pilha conhecida e boa a faltas que podem chegar com a pilha estragada
//! (falta dupla), a qualquer momento (NMI) ou com a máquina instável (MCE).

#![allow(
    clippy::cast_possible_truncation,
    reason = "descritores x86 repartem endereços e limites em campos de 16 e 32 bits"
)]

use core::arch::asm;
use core::mem::size_of;

/// Seletor do código do kernel (índice 1, anel 0).
pub const KERNEL_CODE: u16 = 0x08;
/// Seletor dos dados do kernel (índice 2, anel 0).
pub const KERNEL_DATA: u16 = 0x10;
/// Seletor da TSS (índices 3 e 4).
pub const TSS_SELECTOR: u16 = 0x18;

/// Índices de IST (1 a 7; zero quer dizer "sem IST") usados na IDT.
pub const IST_DOUBLE_FAULT: u8 = 1;
/// IST da NMI.
pub const IST_NMI: u8 = 2;
/// IST da verificação de máquina.
pub const IST_MACHINE_CHECK: u8 = 3;

/// Bytes de cada pilha IST.
const IST_STACK_SIZE: usize = 16 << 10;

/// Pilha de IST, alinhada a 16 bytes.
#[repr(C, align(16))]
struct Stack([u8; IST_STACK_SIZE]);

/// Task State Segment de 64 bits (Intel SDM vol. 3, 8.7).
#[repr(C, packed(4))]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

/// Operando de `lgdt`/`lidt`.
#[repr(C, packed)]
pub struct Pointer {
    /// Bytes da tabela menos um.
    pub limit: u16,
    /// Endereço virtual da tabela.
    pub base: u64,
}

static mut IST_STACKS: [Stack; 3] = [const { Stack([0; IST_STACK_SIZE]) }; 3];

static mut TSS: Tss = Tss {
    reserved0: 0,
    rsp: [0; 3],
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    // Sem mapa de permissões de E/S: base além do limite do segmento.
    iomap_base: size_of::<Tss>() as u16,
};

/// Nula, código 64 bits, dados e os dois descritores da TSS. Fica gravável
/// porque `ltr` marca a TSS como ocupada no descritor.
static mut GDT: [u64; 5] = [
    0,
    0x00af_9a00_0000_ffff, // código: presente, anel 0, executável, L=1
    0x00cf_9200_0000_ffff, // dados: presente, anel 0, gravável
    0,
    0,
];

/// Endereço virtual da GDT, para conferir o que a CPU carregou.
pub fn table_addr() -> u64 {
    (&raw const GDT).addr() as u64
}

/// Descritor de sistema de 16 bytes para uma TSS de 64 bits disponível.
fn tss_descriptor(base: u64) -> [u64; 2] {
    let limit = (size_of::<Tss>() - 1) as u64;
    let low = (limit & 0xffff)
        | ((base & 0xff_ffff) << 16)
        | (0x89 << 40) // presente, tipo 9 (TSS de 64 bits disponível)
        | (((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    [low, base >> 32]
}

/// Monta TSS e GDT, carrega a GDT, recarrega os segmentos e carrega a TSS.
///
/// # Safety
///
/// Só pode rodar uma vez, no boot, com interrupções desligadas e antes de
/// qualquer outro uso de `GDT`, `TSS` e das pilhas IST.
pub unsafe fn init() {
    // SAFETY: contrato acima: nada mais acessa os estáticos agora, então os
    // ponteiros crus não criam referências concorrentes.
    unsafe {
        let stacks = &raw mut IST_STACKS;
        let tss = &raw mut TSS;
        for (i, slot) in [IST_DOUBLE_FAULT, IST_NMI, IST_MACHINE_CHECK]
            .into_iter()
            .enumerate()
        {
            let top = (&raw mut (*stacks)[i]).addr() + IST_STACK_SIZE;
            (*tss).ist[usize::from(slot - 1)] = top as u64;
        }
        let gdt = &raw mut GDT;
        let [low, high] = tss_descriptor(tss.addr() as u64);
        (*gdt)[3] = low;
        (*gdt)[4] = high;
        let pointer = Pointer {
            limit: (size_of::<[u64; 5]>() - 1) as u16,
            base: gdt.addr() as u64,
        };
        asm!(
            "lgdt [{ptr}]",
            // Recarrega CS com um retorno distante para o rótulo 2.
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov ss, {data:x}",
            "mov fs, {zero:x}",
            "mov gs, {zero:x}",
            "ltr {tss:x}",
            ptr = in(reg) &raw const pointer,
            code = in(reg) u64::from(KERNEL_CODE),
            data = in(reg) KERNEL_DATA,
            zero = in(reg) 0u16,
            tss = in(reg) TSS_SELECTOR,
            tmp = out(reg) _,
        );
    }
}
