//! GDT e TSS com pilhas IST (T-105).
//!
//! No modo longo a segmentação quase não importa: a GDT tem o código e os
//! dados do kernel, os do usuário (T-206) na ordem que SYSRET exige e o
//! descritor da TSS. A TSS dá a pilha de kernel da thread atual (RSP0, para
//! interrupções vindas do anel 3) e as pilhas IST, que dão pilha conhecida
//! e boa a faltas que podem chegar com a pilha estragada (falta dupla), a
//! qualquer momento (NMI) ou com a máquina instável (MCE).

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
/// Base dos seletores de usuário no STAR: SYSRET carrega SS = base + 8 e
/// CS = base + 16 (índice 3 seria o código de 32 bits, ausente).
pub const SYSRET_BASE: u16 = 0x18;
/// Seletor dos dados do usuário (índice 4, anel 3).
pub const USER_DATA: u16 = 0x20 | 3;
/// Seletor do código de 64 bits do usuário (índice 5, anel 3).
pub const USER_CODE: u16 = 0x28 | 3;
/// Seletor da TSS (índices 6 e 7).
pub const TSS_SELECTOR: u16 = 0x30;
/// Entradas da GDT.
pub const GDT_ENTRIES: usize = 8;

/// Índices de IST (1 a 7; zero quer dizer "sem IST") usados na IDT.
pub const IST_DOUBLE_FAULT: u8 = 1;
/// IST da NMI.
pub const IST_NMI: u8 = 2;
/// IST da verificação de máquina.
pub const IST_MACHINE_CHECK: u8 = 3;

/// Bytes de cada pilha IST, que é também o alinhamento delas: o topo de
/// cada uma guarda o endereço da `PerCpu` dona (ADR 0030, item 2).
pub const IST_STACK_SIZE: usize = 16 << 10;

/// Task State Segment de 64 bits (Intel SDM vol. 3, 8.7).
#[repr(C, packed(4))]
pub struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

impl Tss {
    /// TSS vazia, sem mapa de permissões de E/S.
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp: [0; 3],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            // Sem mapa de permissões de E/S: base além do limite do segmento.
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

/// Operando de `lgdt`/`lidt`.
#[repr(C, packed)]
pub struct Pointer {
    /// Bytes da tabela menos um.
    pub limit: u16,
    /// Endereço virtual da tabela.
    pub base: u64,
}

/// GDT de cada CPU (a TSS de cada uma tem base própria e bit de ocupada).
pub type Gdt = [u64; GDT_ENTRIES];

/// Nula, código e dados do kernel, código de 32 bits do usuário (ausente:
/// o kernel nunca volta ao modo de compatibilidade), dados e código de 64
/// bits do usuário e os dois descritores da TSS (preenchidos por [`load`]).
/// Fica gravável porque `ltr` marca a TSS como ocupada no descritor.
pub const GDT_TEMPLATE: Gdt = [
    0,
    0x00af_9a00_0000_ffff, // código: presente, anel 0, executável, L=1
    0x00cf_9200_0000_ffff, // dados: presente, anel 0, gravável
    0,
    0x00cf_f200_0000_ffff, // dados: presente, anel 3, gravável
    0x00af_fa00_0000_ffff, // código: presente, anel 3, executável, L=1
    0,
    0,
];

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

/// Monta a TSS (pilhas IST com topos `ist_tops`, na ordem de
/// [`IST_DOUBLE_FAULT`], [`IST_NMI`] e [`IST_MACHINE_CHECK`]) e a GDT,
/// carrega a GDT, recarrega os segmentos e carrega a TSS nesta CPU.
///
/// # Safety
///
/// Uma vez por CPU, com interrupções desligadas; `gdt` e `tss` são desta
/// CPU, vivem para sempre e nada mais os acessa agora; os topos são de
/// pilhas mapeadas e só desta CPU. Carregar um seletor nulo em GS pode
/// zerar `GS_BASE`: quem chama o grava depois.
pub unsafe fn load(gdt: *mut Gdt, tss: *mut Tss, ist_tops: [u64; 3]) {
    // SAFETY: contrato acima: os ponteiros crus não criam referências
    // concorrentes.
    unsafe {
        for (slot, top) in [IST_DOUBLE_FAULT, IST_NMI, IST_MACHINE_CHECK]
            .into_iter()
            .zip(ist_tops)
        {
            let ist = &raw mut (*tss).ist;
            ist.cast::<u64>()
                .add(usize::from(slot - 1))
                .write_unaligned(top);
        }
        gdt.write(GDT_TEMPLATE);
        let [low, high] = tss_descriptor(tss.addr() as u64);
        (*gdt)[6] = low;
        (*gdt)[7] = high;
        let pointer = Pointer {
            limit: (size_of::<Gdt>() - 1) as u16,
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

/// Pilha de kernel usada quando uma interrupção chega no anel 3 (RSP0).
///
/// # Safety
///
/// Só com interrupções desligadas, na CPU dona de `tss`; `top` é o topo de
/// uma pilha de kernel mapeada que a thread atual vai usar.
pub unsafe fn set_kernel_stack(tss: *mut Tss, top: u64) {
    // SAFETY: contrato acima; a TSS é empacotada, então a escrita não pode
    // supor alinhamento de 8.
    unsafe {
        let rsp = &raw mut (*tss).rsp;
        rsp.cast::<u64>().write_unaligned(top);
    }
}
