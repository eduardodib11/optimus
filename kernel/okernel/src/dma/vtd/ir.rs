//! Fila de invalidação e remapeamento de interrupções do VT-d (ADR 0044,
//! item 6; T-404).
//!
//! O remapeamento só liga quando todas as unidades o têm (`ECAP.IR`) e a
//! fila de invalidação (`ECAP.QI`), que é o único jeito de invalidar a cache
//! de entradas de interrupção. Com a fila ligada, os registradores de
//! invalidação (`CCMD` e `IOTLB`) não podem mais ser usados: toda
//! invalidação da unidade passa por ela e termina num descritor de espera
//! que escreve um valor na página de estado.
//!
//! A tabela de remapeamento (IRT) tem 256 entradas, uma por vetor: o
//! índice de uma MSI é o próprio vetor do `Interrupt`. Cada entrada leva o
//! BDF de origem com verificação (`SVT = 1`), então só aquele dispositivo
//! dispara o vetor. Interrupções no formato de compatibilidade ficam
//! bloqueadas (`CFI = 0`): uma MSI escrita à mão por um driver não chega.

use core::cell::Cell;

use super::{Hw, Unit, command, flush, spin};
use crate::mm::PhysAddr;

pub(super) const IQT: usize = 0x88;
pub(super) const IQA: usize = 0x90;
pub(super) const IRTA: usize = 0xb8;
pub(super) const QIE: u32 = 1 << 26;
pub(super) const IRE: u32 = 1 << 25;
pub(super) const SIRTP: u32 = 1 << 24;
/// `ECAP.QI` e `ECAP.IR`.
pub(super) const ECAP_QI: u64 = 1 << 1;
pub(super) const ECAP_IR: u64 = 1 << 3;
/// Entradas da fila numa página (descritores de 128 bits).
const SLOTS: usize = 256;
/// `IRTA.S`: 2^(S + 1) = 256 entradas.
const IRT_SIZE: u64 = 7;

/// Descritores (128 bits: `u64` baixo e alto).
const CTX_GLOBAL: u64 = 1 | 1 << 4;
const IOTLB: u64 = 2;
const IOTLB_DRAIN: u64 = 1 << 7 | 1 << 6;
const IEC_GLOBAL: u64 = 4;
const IEC_INDEX: u64 = 4 | 1 << 4;
const WAIT: u64 = 5 | 1 << 5 | 1 << 6;
const DONE: u64 = 1;

/// A fila de invalidação de uma unidade.
pub(super) struct Queue {
    base: PhysAddr,
    status: PhysAddr,
    /// Próxima entrada livre.
    tail: Cell<usize>,
}

impl Queue {
    /// Liga a fila da unidade `u` (com a tradução ainda desligada).
    pub(super) fn enable(hw: &mut dyn Hw, u: usize, sts: u32) -> Option<Self> {
        let base = hw.alloc_table()?;
        let status = hw.alloc_table()?;
        hw.write64(u, IQT, 0);
        hw.write64(u, IQA, base.0);
        command(hw, u, sts | QIE, QIE, QIE);
        Some(Self {
            base,
            status,
            tail: Cell::new(0),
        })
    }
}

/// Manda `descs` à fila da unidade, mais um descritor de espera, e espera a
/// unidade escrever o estado.
pub(super) fn submit(hw: &mut dyn Hw, units: &[Unit], unit: &Unit, descs: &[(u64, u64)]) {
    let q = unit.queue.as_ref().expect("vt-d: unidade sem fila");
    hw.table(q.status)[0] = 0;
    let wait = (WAIT | DONE << 32, q.status.0);
    let mut tail = q.tail.get();
    for &(lo, hi) in descs.iter().chain(core::iter::once(&wait)) {
        let t = hw.table(q.base);
        t[tail * 2] = lo;
        t[tail * 2 + 1] = hi;
        flush(hw, units, q.base.0 + tail as u64 * 16, 16);
        tail = (tail + 1) % SLOTS;
    }
    q.tail.set(tail);
    hw.write64(unit.index, IQT, tail as u64 * 16);
    // Cada volta relê a página pelo `Hw` (como o semáforo do AMD-Vi).
    let status = q.status;
    spin(hw, |hw| hw.table(status)[0] == DONE);
}

/// Os descritores do que `super::invalidate` pede pelos registradores.
pub(super) fn invalidation(ctx: bool, iotlb: u64) -> [(u64, u64); 2] {
    // Granularidade (global 1, domínio 2) e domínio do valor do registrador.
    let granularity = (iotlb >> 60) & 3;
    let did = (iotlb >> 32) & 0xffff;
    let tlb = (IOTLB | granularity << 4 | IOTLB_DRAIN | did << 16, 0);
    if ctx {
        [(CTX_GLOBAL, 0), tlb]
    } else {
        [tlb, tlb]
    }
}

/// Liga o remapeamento na unidade, com a fila já ligada: aponta a IRT,
/// invalida a cache de entradas e liga `IRE` (com `CFI = 0`).
pub(super) fn enable(hw: &mut dyn Hw, units: &[Unit], unit: &Unit, irt: PhysAddr) {
    let u = unit.index;
    hw.write64(u, IRTA, irt.0 | IRT_SIZE);
    let sts = hw.read32(u, super::GSTS) & super::PERSISTENT;
    command(hw, u, sts | SIRTP, SIRTP, SIRTP);
    submit(hw, units, unit, &[(IEC_GLOBAL, 0)]);
    let sts = hw.read32(u, super::GSTS) & super::PERSISTENT;
    command(hw, u, sts | IRE, IRE, IRE);
}

/// Entrada da IRT do vetor `vector`: entrega fixa, por borda, ao APIC
/// `dest` em modo físico; com `source`, só aquele BDF a usa.
pub(super) fn entry(vector: u8, dest: u8, source: Option<u16>) -> (u64, u64) {
    let lo = 1 | u64::from(vector) << 16 | u64::from(dest) << 40;
    let hi = source.map_or(0, |sid| u64::from(sid) | 1 << 18);
    (lo, hi)
}

/// Descritor que invalida a entrada `index` da cache de interrupções.
pub(super) fn invalidate_entry(index: u8) -> (u64, u64) {
    (IEC_INDEX | u64::from(index) << 32, 0)
}

/// Endereço de MSI no formato remapeável para a entrada `index` (`SHV = 0`;
/// o dado vai zero).
pub(super) fn address(index: u8) -> u64 {
    0xfee0_0000 | u64::from(index) << 5 | 1 << 4
}
