//! Classes de tamanho e plano de alocação (ADR 0039, item 2).
//!
//! Até 64 bytes as classes são lineares, de 8 em 8 (8, 16, ..., 64); de 64
//! a 32 KiB há 4 classes por duplicação (degraus de 25%: 80, 96, 112, 128,
//! 160, ...). Acima de 64 bytes o arredondamento perde no máximo 20% do
//! bloco. Uma página de 64 KiB guarda de 2 a 8 blocos das classes
//! acima de 8 KiB. De 32 KiB a 512 KiB o bloco é um múltiplo de páginas de 64 KiB
//! dentro de um segmento; acima disso, o bloco tem segmento próprio.

use crate::{MAX_ALIGN, MAX_LARGE, MAX_SMALL, PAGE_SIZE, SEGMENT_SIZE};

/// Quantidade de classes de tamanho.
pub(crate) const NUM_CLASSES: usize = 44;

/// Tamanho do bloco da classe `c` (`c < NUM_CLASSES`).
pub(crate) const fn class_size(c: usize) -> usize {
    if c < 8 {
        (c + 1) * 8
    } else {
        let k = 6 + (c - 8) / 4;
        let sub = (c - 8) % 4;
        (5 + sub) << (k - 2)
    }
}

/// Menor classe que comporta `size` bytes (`1 <= size <= MAX_SMALL`).
pub(crate) const fn class_of(size: usize) -> usize {
    if size <= 64 {
        size.div_ceil(8) - 1
    } else {
        let s = size - 1;
        let k = (usize::BITS - 1 - s.leading_zeros()) as usize;
        let sub = (s >> (k - 2)) & 3;
        8 + (k - 6) * 4 + sub
    }
}

/// Como atender um pedido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Classe de tamanho dentro de uma página de 64 KiB.
    Small(usize),
    /// Bloco de tantas páginas contíguas de um segmento.
    Large(usize),
    /// Bloco com tantos segmentos próprios.
    Huge(usize),
    /// Alinhamento ou tamanho que o alocador não atende.
    Fail,
}

/// Escolhe como atender `size` bytes com alinhamento `align`.
pub(crate) fn plan(size: usize, align: usize) -> Plan {
    if !align.is_power_of_two() || align > MAX_ALIGN {
        return Plan::Fail;
    }
    let Some(s) = size.max(1).checked_next_multiple_of(align) else {
        return Plan::Fail;
    };
    if s <= MAX_SMALL {
        // Os blocos da classe começam em múltiplos do tamanho dela dentro
        // de uma página alinhada: só serve a classe cujo tamanho é múltiplo
        // do alinhamento (a de 32 KiB serve a todo alinhamento até 32 KiB).
        let mut c = class_of(s);
        while !class_size(c).is_multiple_of(align) {
            c += 1;
        }
        Plan::Small(c)
    } else if s <= MAX_LARGE {
        Plan::Large(s.div_ceil(PAGE_SIZE))
    } else {
        // O bloco começa na página 1 do primeiro segmento (a 0 é o
        // cabeçalho).
        // Nenhum `Layout` passa de `isize::MAX`, e abaixo disso o número de
        // segmentos vezes o tamanho de um não estoura `usize`.
        match s.checked_add(PAGE_SIZE) {
            Some(total) if isize::try_from(total).is_ok() => {
                Plan::Huge(total.div_ceil(SEGMENT_SIZE))
            }
            _ => Plan::Fail,
        }
    }
}
