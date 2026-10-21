//! `oalloc`: núcleo do alocador do Optimus, estilo mimalloc (SDD v1.0,
//! seção 7.1; ADR 0039, item 2; T-334).
//!
//! A crate não chama o kernel: a memória vem de um [`PageSource`] (no
//! `ostd`, `MemoryObject` mapeado com `vm_map`; nos testes, o `std::alloc`
//! do host), então os testes rodam no host, inclusive sob Miri.
//!
//! # Desenho
//!
//! - **Segmentos** de 2 MiB, alinhados a 2 MiB: `ptr & !(2 MiB - 1)` acha o
//!   cabeçalho do segmento. Cada segmento tem 32 **páginas** de 64 KiB; a
//!   página 0 guarda o cabeçalho (dono, mapa de páginas, bitmaps).
//! - **Classes de tamanho** (módulo `class`): de 8 em 8 até 64 bytes, depois
//!   4 por duplicação até 32 KiB. De 32 KiB a 512 KiB, o bloco é um conjunto
//!   de páginas contíguas; acima disso, segmento próprio.
//! - **Heap por thread** ([`Heap`]): cada página de uma classe tem a lista
//!   `free` (o que a alocação consome), a `local_free` (o que o dono liberou)
//!   e a `thread_free` (pilha atômica em que **outras** threads empilham).
//!   Quando `free` esvazia, o dono junta as outras duas. Sem trava no caminho
//!   comum; a única operação atômica de quem aloca é o `swap` da
//!   `thread_free` na junção.
//! - **Liberação entre threads:** [`Heap::free`] compara o dono do segmento
//!   com o id do heap que libera; se for outro, empilha o bloco na
//!   `thread_free` da página. O dono recolhe depois.
//! - **Thread que sai:** `Drop` do [`Heap`] devolve o que está ocioso e
//!   *abandona* os segmentos que ainda têm blocos vivos (pilha atômica em
//!   [`Global`]); outro heap os adota ao precisar de memória
//!   ([`Heap::adopt`]).
//! - **Endurecimento:** o elo da lista livre é `endereço ^ chave` (chave por
//!   página, derivada da do heap e da semente da fonte); um bitmap por página
//!   marca os blocos livres, então liberação dupla, ponteiro que não é
//!   início de bloco e elo adulterado abortam por [`PageSource::fault`] em
//!   vez de corromper o heap. O cabeçalho do segmento leva um *canary*
//!   (valor fixo mais um valor dependente do endereço e do segredo do
//!   [`Global`]), conferido a cada liberação.
//! - **Falta de memória** devolve ponteiro nulo.
//!
//! Limites: alinhamento até 64 KiB (acima, [`Heap::alloc`] devolve nulo).
//!
//! # Unsafe
//!
//! A crate tem `unsafe` porque um alocador manipula ponteiros brutos para
//! memória que ele mesmo organiza. O teto está em `unsafe-allowlist.toml` e
//! o `cargo xtask check` o confere. As invariantes, que todo bloco
//! `// SAFETY:` cita:
//!
//! - **INV-S (segmentos):** todo `*mut Segment` e `*mut Page` guardado num
//!   [`Heap`] (listas e lista de segmentos) aponta para um cabeçalho
//!   inicializado de um segmento que o heap possui (`owner == id`) e que a
//!   fonte ainda não recebeu de volta. Só a thread dona toca os campos não
//!   atômicos: o `Heap` não é `Send` (tem ponteiros brutos), então ele não
//!   muda de thread.
//! - **INV-R (remoto):** quem não é dono só lê campos que o dono não muda
//!   enquanto a página tem blocos entregues (`kind`, `bsize`, `recip`,
//!   `cap`, `key`) e só escreve na `thread_free` (atômica) e no bloco que
//!   ele próprio está liberando.
//! - **INV-B (blocos):** um bloco entregue por [`Heap::alloc`] é exclusivo
//!   de quem o recebeu até [`Heap::free`]; um bloco livre pertence ao
//!   alocador, que grava nele o elo da lista.
//! - **INV-F (fonte):** a [`PageSource`] devolve memória gravável, alinhada
//!   a 2 MiB, com procedência sobre a faixa inteira, que continua válida
//!   até `free_segments`.
//!
//! O `Heap` é testado no host com 4 threads e liberações cruzadas, e sob
//! Miri nos PRs que mudam esta crate (`.github/workflows/ci.yml`).

#![cfg_attr(not(test), no_std)]
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]
// Os endereços são `usize` de 64 bits (conferido abaixo); os `as` entre
// `u32`, `u64` e `usize` nos campos das páginas são limitados pelas
// constantes (página de 64 KiB, 32 páginas por segmento).
#![allow(clippy::cast_possible_truncation)]

use core::fmt;

mod class;
mod heap;

#[cfg(test)]
mod tests;
#[cfg(all(test, not(miri)))]
mod tests_colecoes;

pub use heap::{Global, Heap, Stats};

const _: () = assert!(usize::BITS == 64, "oalloc supõe endereços de 64 bits");

/// Tamanho e alinhamento de um segmento.
pub const SEGMENT_SIZE: usize = 2 << 20;
/// Tamanho da página do alocador.
pub const PAGE_SIZE: usize = 64 << 10;
/// Páginas por segmento (a primeira guarda o cabeçalho).
pub const PAGES_PER_SEGMENT: usize = SEGMENT_SIZE / PAGE_SIZE;
/// Maior pedido atendido por uma classe de tamanho.
pub const MAX_SMALL: usize = 32 << 10;
/// Maior pedido atendido por páginas de um segmento; acima, segmento próprio.
pub const MAX_LARGE: usize = 512 << 10;
/// Maior alinhamento atendido.
pub const MAX_ALIGN: usize = PAGE_SIZE;

/// Falha que o alocador detectou e que não admite continuar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// O bloco já estava livre.
    DoubleFree,
    /// O ponteiro não é o início de um bloco deste alocador.
    ForeignPointer,
    /// Uma lista livre ou um contador foi adulterado.
    Corrupted,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DoubleFree => "liberação dupla",
            Self::ForeignPointer => "ponteiro que não é início de bloco deste alocador",
            Self::Corrupted => "lista livre ou contador corrompido",
        })
    }
}

/// De onde o alocador tira e para onde devolve segmentos.
///
/// # Safety
///
/// Quem implementa garante (INV-F): [`alloc_segments`](Self::alloc_segments)
/// devolve nulo ou `count * SEGMENT_SIZE` bytes graváveis, alinhados a
/// `SEGMENT_SIZE`, que ninguém mais usa e que valem até o
/// [`free_segments`](Self::free_segments) correspondente, com procedência
/// sobre a faixa inteira; [`owns`](Self::owns) diz a verdade para endereços
/// de segmentos vivos.
pub unsafe trait PageSource: Sync {
    /// Pede `count` segmentos contíguos; nulo se a memória acabou. O
    /// conteúdo é indefinido.
    fn alloc_segments(&self, count: usize) -> *mut u8;

    /// Devolve o que [`alloc_segments`](Self::alloc_segments) deu com o
    /// mesmo `count`.
    ///
    /// # Safety
    ///
    /// `base` e `count` vêm de uma chamada anterior a `alloc_segments`,
    /// ainda não devolvida, e ninguém usa mais a faixa.
    unsafe fn free_segments(&self, base: *mut u8, count: usize);

    /// O endereço está no **primeiro segmento** de uma faixa que esta fonte
    /// deu e ainda não recebeu de volta? Serve para recusar ponteiros alheios
    /// sem tocá-los. Os segmentos seguintes de uma faixa de vários segmentos
    /// (bloco enorme) respondem `false`: o início deles é dado do usuário,
    /// não um cabeçalho, e o alocador não pode lê-lo para julgar um ponteiro
    /// interior (achado da revisão da T-334).
    fn owns(&self, addr: usize) -> bool;

    /// Semente para as chaves do endurecimento; 0 se não houver entropia.
    /// É chamada uma vez por [`Heap::new`] (o primeiro valor dá o segredo do
    /// [`Global`]; os seguintes, a parte da chave de cada heap), então uma
    /// fonte com entropia deve devolver um valor novo a cada chamada.
    fn seed(&self) -> u64 {
        0
    }

    /// Chamada quando o alocador detecta uma [`Fault`]. Não volta. O padrão
    /// é um pânico; o `ostd` encerra o processo.
    fn fault(&self, fault: Fault) -> ! {
        panic!("oalloc: {fault}")
    }
}
