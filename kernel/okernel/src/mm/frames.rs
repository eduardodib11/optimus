//! Plano de inicialização do buddy a partir do mapa de memória (T-107).
//!
//! O buddy precisa de um [`FrameMeta`] por frame da faixa que gerencia, e o
//! kernel ainda não tem heap: os metadados ocupam o começo da primeira faixa
//! usável que os comporte. A faixa gerenciada vai do primeiro ao último frame
//! usável (buracos no meio custam 12 bytes por frame). A memória abaixo de
//! [`LOW_MEMORY`] fica de fora, reservada ao trampolim de partida dos núcleos
//! (SMP) e a firmware legado.

#![forbid(unsafe_code)]

use kabi::boot::{MemKind, MemRegion};

use super::buddy::FrameMeta;
use super::{FRAME_SIZE, PhysAddr};

/// Memória física abaixo deste endereço não vai para o buddy.
pub const LOW_MEMORY: u64 = 1 << 20;

/// Onde ficam a faixa gerenciada e os metadados.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Primeiro frame da faixa gerenciada.
    pub base: PhysAddr,
    /// Frames da faixa gerenciada (e entradas de metadados).
    pub frames: usize,
    /// Endereço físico dos metadados, alinhado a 4 KiB.
    pub meta: PhysAddr,
    /// Bytes reservados aos metadados, múltiplo de 4 KiB.
    pub meta_bytes: u64,
}

/// Faixas usáveis acima de [`LOW_MEMORY`], com as bordas alinhadas a 4 KiB.
fn usable(map: &[MemRegion]) -> impl Iterator<Item = (u64, u64)> + '_ {
    map.iter()
        .filter(|r| r.kind() == MemKind::Usable)
        .map(|r| {
            (
                r.base.max(LOW_MEMORY).next_multiple_of(FRAME_SIZE),
                r.end() & !(FRAME_SIZE - 1),
            )
        })
        .filter(|(start, end)| start < end)
}

/// Escolhe a faixa gerenciada e o lugar dos metadados; `None` se não houver
/// memória usável ou nenhuma faixa comportar os metadados.
#[must_use]
pub fn plan(map: &[MemRegion]) -> Option<Plan> {
    let start = usable(map).map(|(s, _)| s).min()?;
    let end = usable(map).map(|(_, e)| e).max()?;
    let frames = usize::try_from((end - start) / FRAME_SIZE).ok()?;
    let meta_bytes = u64::try_from(frames.checked_mul(size_of::<FrameMeta>())?)
        .ok()?
        .next_multiple_of(FRAME_SIZE);
    let (meta, _) = usable(map).find(|(s, e)| e - s >= meta_bytes)?;
    Some(Plan {
        base: PhysAddr(start),
        frames,
        meta: PhysAddr(meta),
        meta_bytes,
    })
}

/// Páginas do trampolim de partida dos APs (ADR 0030, item 3): código,
/// parâmetros e as quatro tabelas de página temporárias.
pub const TRAMPOLINE_PAGES: u64 = 6;

/// Endereço da primeira sequência de [`TRAMPOLINE_PAGES`] páginas usáveis
/// abaixo de [`LOW_MEMORY`] e acima de `0x1000` (o vetor do SIPI é o
/// número da página, e a página 0 guarda a IVT); `None` se não houver.
#[must_use]
pub fn trampoline_base(map: &[MemRegion]) -> Option<u64> {
    let need = TRAMPOLINE_PAGES * FRAME_SIZE;
    map.iter()
        .filter(|r| r.kind() == MemKind::Usable)
        .map(|r| {
            (
                r.base.max(FRAME_SIZE).next_multiple_of(FRAME_SIZE),
                r.end().min(LOW_MEMORY) & !(FRAME_SIZE - 1),
            )
        })
        .filter(|(start, end)| start < end && end - start >= need)
        .map(|(start, _)| start)
        .min()
}

/// Faixas `(base, len)` a entregar ao buddy: as usáveis menos os metadados.
pub fn free_ranges<'a>(map: &'a [MemRegion], plan: &Plan) -> impl Iterator<Item = (u64, u64)> + 'a {
    let (hole_start, hole_end) = (plan.meta.0, plan.meta.0 + plan.meta_bytes);
    usable(map)
        .flat_map(move |(s, e)| [(s, e.min(hole_start)), (s.max(hole_end), e)])
        .filter(|(s, e)| s < e)
        .map(|(s, e)| (s, e - s))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn region(base: u64, len: u64, kind: MemKind) -> MemRegion {
        MemRegion::new(base, len, kind)
    }

    #[test]
    fn metadados_na_primeira_faixa_que_cabe() {
        let map = [
            region(0, 640 << 10, MemKind::Usable),
            region(MIB, 0x1800, MemKind::Usable),
            region(2 * MIB, MIB, MemKind::Kernel),
            region(4 * MIB, 60 * MIB, MemKind::Usable),
            region(64 * MIB, 4 * MIB, MemKind::Reserved),
            region(68 * MIB, 0x10_0800, MemKind::Usable),
        ];
        let p = plan(&map).unwrap();
        assert_eq!(p.base, PhysAddr(MIB));
        let frames = (69 * MIB - MIB) / FRAME_SIZE;
        assert_eq!(p.frames, usize::try_from(frames).unwrap());
        let bytes = (frames * size_of::<FrameMeta>() as u64).next_multiple_of(FRAME_SIZE);
        assert_eq!((p.meta, p.meta_bytes), (PhysAddr(4 * MIB), bytes));

        let ranges: Vec<_> = free_ranges(&map, &p).collect();
        assert_eq!(
            ranges,
            [
                (MIB, 0x1000),
                (4 * MIB + bytes, 60 * MIB - bytes),
                (68 * MIB, MIB),
            ]
        );
    }

    #[test]
    fn trampolim_abaixo_de_1_mib() {
        let map = [
            region(0, 0x3000, MemKind::Usable),
            region(0x3000, 0x1000, MemKind::Reserved),
            region(0x8000, 0x9_7000, MemKind::Usable),
            region(MIB, 60 * MIB, MemKind::Usable),
        ];
        assert_eq!(trampoline_base(&map), Some(0x8000));
        // A página 0 nunca entra; 0x1000 a 0x7000 cabe.
        let map = [region(0, 0x7000, MemKind::Usable)];
        assert_eq!(trampoline_base(&map), Some(0x1000));
        // Pequeno demais, ou só acima de 1 MiB.
        assert_eq!(trampoline_base(&[region(0, 0x6000, MemKind::Usable)]), None);
        assert_eq!(
            trampoline_base(&[region(MIB - 0x2000, 8 * MIB, MemKind::Usable)]),
            None
        );
        // Faixa que cruza 1 MiB conta só até ele.
        assert_eq!(
            trampoline_base(&[region(MIB - 0x6000, MIB, MemKind::Usable)]),
            Some(MIB - 0x6000)
        );
    }

    #[test]
    fn sem_memoria_usavel() {
        assert_eq!(plan(&[]), None);
        assert_eq!(plan(&[region(0, 512 << 10, MemKind::Usable)]), None);
        // Faixas pequenas demais para os metadados de toda a extensão.
        let sparse = [
            region(MIB, 0x1000, MemKind::Usable),
            region(1 << 40, 0x1000, MemKind::Usable),
        ];
        assert_eq!(plan(&sparse), None);
    }
}
