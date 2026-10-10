//! Acesso à `BootInfo` entregue pelo `optboot` (T-102) e testes de kernel
//! sobre ela.

use core::sync::atomic::{AtomicPtr, Ordering};

use kabi::boot::{BootInfo, MemKind, MemRegion};

use crate::ktest::{Outcome, Test};

/// Teto de faixas aceitas no mapa de memória, contra um `BootInfo` corrompido.
const MAX_REGIONS: u64 = 4096;

static BOOT_INFO: AtomicPtr<BootInfo> = AtomicPtr::new(core::ptr::null_mut());

/// Guarda a `BootInfo` para o resto do kernel.
pub fn set(info: &'static BootInfo) {
    BOOT_INFO.store(core::ptr::from_ref(info).cast_mut(), Ordering::Release);
}

/// A `BootInfo` guardada por [`set`].
pub fn get() -> Option<&'static BootInfo> {
    let ptr = BOOT_INFO.load(Ordering::Acquire);
    // SAFETY: `set` só guarda referências `'static`, e nada escreve na
    // `BootInfo` depois da entrega (o kernel só a lê).
    unsafe { ptr.as_ref() }
}

/// Mapa de memória da `BootInfo`, se o ponteiro e o tamanho forem plausíveis.
pub fn memory_map(info: &BootInfo) -> Option<&'static [MemRegion]> {
    let ptr = info.memory_map;
    let len = usize::try_from(info.memory_map_len).ok()?;
    if ptr.is_null() || !ptr.is_aligned() || info.memory_map_len > MAX_REGIONS {
        return None;
    }
    // SAFETY: o optboot (T-103) grava `memory_map_len` faixas num vetor
    // próprio, de tipo Kernel no mapa, apontado pelo mapa direto; nada mais
    // escreve nessa memória.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Imprime o mapa de memória recebido (aceite do T-102).
pub fn log_memory_map(map: &[MemRegion]) {
    info!("okernel: mapa de memória com {} faixas", map.len());
    for r in map {
        info!(
            "okernel:   {:#014x}-{:#014x} {:?} ({} KiB)",
            r.base,
            r.end(),
            r.kind(),
            r.len >> 10
        );
    }
    let usable: u64 = map
        .iter()
        .filter(|r| r.kind() == MemKind::Usable)
        .map(|r| r.len)
        .sum();
    info!("okernel: {} KiB usáveis", usable >> 10);
}

/// Testes de kernel da `BootInfo`.
pub const TESTS: &[Test] = &[Test {
    name: "boot.mapa_de_memoria_ordenado_e_com_ram",
    run: mapa_ordenado,
}];

fn mapa_ordenado() -> Outcome {
    let info = get().ok_or("BootInfo ausente")?;
    ensure!(info.is_valid());
    let map = memory_map(info).ok_or("mapa de memória inválido")?;
    ensure!(!map.is_empty());
    ensure!(map.windows(2).all(|w| w[0].end() <= w[1].base));
    ensure!(map.iter().any(|r| r.kind() == MemKind::Usable));
    Ok(())
}
