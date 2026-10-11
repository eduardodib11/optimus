//! Acesso à `BootInfo` entregue pelo `optboot` (T-102) e testes de kernel
//! sobre ela.

use core::sync::atomic::{AtomicPtr, Ordering};

use kabi::boot::{BootInfo, DIRECT_MAP_START, MemKind, MemRegion, direct_map_base_valid};

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

/// Fim da faixa física coberta pelo mapa direto, pela mesma regra do
/// optboot: toda a RAM, ACPI e bootfs e ao menos 4 GiB, arredondado para 1 GiB.
pub fn direct_map_limit(map: &[MemRegion]) -> u64 {
    let ram = map
        .iter()
        .filter(|r| {
            matches!(
                r.kind(),
                MemKind::Usable | MemKind::Acpi | MemKind::Kernel | MemKind::Bootfs
            )
        })
        .map(MemRegion::end)
        .max()
        .unwrap_or(0);
    ram.max(4 << 30).next_multiple_of(1 << 30)
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
pub const TESTS: &[Test] = &[
    Test {
        name: "boot.mapa_de_memoria_ordenado_e_com_ram",
        run: mapa_ordenado,
    },
    Test {
        name: "boot.mapa_direto_na_base_sorteada",
        run: mapa_direto_sorteado,
    },
];

fn mapa_ordenado() -> Outcome {
    let info = get().ok_or("BootInfo ausente")?;
    ensure!(info.is_valid());
    let map = memory_map(info).ok_or("mapa de memória inválido")?;
    ensure!(!map.is_empty());
    ensure!(map.windows(2).all(|w| w[0].end() <= w[1].base));
    ensure!(map.iter().any(|r| r.kind() == MemKind::Usable));
    Ok(())
}

/// ADR 0026: o kernel usa a base da `BootInfo`, alinhada a 1 GiB e dentro
/// da faixa, e o físico 0 está nela; o GiB anterior não é mapa direto.
fn mapa_direto_sorteado() -> Outcome {
    let info = get().ok_or("BootInfo ausente")?;
    let map = memory_map(info).ok_or("mapa de memória inválido")?;
    let (base, limit) = (info.direct_map_base, direct_map_limit(map));
    info!("ktest: · mapa direto em {base:#x}, {} GiB", limit >> 30);
    ensure!(crate::kmem::direct_base() == base);
    ensure!(direct_map_base_valid(base, limit));
    let first = crate::kmem::translate(base).ok_or("físico 0 fora do mapa")?;
    ensure!(first.phys.0 == 0);
    let last = crate::kmem::translate(base + limit - 4096).ok_or("fim fora do mapa")?;
    ensure!(last.phys.0 == limit - 4096);
    ensure!(base == DIRECT_MAP_START || crate::kmem::translate(base - 4096).is_none());
    Ok(())
}
