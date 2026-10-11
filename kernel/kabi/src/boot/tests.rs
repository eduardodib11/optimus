//! Testes do layout e da normalização da `BootInfo`.

use super::*;
use core::mem::{offset_of, size_of};

#[test]
fn layout_estavel() {
    assert_eq!(size_of::<MemRegion>(), 24);
    assert_eq!(size_of::<Framebuffer>(), 32);
    assert_eq!(offset_of!(BootInfo, memory_map), 16);
    assert_eq!(offset_of!(BootInfo, framebuffer), 32);
    assert_eq!(offset_of!(BootInfo, acpi_rsdp), 64);
    assert_eq!(offset_of!(BootInfo, cmdline), 88);
    assert_eq!(offset_of!(BootInfo, rng_seed), 88 + 1024 + 8);
    assert_eq!(offset_of!(BootInfo, kaslr_slide), 88 + 1024 + 8 + 64);
    assert_eq!(
        offset_of!(BootInfo, direct_map_base),
        88 + 1024 + 8 + 64 + 8
    );
    assert_eq!(size_of::<BootInfo>(), 88 + 1024 + 8 + 64 + 8 + 8 + 16 + 8);
    assert_eq!(BOOT_MAGIC.to_be_bytes(), *b"OPTIMUS!");
}

#[test]
fn opcionais_vazios_viram_none() {
    let mut info = BootInfo::empty();
    assert!(info.is_valid());
    assert_eq!((info.framebuffer(), info.acpi_rsdp()), (None, None));
    assert_eq!(info.cmdline(), Some(""));
    info.acpi_rsdp = 0xe0000;
    info.framebuffer.base = 0x8000_0000;
    assert_eq!(info.acpi_rsdp(), Some(0xe0000));
    assert!(info.framebuffer().is_some());
    info.magic ^= 1;
    assert!(!info.is_valid());
}

#[test]
fn cmdline_trunca_sem_cortar_caractere() {
    let mut info = BootInfo::empty();
    info.set_cmdline("log=debug test=fault");
    assert_eq!(info.cmdline(), Some("log=debug test=fault"));
    let long = "é".repeat(CMDLINE_MAX);
    info.set_cmdline(&long);
    assert_eq!(info.cmdline_len, CMDLINE_MAX as u64);
    assert_eq!(info.cmdline().map(str::len), Some(CMDLINE_MAX));
    info.cmdline_len = CMDLINE_MAX as u64 + 1;
    assert_eq!(info.cmdline(), None);
}

#[test]
fn normaliza_ordena_e_funde() {
    use MemKind::{Acpi, Kernel, Usable};
    let mut map = [
        MemRegion::new(0x10_0000, 0x1000, Usable),
        MemRegion::new(0, 0x1000, Usable),
        MemRegion::new(0x1000, 0x1000, Usable),
        MemRegion::new(0x3000, 0, Acpi),
        MemRegion::new(0x2000, 0x1000, Kernel),
        MemRegion::new(0x3000, 0x1000, Kernel),
        MemRegion::new(0x4000, 0x1000, Usable),
    ];
    let n = normalize(&mut map);
    assert_eq!(
        &map[..n],
        &[
            MemRegion::new(0, 0x2000, Usable),
            MemRegion::new(0x2000, 0x2000, Kernel),
            MemRegion::new(0x4000, 0x1000, Usable),
            MemRegion::new(0x10_0000, 0x1000, Usable),
        ]
    );
    assert_eq!(normalize(&mut []), 0);
}

#[test]
fn tipo_desconhecido_conta_como_reservado() {
    let mut r = MemRegion::new(0, 1, MemKind::Mmio);
    assert_eq!(r.kind(), MemKind::Mmio);
    r.kind = 99;
    assert_eq!(r.kind(), MemKind::Reserved);
    assert_eq!(MemRegion::new(u64::MAX, 2, MemKind::Usable).end(), u64::MAX);
}

#[test]
fn mapa_direto_sorteado_em_passos_de_1_gib() {
    const GIB: u64 = 1 << 30;
    let span = DIRECT_MAP_END - DIRECT_MAP_START;
    assert_eq!(direct_map_slots(4 * GIB), span / GIB - 3);
    assert_eq!(direct_map_slots(4 * GIB - 1), direct_map_slots(4 * GIB));
    assert_eq!(direct_map_slots(span), 1);
    assert_eq!(direct_map_slots(span + 1), 0);
    assert_eq!(direct_map_slots(u64::MAX), 0);
    assert_eq!(choose_direct_map_base(0, 4 * GIB), Some(DIRECT_MAP_START));
    assert_eq!(choose_direct_map_base(7, span + 1), None);
    let last = DIRECT_MAP_END - 4 * GIB;
    assert_eq!(
        choose_direct_map_base(u64::MAX, 4 * GIB).map(|b| b <= last),
        Some(true)
    );
    assert_eq!(
        choose_direct_map_base(direct_map_slots(4 * GIB) - 1, 4 * GIB),
        Some(last)
    );
    let mut seen = std::collections::HashSet::new();
    for r in [1u64, 2, 3, 0xdead_beef, 1 << 40, u64::MAX / 3] {
        let base = choose_direct_map_base(r, 512 << 20).unwrap();
        assert!(direct_map_base_valid(base, 512 << 20));
        assert!(base + GIB <= DIRECT_MAP_END);
        seen.insert(base);
    }
    assert!(seen.len() > 1);
    assert!(direct_map_base_valid(last, 4 * GIB));
    assert!(!direct_map_base_valid(last + GIB, 4 * GIB));
    assert!(!direct_map_base_valid(DIRECT_MAP_START + 4096, GIB));
    assert!(!direct_map_base_valid(DIRECT_MAP_START - GIB, GIB));
    assert_eq!(BootInfo::empty().direct_map_base, DIRECT_MAP_START);
}
