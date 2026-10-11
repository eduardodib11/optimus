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
    assert_eq!(size_of::<BootInfo>(), 88 + 1024 + 8 + 64 + 8 + 16 + 8);
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
