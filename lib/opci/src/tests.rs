#![allow(clippy::cast_possible_truncation, reason = "metades de BARs de teste")]

extern crate std;

use super::*;
use std::collections::BTreeMap;
use std::format;
use std::string::String;
use std::vec::Vec;

/// Função falsa: 64 palavras de configuração e a máscara de cada BAR.
#[derive(Clone)]
struct Fake {
    regs: [u32; 64],
    masks: [u32; 6],
}

impl Fake {
    fn new(vendor: u16, device: u16, class: u32, header: u8) -> Self {
        let mut regs = [0; 64];
        regs[0] = u32::from(vendor) | u32::from(device) << 16;
        regs[2] = class;
        regs[3] = u32::from(header) << 16;
        regs[1] = 0x0007;
        Self {
            regs,
            masks: [0; 6],
        }
    }

    /// BAR `i` de memória de `size` bytes em `base` (`flags`: bits 0..4).
    fn mem(mut self, i: usize, base: u64, size: u64, flags: u32) -> Self {
        let mask = !(size - 1);
        self.regs[4 + i] = (base as u32) | flags;
        self.masks[i] = (mask as u32) & !0xF | flags;
        if flags & 6 == 4 {
            self.regs[5 + i] = (base >> 32) as u32;
            self.masks[i + 1] = (mask >> 32) as u32;
        }
        self
    }

    fn io(mut self, i: usize, base: u32, size: u32) -> Self {
        self.regs[4 + i] = base | 1;
        self.masks[i] = (!(size - 1) & 0xFFFF) | 1;
        self
    }

    /// Capability em `at`; a primeira chamada também a põe no `CAP_PTR`.
    fn cap(mut self, at: u16, words: &[u32]) -> Self {
        if self.regs[1] & (reg::STATUS_CAP_LIST << 16) == 0 {
            self.regs[1] |= reg::STATUS_CAP_LIST << 16;
            self.regs[13] = u32::from(at);
        }
        for (k, w) in words.iter().enumerate() {
            self.regs[usize::from(at / 4) + k] = *w;
        }
        self
    }
}

#[derive(Default)]
struct Bus {
    fns: BTreeMap<Bdf, Fake>,
    /// BARs lidos com a decodificação ligada (erro do dimensionamento).
    decoding_reads: usize,
}

const fn bdf(bus: u8, dev: u8, func: u8) -> Bdf {
    Bdf { bus, dev, func }
}

impl Config for Bus {
    fn read(&mut self, at: Bdf, offset: u16) -> u32 {
        let Some(f) = self.fns.get(&at) else {
            return u32::MAX;
        };
        let i = usize::from(offset / 4);
        let bars = if (f.regs[3] >> 16) & 0x7F == 1 { 6 } else { 10 };
        if (4..bars).contains(&i) && f.regs[1] & 3 != 0 && f.regs[i] != 0 {
            self.decoding_reads += 1;
        }
        f.regs.get(i).copied().unwrap_or(0)
    }

    fn write(&mut self, at: Bdf, offset: u16, value: u32) {
        let Some(f) = self.fns.get_mut(&at) else {
            return;
        };
        let i = usize::from(offset / 4);
        if (4..10).contains(&i) {
            let m = f.masks[i - 4];
            let upper = i > 4 && f.masks[i - 5] & 7 == 4;
            let low = if upper {
                0
            } else if m & 1 == 1 {
                3
            } else {
                0xF
            };
            f.regs[i] = (value & m & !low) | (m & low & f.regs[i]) | (f.regs[i] & low);
        } else if i == 1 {
            // Os bits de status são RW1C: gravar zero não os muda.
            f.regs[1] = (f.regs[1] & 0xFFFF_0000) | (value & 0xFFFF);
        } else if i < 64 {
            f.regs[i] = value;
        }
    }
}

/// Um q35 parecido com o do QEMU: ponte de host, VGA, e1000e, uma ponte
/// `PCIe` com um dispositivo atrás, e a função 0x1f multifunção.
fn q35() -> Bus {
    let mut b = Bus::default();
    let mut add = |at, f| {
        b.fns.insert(at, f);
    };
    let mut bridge = Fake::new(0x1b36, 0x000c, 0x0604_0000, 1).cap(0x40, &[0x0042_0010]);
    bridge.regs[6] = 0x0001_0100;
    add(bdf(0, 0, 0), Fake::new(0x8086, 0x29c0, 0x0600_0000, 0));
    add(
        bdf(0, 1, 0),
        Fake::new(0x1234, 0x1111, 0x0300_0002, 0)
            .mem(0, 0x8000_0000, 16 << 20, 8)
            .mem(2, 0xC000_0000, 4096, 0),
    );
    add(
        bdf(0, 2, 0),
        Fake::new(0x8086, 0x10d3, 0x0200_0000, 0)
            .mem(0, 0xC004_0000, 128 << 10, 0)
            .io(2, 0x6000, 32)
            .mem(3, 0xC006_0000, 16 << 10, 0)
            // PCIe em 0xE0 → MSI-X em 0xA0 (tabela no BAR 3, PBA no 3 + 0x2000) → MSI em 0xD0.
            .cap(0xE0, &[0x0002_A010])
            .cap(0xA0, &[0x0004_D011, 0x3, 0x2003])
            .cap(0xD0, &[0x0080_0005]),
    );
    add(bdf(0, 3, 0), bridge);
    add(
        bdf(1, 0, 0),
        Fake::new(0x1af4, 0x1042, 0x0100_0001, 0).mem(4, 0x8_0000_0000, 16 << 10, 0xC),
    );
    add(
        bdf(0, 0x1f, 0),
        Fake::new(0x8086, 0x2918, 0x0601_0002, 0x80),
    );
    add(
        bdf(0, 0x1f, 2),
        Fake::new(0x8086, 0x2922, 0x0106_0102, 0).io(4, 0xC040, 32),
    );
    add(
        bdf(0, 0x1f, 3),
        Fake::new(0x8086, 0x2930, 0x0c05_0002, 0).io(4, 0x0700, 64),
    );
    b
}

fn all(b: &mut Bus) -> Vec<Function> {
    let mut out = Vec::new();
    scan(b, 255, |f| out.push(*f));
    out
}

#[test]
fn lista_como_lspci() {
    let mut b = q35();
    let lines: Vec<String> = all(&mut b).iter().map(|f| format!("{f}")).collect();
    assert_eq!(
        lines,
        [
            "00:00.0 0600: 8086:29c0",
            "00:01.0 0300: 1234:1111 (rev 02)",
            "00:02.0 0200: 8086:10d3",
            "00:03.0 0604: 1b36:000c",
            "00:1f.0 0601: 8086:2918 (rev 02)",
            "00:1f.2 0106: 8086:2922 (rev 02)",
            "00:1f.3 0c05: 8086:2930 (rev 02)",
            "01:00.0 0100: 1af4:1042 (rev 01)",
        ]
    );
    assert_eq!(
        b.decoding_reads, 0,
        "BAR dimensionado com decodificação ligada"
    );
}

#[test]
fn bars_dimensionados_e_restaurados() {
    let mut b = q35();
    let before = b.fns.clone();
    let fs = all(&mut b);
    let vga = fs.iter().find(|f| f.device == 0x1111).unwrap();
    assert_eq!(
        vga.bars[0],
        Bar::Memory {
            base: 0x8000_0000,
            size: 16 << 20,
            prefetch: true,
            wide: false
        }
    );
    assert_eq!(vga.bars[1], Bar::None);
    assert_eq!(
        vga.bars[2],
        Bar::Memory {
            base: 0xC000_0000,
            size: 4096,
            prefetch: false,
            wide: false
        }
    );
    let nic = fs.iter().find(|f| f.device == 0x10d3).unwrap();
    assert_eq!(
        nic.bars[2],
        Bar::Io {
            base: 0x6000,
            size: 32
        }
    );
    let blk = fs.iter().find(|f| f.device == 0x1042).unwrap();
    assert_eq!(
        blk.bars[4],
        Bar::Memory {
            base: 0x8_0000_0000,
            size: 16 << 10,
            prefetch: true,
            wide: true
        }
    );
    assert_eq!(blk.bars[5], Bar::None);
    for (at, f) in &before {
        assert_eq!(b.fns[at].regs, f.regs, "{at} mudou depois da varredura");
    }
}

#[test]
fn capabilities_e_ponte() {
    let mut b = q35();
    let fs = all(&mut b);
    let nic = fs.iter().find(|f| f.device == 0x10d3).unwrap();
    assert_eq!(nic.caps.pcie, Some(0xE0));
    assert_eq!(nic.caps.msi, Some(0xD0));
    assert_eq!(
        nic.caps.msix,
        Some(Msix {
            at: 0xA0,
            entries: 5,
            table: BarOffset { bar: 3, offset: 0 },
            pba: BarOffset {
                bar: 3,
                offset: 0x2000
            },
        })
    );
    let bridge = fs.iter().find(|f| f.header == 1).unwrap();
    assert_eq!(bridge.bridge, Some((1, 1)));
    assert_eq!(bridge.caps.pcie, Some(0x40));
    assert_eq!(
        fs.iter().find(|f| f.device == 0x2922).unwrap().bars[4],
        Bar::Io {
            base: 0xC040,
            size: 32
        }
    );
}

#[test]
fn ecam_e_bdf() {
    assert_eq!(
        bdf(1, 2, 3).ecam_offset(),
        (1 << 20) | (2 << 15) | (3 << 12)
    );
    assert_eq!(bdf(255, 31, 7).ecam_offset(), 0x0FFF_F000);
    assert_eq!(format!("{}", bdf(0xa, 0x1f, 7)), "0a:1f.7");
}

/// Configuração com palavras pseudoaleatórias: a varredura termina sem
/// pânico, mesmo com listas de capabilities em laço.
struct Noise(u64);

impl Config for Noise {
    fn read(&mut self, at: Bdf, offset: u16) -> u32 {
        if at.bus > 1 {
            return u32::MAX;
        }
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        let w = self.0 as u32;
        match offset {
            0x04 => w | (reg::STATUS_CAP_LIST << 16),
            0x34 => 0x40,
            o if o >= 0x40 => (w & 0xFFFF_00FF) | 0x4000,
            _ => w,
        }
    }

    fn write(&mut self, _: Bdf, _: u16, _: u32) {}
}

#[test]
fn ruido_nao_entra_em_panico() {
    for seed in 1u64..64 {
        let mut n = Noise(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut count = 0;
        scan(&mut n, 255, |_| count += 1);
        assert!(count <= 2 * 32 * 8);
    }
}
