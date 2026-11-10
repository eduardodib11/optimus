#![no_main]

use libfuzzer_sys::fuzz_target;
use opci::{Bdf, Config};

/// Espaço de configuração feito dos bytes da entrada: cada leitura é uma
/// palavra da entrada (repetida em ciclo), com escritas guardadas à parte
/// para o dimensionamento de BARs ver o que gravou.
struct Fuzzed<'a> {
    data: &'a [u8],
    writes: Vec<(Bdf, u16, u32)>,
}

impl Config for Fuzzed<'_> {
    fn read(&mut self, bdf: Bdf, offset: u16) -> u32 {
        if let Some(&(_, _, v)) = self.writes.iter().rev().find(|w| w.0 == bdf && w.1 == offset) {
            return v;
        }
        let words = self.data.len() / 4;
        if words == 0 {
            return 0xFFFF_FFFF;
        }
        // Cada função enxerga uma janela própria; a maioria cai fora do ID
        // e o que sobra dá funções reais com cabeçalho arbitrário.
        let slot = usize::from(bdf.dev) * 8 + usize::from(bdf.func);
        let w = (slot * 7 + usize::from(bdf.bus) * 131 + usize::from(offset / 4)) % words;
        let b = &self.data[w * 4..w * 4 + 4];
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    fn write(&mut self, bdf: Bdf, offset: u16, value: u32) {
        if self.writes.len() < 256 {
            self.writes.push((bdf, offset, value));
        }
    }
}

// O espaço de configuração vem do dispositivo: a varredura nunca pode dar pânico.
fuzz_target!(|data: &[u8]| {
    let Some((&last, rest)) = data.split_first() else {
        return;
    };
    let mut cfg = Fuzzed { data: rest, writes: Vec::new() };
    let mut n = 0u32;
    opci::scan(&mut cfg, last % 4, |f| {
        n += 1;
        let _ = f.to_string();
    });
    std::hint::black_box(n);
});
