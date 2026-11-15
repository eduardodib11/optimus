#![no_main]

use libfuzzer_sys::fuzz_target;
use ogpt::Disk;

/// Disco feito dos bytes da entrada: o setor `lba` é uma janela da entrada
/// (em ciclo), então cabeçalho e tabela são arbitrários. O primeiro byte
/// escolhe o tamanho do setor e a quantidade de setores.
struct Fuzzed<'a> {
    data: &'a [u8],
    ss: usize,
    sectors: u64,
}

impl Disk for Fuzzed<'_> {
    fn sector_size(&self) -> usize {
        self.ss
    }
    fn sectors(&self) -> u64 {
        self.sectors
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        if lba >= self.sectors || self.data.is_empty() {
            return false;
        }
        let start = usize::try_from(lba % 64).unwrap_or(0) * 97;
        for (i, b) in buf.iter_mut().enumerate() {
            *b = self.data[(start + i) % self.data.len()];
        }
        true
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&h, rest)) = data.split_first() else { return };
    let ss = if h & 1 == 0 { 512 } else { 4096 };
    let sectors = u64::from(h >> 1) * 37 + 6;
    let mut d = Fuzzed { data: rest, ss, sectors };
    if let Ok(t) = ogpt::parse(&mut d) {
        for p in t.parts() {
            let _ = (p.sectors(), p.aligned_4k(ss), p.name_is("data"));
        }
    }
});
