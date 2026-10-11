//! Gerador pseudoaleatório próprio (xorshift64*, semeado por splitmix64):
//! sem crates externas na imagem (SDD 17.1) e reprodutível pela semente.

/// Estado do gerador; nunca zero.
pub struct Rng(u64);

impl Rng {
    /// Gerador para `seed` (qualquer valor, inclusive zero).
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        Self(if z == 0 { 1 } else { z })
    }

    /// Próximos 64 bits.
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Valor em `[0, n)` (zero se `n` for zero).
    pub fn below(&mut self, n: u64) -> u64 {
        #[allow(clippy::cast_possible_truncation, reason = "parte alta de 128 bits")]
        let v = ((u128::from(self.next()) * u128::from(n)) >> 64) as u64;
        v
    }

    /// Verdadeiro com probabilidade `num / den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    /// Um item de `items` (não vazio).
    pub fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        let i = usize::try_from(self.below(items.len() as u64)).unwrap_or(0);
        items[i]
    }
}
