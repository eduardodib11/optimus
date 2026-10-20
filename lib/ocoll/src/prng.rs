//! Geradores pseudoaleatórios **não criptográficos** (ADR 0039, item 4):
//! para índices de tabela, sorteio de endereços e testes. Chaves e nonces
//! vêm de `ostd::rand::secure_fill`.

/// `SplitMix64`: uma palavra de estado; bom para derivar sementes.
#[derive(Clone, Debug)]
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    /// Próxima palavra.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        mix64(self.0)
    }
}

/// A função final do `SplitMix64`: bijeção de `u64` com boa difusão.
#[must_use]
pub const fn mix64(x: u64) -> u64 {
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// xoshiro256++ (Blackman e Vigna): 256 bits de estado, período 2²⁵⁶ − 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xoshiro256pp {
    s: [u64; 4],
}

impl Xoshiro256pp {
    /// Gerador com o estado `s`. O estado todo zero é substituído (o gerador
    /// ficaria preso no zero).
    #[must_use]
    pub fn from_state(s: [u64; 4]) -> Self {
        if s == [0; 4] {
            return Self::from_u64(0);
        }
        Self { s }
    }

    /// Gerador semeado por 32 bytes (por exemplo, de `secure_fill`).
    #[must_use]
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        let mut s = [0u64; 4];
        for (w, c) in s.iter_mut().zip(seed.chunks_exact(8)) {
            *w = u64::from_le_bytes(c.try_into().unwrap_or([0; 8]));
        }
        Self::from_state(s)
    }

    /// Gerador semeado por uma palavra, expandida com `SplitMix64`.
    #[must_use]
    pub fn from_u64(seed: u64) -> Self {
        let mut sm = SplitMix64(seed);
        Self {
            s: [sm.next_u64(), sm.next_u64(), sm.next_u64(), sm.next_u64()],
        }
    }

    /// Próxima palavra.
    pub fn next_u64(&mut self) -> u64 {
        let s = &mut self.s;
        let result = s[0].wrapping_add(s[3]).rotate_left(23).wrapping_add(s[0]);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    /// Valor uniforme em `0..n` (rejeição, sem viés). `n = 0` dá 0.
    pub fn below(&mut self, n: u64) -> u64 {
        if n <= 1 {
            return 0;
        }
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let x = self.next_u64();
            if x < zone {
                return x % n;
            }
        }
    }

    /// Enche `buf` de bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let w = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
    }
}
