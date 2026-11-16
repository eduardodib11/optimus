//! SHA-3 e SHAKE (FIPS 202): a esponja Keccak-f[1600].
//!
//! O ML-KEM (FIPS 203) usa SHA3-256, SHA3-512, SHAKE128 e SHAKE256. A
//! permutação só faz operações bit a bit e rotações fixas; os índices
//! dependem apenas da posição na esponja, nunca dos dados.

#[rustfmt::skip]
const RC: [u64; 24] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808a,
    0x8000_0000_8000_8000, 0x0000_0000_0000_808b, 0x0000_0000_8000_0001,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8009, 0x0000_0000_0000_008a,
    0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000a,
    0x0000_0000_8000_808b, 0x8000_0000_0000_008b, 0x8000_0000_0000_8089,
    0x8000_0000_0000_8003, 0x8000_0000_0000_8002, 0x8000_0000_0000_0080,
    0x0000_0000_0000_800a, 0x8000_0000_8000_000a, 0x8000_0000_8000_8081,
    0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
];

/// Rotações do passo ρ, na ordem do percurso de π.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];
/// Percurso do passo π a partir da lane 1.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Keccak-f[1600], 24 rodadas.
fn keccak_f(a: &mut [u64; 25]) {
    for rc in RC {
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut t = a[1];
        for (&j, &r) in PI.iter().zip(&RHO) {
            let prox = a[j];
            a[j] = t.rotate_left(r);
            t = prox;
        }
        for y in 0..5 {
            let mut linha = [0u64; 5];
            linha.copy_from_slice(&a[5 * y..5 * y + 5]);
            for x in 0..5 {
                a[5 * y + x] = linha[x] ^ (!linha[(x + 1) % 5] & linha[(x + 2) % 5]);
            }
        }
        a[0] ^= rc;
    }
}

/// Esponja com taxa `rate` bytes e byte de domínio `ds` (0x06 no SHA-3,
/// 0x1f no SHAKE).
#[derive(Clone)]
struct Sponge {
    st: [u64; 25],
    rate: usize,
    pos: usize,
    ds: u8,
    squeezing: bool,
}

impl Sponge {
    const fn new(rate: usize, ds: u8) -> Self {
        Self {
            st: [0; 25],
            rate,
            pos: 0,
            ds,
            squeezing: false,
        }
    }

    fn xor_byte(&mut self, i: usize, b: u8) {
        self.st[i / 8] ^= u64::from(b) << (8 * (i % 8));
    }

    fn absorb(&mut self, data: &[u8]) {
        debug_assert!(!self.squeezing, "absorver depois de espremer");
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f(&mut self.st);
                self.pos = 0;
            }
        }
    }

    fn pad(&mut self) {
        self.xor_byte(self.pos, self.ds);
        self.xor_byte(self.rate - 1, 0x80);
        keccak_f(&mut self.st);
        self.pos = 0;
        self.squeezing = true;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.pad();
        }
        for o in out {
            if self.pos == self.rate {
                keccak_f(&mut self.st);
                self.pos = 0;
            }
            *o = self.st[self.pos / 8].to_le_bytes()[self.pos % 8];
            self.pos += 1;
        }
    }
}

impl Drop for Sponge {
    fn drop(&mut self) {
        // A esponja absorve chaves e sementes do ML-KEM.
        for w in &mut self.st {
            *w = 0;
        }
        core::hint::black_box(&mut self.st);
    }
}

macro_rules! sha3 {
    ($nome:ident, $fn:ident, $saida:expr, $doc:literal) => {
        #[doc = concat!($doc, " incremental.")]
        #[derive(Clone)]
        pub struct $nome(Sponge);

        impl Default for $nome {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $nome {
            /// Bytes do resumo.
            pub const OUT_LEN: usize = $saida;

            /// Estado inicial.
            #[must_use]
            pub const fn new() -> Self {
                Self(Sponge::new(200 - 2 * $saida, 0x06))
            }

            /// Alimenta o hash com `data`.
            pub fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            /// Termina e devolve o resumo.
            #[must_use]
            pub fn finalize(mut self) -> [u8; $saida] {
                let mut out = [0u8; $saida];
                self.0.squeeze(&mut out);
                out
            }
        }

        #[doc = concat!($doc, " de `data` de uma vez.")]
        #[must_use]
        pub fn $fn(data: &[u8]) -> [u8; $saida] {
            let mut h = $nome::new();
            h.update(data);
            h.finalize()
        }
    };
}

sha3!(Sha3_256, sha3_256, 32, "SHA3-256");
sha3!(Sha3_512, sha3_512, 64, "SHA3-512");

macro_rules! shake {
    ($nome:ident, $seg:expr, $doc:literal) => {
        #[doc = concat!($doc, ": absorve com `update` e espreme quantos bytes quiser com `squeeze`.")]
        #[derive(Clone)]
        pub struct $nome(Sponge);

        impl Default for $nome {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $nome {
            /// Estado inicial.
            #[must_use]
            pub const fn new() -> Self {
                Self(Sponge::new(200 - $seg / 4, 0x1f))
            }

            /// Alimenta a esponja. Não pode vir depois de `squeeze`.
            pub fn update(&mut self, data: &[u8]) {
                self.0.absorb(data);
            }

            /// Espreme `out.len()` bytes; chamadas seguidas continuam a saída.
            pub fn squeeze(&mut self, out: &mut [u8]) {
                self.0.squeeze(out);
            }
        }
    };
}

shake!(Shake128, 128, "SHAKE128");
shake!(Shake256, 256, "SHAKE256");

/// SHAKE256 de `data`, enchendo `out` (o `J` e o `PRF` do ML-KEM).
pub fn shake256(data: &[&[u8]], out: &mut [u8]) {
    let mut x = Shake256::new();
    for d in data {
        x.update(d);
    }
    x.squeeze(out);
}

#[cfg(test)]
mod tests;
