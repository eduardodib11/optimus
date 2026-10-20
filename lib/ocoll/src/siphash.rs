//! SipHash-1-3 (Aumasson e Bernstein): 1 rodada de compressão por bloco de
//! 8 bytes e 3 na finalização, com chave de 128 bits. É o hasher do
//! `HashMap` do `std`.

use core::hash::Hasher;

/// SipHash-1-3 com chave de 128 bits.
#[derive(Clone, Debug)]
pub struct SipHasher13 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    /// Bytes que ainda não completaram uma palavra (little-endian).
    tail: u64,
    /// Quantos bytes há em `tail` (0 a 7).
    ntail: usize,
    /// Bytes escritos no total.
    length: usize,
}

impl SipHasher13 {
    /// Hasher com a chave `(k0, k1)`.
    #[must_use]
    pub const fn new_with_keys(k0: u64, k1: u64) -> Self {
        Self {
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
            tail: 0,
            ntail: 0,
            length: 0,
        }
    }

    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        self.round();
        self.v0 ^= m;
    }
}

impl Hasher for SipHasher13 {
    fn write(&mut self, bytes: &[u8]) {
        self.length += bytes.len();
        let mut bytes = bytes;
        // Caminho rápido: sem resto pendente, palavras inteiras direto.
        while self.ntail == 0 && bytes.len() >= 8 {
            let (word, rest) = bytes.split_at(8);
            self.compress(u64::from_le_bytes(word.try_into().unwrap_or([0; 8])));
            bytes = rest;
        }
        for &b in bytes {
            self.tail |= u64::from(b) << (8 * self.ntail);
            self.ntail += 1;
            if self.ntail == 8 {
                let m = self.tail;
                self.compress(m);
                self.tail = 0;
                self.ntail = 0;
            }
        }
    }

    fn finish(&self) -> u64 {
        let mut s = self.clone();
        let b = ((self.length as u64 & 0xff) << 56) | self.tail;
        s.compress(b);
        s.v2 ^= 0xff;
        s.round();
        s.round();
        s.round();
        s.v0 ^ s.v1 ^ s.v2 ^ s.v3
    }
}
