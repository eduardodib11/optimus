//! Portas efêmeras (RFC 6056): o `netd` sorteia no `keyd` e esta tabela só
//! guarda quais estão em uso. A faixa é a da IANA, 49152 a 65535.

/// Primeira porta efêmera.
pub const FIRST: u16 = 49152;
/// Quantidade de portas efêmeras.
pub const COUNT: usize = 65536 - FIRST as usize;

/// Quais portas efêmeras estão em uso.
#[derive(Debug)]
pub struct Ephemeral {
    used: [u64; COUNT / 64],
}

impl Default for Ephemeral {
    fn default() -> Self {
        Self::new()
    }
}

impl Ephemeral {
    /// Tabela vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            used: [0; COUNT / 64],
        }
    }

    fn index(port: u16) -> Option<usize> {
        usize::from(port)
            .checked_sub(usize::from(FIRST))
            .filter(|i| *i < COUNT)
    }

    /// A porta está em uso (portas fora da faixa contam como livres: não são
    /// desta tabela).
    #[must_use]
    pub fn in_use(&self, port: u16) -> bool {
        Self::index(port).is_some_and(|i| self.used[i / 64] >> (i % 64) & 1 != 0)
    }

    /// Reserva uma porta livre, começando em `random` (do `keyd`) e andando
    /// até achar; `None` se todas estão em uso.
    pub fn alloc(&mut self, random: u32) -> Option<u16> {
        let start = random as usize % COUNT;
        for k in 0..COUNT {
            let i = (start + k) % COUNT;
            if self.used[i / 64] >> (i % 64) & 1 == 0 {
                self.used[i / 64] |= 1 << (i % 64);
                return u16::try_from(i + usize::from(FIRST)).ok();
            }
        }
        None
    }

    /// Reserva uma porta pedida, se estiver livre.
    pub fn reserve(&mut self, port: u16) -> bool {
        match Self::index(port) {
            Some(i) if self.used[i / 64] >> (i % 64) & 1 == 0 => {
                self.used[i / 64] |= 1 << (i % 64);
                true
            }
            _ => false,
        }
    }

    /// Devolve uma porta.
    pub fn release(&mut self, port: u16) {
        if let Some(i) = Self::index(port) {
            self.used[i / 64] &= !(1 << (i % 64));
        }
    }
}
