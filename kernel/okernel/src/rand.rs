//! DRBG do kernel (ADR 0039, item 4; T-337).
//!
//! Gerador determinístico sobre o BLAKE3 em modo chaveado (`optcrypt`). A
//! chave inicial é `BLAKE3(semente ‖ "okernel-drbg")`, com a semente de 64
//! bytes que o `optboot` deixa em `BootInfo.rng_seed`. Cada saída é o XOF
//! do BLAKE3 chaveado com a chave atual sobre `domínio ‖ tamanho ‖ extra`:
//! os primeiros 32 bytes viram a chave nova e o resto é entregue
//! (apagamento rápido de chave: quem lê a chave depois de uma saída não
//! reconstrói as anteriores). `extra` é a mistura que o kernel passa a cada
//! pedido (TSC e `RDSEED`/`RDRAND` quando existirem), e um DRBG por CPU
//! sai do principal por [`Drbg::fork`].
//!
//! Este módulo só tem a construção, testável no host; as fontes de mistura,
//! o estado por CPU e a `sys_info` de entropia ficam no binário (`krand`).

#![forbid(unsafe_code)]

use optcrypt::blake3::{Hasher, KEY_LEN};

/// Rótulo da chave inicial: `BLAKE3(semente ‖ SEED_LABEL)`.
pub const SEED_LABEL: &[u8] = b"okernel-drbg";
/// Bytes entregues por passo; pedidos maiores são cortados em passos, cada
/// um com a própria troca de chave.
pub const MAX_STEP: usize = 64;

/// Domínio de uma saída comum.
const DOMAIN_OUTPUT: u8 = 0;
/// Domínio da chave de um DRBG filho ([`Drbg::fork`]).
const DOMAIN_FORK: u8 = 1;

/// O DRBG: só a chave atual. Sem semente não existe (ver
/// [`Drbg::from_seed`]); a chave é apagada ao soltar o valor.
pub struct Drbg {
    key: [u8; KEY_LEN],
}

impl Drbg {
    /// DRBG semeado por `seed`; `None` se a semente é toda zero (o
    /// `optboot` não achou fonte de entropia: ADR 0039, item 4).
    #[must_use]
    pub fn from_seed(seed: &[u8]) -> Option<Self> {
        if seed.iter().all(|&b| b == 0) {
            return None;
        }
        let key = Hasher::new().update(seed).update(SEED_LABEL).finalize();
        Some(Self { key })
    }

    /// DRBG que continua de uma chave guardada por [`Self::into_key`].
    #[must_use]
    pub const fn from_key(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }

    /// A chave atual, para guardar fora do valor (o valor é apagado).
    #[must_use]
    pub fn into_key(mut self) -> [u8; KEY_LEN] {
        let key = self.key;
        wipe(&mut self.key);
        key
    }

    /// Enche `out` com bytes aleatórios, misturando `extra` em cada passo
    /// de até [`MAX_STEP`] bytes. Vazio não muda o estado.
    pub fn fill(&mut self, extra: &[u8], out: &mut [u8]) {
        for chunk in out.chunks_mut(MAX_STEP) {
            self.step(DOMAIN_OUTPUT, &[], extra, chunk);
        }
    }

    /// DRBG filho de id `id` (um por CPU), com chave tirada deste; este
    /// troca de chave como numa saída.
    #[must_use]
    pub fn fork(&mut self, id: u32, extra: &[u8]) -> Self {
        let mut key = [0; KEY_LEN];
        self.step(DOMAIN_FORK, &id.to_le_bytes(), extra, &mut key);
        Self { key }
    }

    /// Um passo: XOF do BLAKE3 com a chave atual sobre `domínio ‖ id ‖
    /// tamanho ‖ extra`; 32 bytes viram a chave nova, o resto vai a `out`
    /// (até [`MAX_STEP`] bytes).
    fn step(&mut self, domain: u8, id: &[u8], extra: &[u8], out: &mut [u8]) {
        assert!(out.len() <= MAX_STEP, "passo do DRBG maior que MAX_STEP");
        let mut buf = [0u8; KEY_LEN + MAX_STEP];
        let n = KEY_LEN + out.len();
        let mut h = Hasher::new_keyed(&self.key);
        h.update(&[domain])
            .update(id)
            .update(&(out.len() as u64).to_le_bytes())
            .update(extra);
        h.finalize_xof(&mut buf[..n]);
        self.key.copy_from_slice(&buf[..KEY_LEN]);
        out.copy_from_slice(&buf[KEY_LEN..n]);
        wipe(&mut buf);
        // O `Hasher` guarda a chave antiga; sobrescrevê-lo no lugar é o
        // apagamento possível sem acesso aos campos dele.
        h = Hasher::new();
        core::hint::black_box(&mut h);
    }
}

impl Drop for Drbg {
    fn drop(&mut self) {
        wipe(&mut self.key);
    }
}

/// Zera `bytes` sem o otimizador poder omitir a escrita.
fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}

#[cfg(test)]
mod tests;
