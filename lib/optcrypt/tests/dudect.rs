//! P5 (ADR 0053): teste estilo dudect de tempo constante. Mede duas
//! classes de entrada com tempos intercalados e aplica o teste t de Welch:
//! |t| acima de 10 indica dependência dos dados.
//!
//! Lento e sensível ao ruído do host, por isso é `#[ignore]`; a campanha
//! roda com `cargo test -p optcrypt --release --test dudect -- --ignored`.

#![allow(clippy::cast_precision_loss, reason = "ns cabem em f64")]

use std::hint::black_box;
use std::time::Instant;

use optcrypt::hmac::{hmac_sha256, verify};
use optcrypt::secret::ct_eq;

const AMOSTRAS: usize = 400_000;
const LIMITE: f64 = 10.0;

#[derive(Default)]
struct Welch {
    n: [f64; 2],
    media: [f64; 2],
    m2: [f64; 2],
}

impl Welch {
    fn push(&mut self, c: usize, x: f64) {
        self.n[c] += 1.0;
        let d = x - self.media[c];
        self.media[c] += d / self.n[c];
        self.m2[c] += d * (x - self.media[c]);
    }
    fn t(&self) -> f64 {
        let v = |c: usize| self.m2[c] / (self.n[c] - 1.0) / self.n[c];
        (self.media[0] - self.media[1]) / (v(0) + v(1)).sqrt()
    }
}

/// Roda `op(classe)` com classes escolhidas por um LCG, descartando
/// os 5% mais lentos (picos de escalonamento) como o dudect original.
fn mede(mut op: impl FnMut(usize)) -> f64 {
    let mut w = Welch::default();
    let mut estado = 0x9e37_79b9_7f4a_7c15u64;
    // Aquecimento: caches, predição de desvios e frequência da CPU.
    for i in 0..20_000 {
        op(i % 2);
    }
    let mut tempos = Vec::with_capacity(AMOSTRAS);
    for _ in 0..AMOSTRAS {
        estado = estado
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let c = usize::from(estado >> 63 == 1);
        let t0 = Instant::now();
        op(c);
        tempos.push((c, t0.elapsed().as_nanos() as f64));
    }
    let mut so_tempos: Vec<f64> = tempos.iter().map(|x| x.1).collect();
    so_tempos.sort_by(f64::total_cmp);
    let corte = so_tempos[AMOSTRAS * 95 / 100];
    for (c, t) in tempos {
        if t <= corte {
            w.push(c, t);
        }
    }
    w.t()
}

#[test]
#[ignore = "campanha de tempo constante; rode com --ignored em --release"]
fn ct_eq_tempo_constante() {
    let a = [0x5au8; 64];
    let igual = a;
    let mut difere_no_inicio = a;
    difere_no_inicio[0] ^= 1;
    let t = mede(|c| {
        let b = if c == 0 { &igual } else { &difere_no_inicio };
        black_box(ct_eq(black_box(&a), black_box(b)));
    });
    assert!(t.abs() < LIMITE, "|t| = {t}");
}

#[test]
#[ignore = "campanha de tempo constante; rode com --ignored em --release"]
fn hmac_verify_tempo_constante() {
    let tag = hmac_sha256(b"chave", b"mensagem");
    let mut ruim = tag;
    ruim[0] ^= 1;
    let t = mede(|c| {
        let alvo = if c == 0 { &tag } else { &ruim };
        black_box(verify(
            black_box(b"chave"),
            black_box(b"mensagem"),
            black_box(alvo),
        ));
    });
    assert!(t.abs() < LIMITE, "|t| = {t}");
}

/// Selar e abrir: classe 0 = texto zerado, classe 1 = texto "aleatório".
#[test]
#[ignore = "campanha de tempo constante; rode com --ignored em --release"]
fn aead_tempo_constante() {
    use optcrypt::aead::{open, seal};
    use optcrypt::secret::Secret;

    let key = Secret::take(&mut [0x42u8; 32]);
    let nonce = [1u8; 12];
    let zeros = [0u8; 256];
    let mut rnd = [0u8; 256];
    for (i, b) in rnd.iter_mut().enumerate() {
        *b = u8::try_from(i * 167 % 256).unwrap();
    }
    let t_seal = mede(|c| {
        let mut buf = if c == 0 { zeros } else { rnd };
        black_box(seal(&key, &nonce, b"aad", black_box(&mut buf)));
    });
    assert!(t_seal.abs() < LIMITE, "selar: |t| = {t_seal}");
    let mut s0 = zeros;
    let mut s1 = rnd;
    let tag0 = seal(&key, &nonce, b"aad", &mut s0);
    let tag1 = seal(&key, &nonce, b"aad", &mut s1);
    let t_open = mede(|c| {
        let (mut buf, tag) = if c == 0 { (s0, tag0) } else { (s1, tag1) };
        black_box(open(&key, &nonce, b"aad", black_box(&mut buf), &tag).is_ok());
    });
    assert!(t_open.abs() < LIMITE, "abrir: |t| = {t_open}");
}
