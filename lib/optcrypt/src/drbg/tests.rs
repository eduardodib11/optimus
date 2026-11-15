//! Comportamento exigido pela ADR 0054: soma sem substituir, kernel
//! obrigatório, apagamento rápido de chave.

use super::*;

fn semeado(kernel: &[u8], virtio: &[u8]) -> Drbg {
    let mut d = Drbg::new();
    d.reseed(kernel, virtio).unwrap();
    d
}

fn saida(d: &mut Drbg, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    d.fill(&mut v).unwrap();
    v
}

#[test]
fn recusa_sem_semente_e_sem_kernel() {
    let mut d = Drbg::new();
    assert_eq!(d.fill(&mut [0u8; 8]), Err(Error::NotSeeded));
    assert_eq!(d.reseed(&[], &[1; 64]), Err(Error::NoKernelEntropy));
    assert!(!d.is_seeded());
    assert_eq!(d.reseed(&[1; 150], &[2; 100]), Err(Error::InputTooLong));
}

#[test]
fn determinismo_e_soma_das_fontes() {
    // Mesmas entradas, mesma sequência.
    assert_eq!(
        saida(&mut semeado(&[1; 72], &[2; 64]), 40),
        saida(&mut semeado(&[1; 72], &[2; 64]), 40)
    );
    // Mesma contribuição virtio, kernel diferente: sementes diferentes
    // (o dispositivo soma, não substitui).
    assert_ne!(
        saida(&mut semeado(&[1; 72], &[2; 64]), 40),
        saida(&mut semeado(&[9; 72], &[2; 64]), 40)
    );
    // Kernel igual, virtio diferente ou ausente: também muda.
    assert_ne!(
        saida(&mut semeado(&[1; 72], &[2; 64]), 40),
        saida(&mut semeado(&[1; 72], &[]), 40)
    );
}

#[test]
fn saidas_consecutivas_diferem_e_o_tamanho_nao_importa() {
    let mut d = semeado(&[7; 72], &[]);
    let (a, b) = (saida(&mut d, 32), saida(&mut d, 32));
    assert_ne!(a, b);
    // Pedidos grandes (mais de um bloco) e pequenos funcionam.
    for n in [0, 1, 31, 32, 33, 100, 1000] {
        assert_eq!(saida(&mut d, n).len(), n);
    }
}

#[test]
fn reseed_depende_da_chave_atual() {
    let (mut a, mut b) = (semeado(&[1; 72], &[]), semeado(&[1; 72], &[]));
    let _ = saida(&mut a, 16);
    a.reseed(&[5; 72], &[]).unwrap();
    b.reseed(&[5; 72], &[]).unwrap();
    // `a` consumiu uma saída antes: a chave atual difere, então a semente também.
    assert_ne!(saida(&mut a, 32), saida(&mut b, 32));
}

#[test]
fn bytes_sao_bem_distribuidos() {
    let mut d = semeado(&[3; 72], &[4; 64]);
    let v = saida(&mut d, 65536);
    let uns: u32 = v.iter().map(|b| b.count_ones()).sum();
    // 524288 bits: média 262144, desvio ~362; aceita ±6 desvios.
    assert!(uns.abs_diff(262_144) < 2200, "bits 1: {uns}");
}
