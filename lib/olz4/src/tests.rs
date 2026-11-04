//! Testes no host: vetores escritos à mão a partir do formato, round-trip
//! em larga escala e descompressão de entrada corrompida.

use super::*;
use std::vec::Vec;

/// Gerador xorshift simples para os testes.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn roundtrip(data: &[u8]) -> Vec<u8> {
    let mut packed = std::vec![0u8; max_compressed_len(data.len())];
    let n = compress(data, &mut packed).expect("compress");
    let mut back = std::vec![0u8; data.len()];
    let m = decompress(&packed[..n], &mut back).expect("decompress");
    assert_eq!(m, data.len());
    assert_eq!(back, data);
    packed.truncate(n);
    packed
}

#[test]
fn vazio_e_um_token_zero() {
    assert_eq!(roundtrip(b""), [0x00]);
    let mut out = [0u8; 0];
    assert_eq!(decompress(&[0x00], &mut out), Ok(0));
}

#[test]
fn so_literais_vetor_do_formato() {
    // Quatro literais: token 0x40 (literal 4, sem casamento).
    assert_eq!(roundtrip(b"abcd"), [0x40, b'a', b'b', b'c', b'd']);
}

#[test]
fn literais_com_comprimento_extra() {
    // 20 bytes sem repetição: token 0xF0 e extra 5 (20 - 15).
    let data: Vec<u8> = (0..20).collect();
    let packed = roundtrip(&data);
    assert_eq!(packed[0], 0xF0);
    assert_eq!(packed[1], 5);
    assert_eq!(&packed[2..], &data[..]);
}

#[test]
fn casamento_decodificado_de_vetor_escrito_a_mao() {
    // "a" literal, casamento offset 1 de 5 bytes (ml = 1), depois token final.
    let packed = [0x11, b'a', 1, 0, 0x00];
    let mut out = [0u8; 6];
    let n = decompress(&packed, &mut out).unwrap();
    assert_eq!(&out[..n], b"aaaaaa");
}

#[test]
fn repeticao_longa_usa_comprimento_extra_do_casamento() {
    let data = std::vec![b'z'; 1000];
    let packed = roundtrip(&data);
    assert!(packed.len() < 40, "ratio ruim: {}", packed.len());
}

#[test]
fn texto_repetitivo_comprime() {
    let data = "optimus os ".repeat(200);
    let packed = roundtrip(data.as_bytes());
    assert!(packed.len() * 4 < data.len());
}

#[test]
fn round_trip_em_um_milhao_de_entradas() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut buf = [0u8; 64];
    for _ in 0..1_000_000 {
        let len = (rng.next() % 64) as usize;
        // Alfabeto pequeno em metade dos casos, para haver casamentos.
        let alpha = if rng.next() & 1 == 0 { 3 } else { 256 };
        for b in buf.iter_mut().take(len) {
            *b = (rng.next() % alpha) as u8;
        }
        roundtrip(&buf[..len]);
    }
}

#[test]
fn offset_zero_e_fora_da_saida_sao_erros() {
    let mut out = [0u8; 16];
    // Literal "a", casamento com offset 0.
    assert_eq!(
        decompress(&[0x11, b'a', 0, 0, 0], &mut out),
        Err(Error::BadOffset)
    );
    // Offset 2 com só 1 byte já escrito.
    assert_eq!(
        decompress(&[0x11, b'a', 2, 0, 0], &mut out),
        Err(Error::BadOffset)
    );
}

#[test]
fn entrada_truncada_e_erro() {
    let mut out = [0u8; 64];
    assert_eq!(decompress(&[], &mut out), Err(Error::Truncated));
    assert_eq!(decompress(&[0x50, b'a'], &mut out), Err(Error::Truncated));
    assert_eq!(decompress(&[0xF0], &mut out), Err(Error::Truncated));
    assert_eq!(
        decompress(&[0x11, b'a', 1], &mut out),
        Err(Error::Truncated)
    );
}

#[test]
fn saida_pequena_e_erro() {
    let mut out = [0u8; 2];
    assert_eq!(
        decompress(&[0x40, b'a', b'b', b'c', b'd'], &mut out),
        Err(Error::OutputTooSmall)
    );
    let mut packed = [0u8; 4];
    assert_eq!(compress(b"abcd", &mut packed), Err(Error::OutputTooSmall));
}

#[test]
fn entrada_aleatoria_nao_causa_panico() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let mut out = [0u8; 512];
    for _ in 0..200_000 {
        let len = (rng.next() % 48) as usize;
        let garbage: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let _ = decompress(&garbage, &mut out);
    }
}
