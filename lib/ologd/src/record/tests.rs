//! Testes do registro de log.

use super::*;

#[test]
fn ida_e_volta() {
    let mut b = [0u8; MAX_PAYLOAD];
    let n = encode(42, Level::Warn, KERNEL_TID, "olá", &mut b).unwrap();
    let r = decode(&b[..n]).unwrap();
    assert_eq!(
        (r.ts_ns, r.level, r.tid, r.msg),
        (42, Level::Warn, KERNEL_TID, "olá")
    );
    assert_eq!(b[8], 2, "warn é 2 na ADR 0036");
}

#[test]
fn mensagem_longa_e_cortada_na_fronteira_utf8() {
    let mut b = [0u8; MAX_PAYLOAD];
    let msg = "é".repeat(400);
    let n = encode(0, Level::Info, 1, &msg, &mut b).unwrap();
    let r = decode(&b[..n]).unwrap();
    assert_eq!(r.msg.len(), MAX_MSG);
    assert!(encode(0, Level::Info, 1, "abc", &mut [0u8; 18]).is_none());
}

#[test]
fn campos_conferidos() {
    let mut b = [0u8; 64];
    let n = encode(1, Level::Info, 0, "x", &mut b).unwrap();
    b[9] = 2;
    // u64 "k" = 7; string "s" = "ab".
    let f = [
        1, b'k', 1, 7, 0, 0, 0, 0, 0, 0, 0, 1, b's', 0, 2, 0, b'a', b'b',
    ];
    b[n..n + f.len()].copy_from_slice(&f);
    assert_eq!(decode(&b[..n + f.len()]).unwrap().msg, "x");
    assert_eq!(decode(&b[..n + f.len() - 1]), Err(DecodeError::Malformed));
}

#[test]
fn entradas_hostis_nao_quebram() {
    let mut b = [0u8; 40];
    let n = encode(1, Level::Info, 0, "abc", &mut b).unwrap();
    let mut x = b;
    x[8] = 0;
    assert_eq!(decode(&x[..n]), Err(DecodeError::BadLevel));
    x = b;
    x[12] = 200;
    assert_eq!(decode(&x[..n]), Err(DecodeError::Malformed));
    x = b;
    x[16] = 0xFF;
    assert_eq!(decode(&x[..n]), Err(DecodeError::NotUtf8));
    let mut seed = 0x1234_5678_u32;
    for len in 0..40 {
        for _ in 0..200 {
            for byte in &mut x[..len] {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *byte = seed.to_le_bytes()[0];
            }
            let _ = decode(&x[..len]);
        }
    }
}
