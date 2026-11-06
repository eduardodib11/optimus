//! Testes do protocolo `Supervisor`.

use super::*;

fn caps() -> [CapDesc; 3] {
    [
        CapDesc {
            kind: KIND_CONTROL,
            index: 0,
            handle: 5,
            name_hash: 0,
        },
        CapDesc {
            kind: KIND_MEM,
            index: QUOTA_INDEX,
            handle: 6,
            name_hash: 0,
        },
        CapDesc {
            kind: KIND_PROVIDE,
            index: 0,
            handle: 7,
            name_hash: 0xA17C_D8BB,
        },
    ]
}

#[test]
fn boot_ida_e_volta() {
    let mut buf = [0u8; MAX_BOOT_BYTES];
    let n = encode_boot(&caps(), 3, &mut buf).unwrap();
    assert_eq!(n, 16 + 40, "cabeça de 16 e 36 bytes arredondados a 40");
    let b = decode_boot(&buf[..n]).unwrap();
    assert_eq!(b.caps(), caps());
    assert_eq!(b.generation, 3);
    assert_eq!(b.quota(), Some(6));
    assert_eq!(b.provided(0xA17C_D8BB), Some(7));
    assert_eq!(b.find(KIND_CONTROL, 0).map(|c| c.handle), Some(5));
}

#[test]
fn layout_da_adr_0033() {
    let mut buf = [0u8; MAX_BOOT_BYTES];
    let n = encode_boot(&caps()[2..], 1, &mut buf).unwrap();
    // Cabeça: ponteiro (deslocamento 16, contagem 1) e geração.
    assert_eq!(&buf[..10], &[16, 0, 0, 0, 1, 0, 0, 0, 1, 0]);
    // CapDesc: kind em 0, index em 2, handle em 4, name_hash em 8.
    assert_eq!(
        &buf[16..28],
        &[6, 0, 0, 0, 7, 0, 0, 0, 0xBB, 0xD8, 0x7C, 0xA1]
    );
    assert_eq!(n, 32);
}

#[test]
fn corpos_ruins_sao_recusados() {
    let mut buf = [0u8; MAX_BOOT_BYTES];
    let n = encode_boot(&caps(), 1, &mut buf).unwrap();
    assert!(decode_boot(&buf[..n - 8]).is_err());
    let mut x = buf;
    x[4] = 97;
    assert!(decode_boot(&x[..n]).is_err());
    let muitos = [CapDesc::default(); MAX_CAPS + 1];
    assert!(encode_boot(&muitos, 1, &mut [0u8; 4096]).is_err());
    assert!(encode_boot(&caps(), 1, &mut [0u8; 20]).is_err());
}

#[test]
fn rotulos() {
    for m in [
        Method::Bootstrap,
        Method::Ready,
        Method::Connect,
        Method::NameOf,
    ] {
        assert_eq!(method_of(label(m)), Some(m));
    }
    assert_eq!(method_of(label(Method::Ready) | 1 << 16), None);
    assert_eq!(method_of(4), None);
    assert_eq!(SvcError::from_u8(3), Some(SvcError::Busy));
    assert_eq!(SvcError::from_u8(4), None);
}

#[test]
fn connect_name_of_e_erro_vao_e_voltam() {
    let mut b = [0u8; MAX_SHORT_BYTES];
    let n = encode_connect(0xDEAD_BEEF, 7, &mut b).unwrap();
    assert_eq!(decode_connect(&b[..n]), Ok((0xDEAD_BEEF, 7)));
    let n = encode_name_of(42, &mut b).unwrap();
    assert_eq!(decode_name_of(&b[..n]), Ok(42));
    let n = encode_name("timed", &mut b).unwrap();
    assert_eq!(decode_name(&b[..n]), Ok("timed"));
    assert!(encode_name(&"x".repeat(MAX_NAME + 1), &mut b).is_err());
    let n = encode_error(SvcError::NotRunning, &mut b).unwrap();
    assert_eq!(decode_error(&b[..n]), Ok(SvcError::NotRunning));
    assert!(decode_connect(&b[..4]).is_err());
}
