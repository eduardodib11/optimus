//! Testes do fio de `DeviceBus`.

use super::*;
use alloc::string::ToString;
use alloc::vec;

fn edu() -> (Node, Resources) {
    let node = Node {
        id: 0x18,
        bus: Bus::Pci,
        pci_id: Some((0x1234, 0x11e8)),
        class: Some(Class {
            class: 0x00,
            subclass: 0xff,
            prog_if: 0,
        }),
        compatible: vec![],
    };
    let mut res = Resources {
        bdf: Some(0x18),
        msi: true,
        ..Resources::default()
    };
    res.bars[0] = Some(Bar {
        io: false,
        prefetch: false,
        base: 0xfea0_0000,
        size: 1 << 20,
    });
    (node, res)
}

#[test]
fn publish_ida_e_volta() {
    let mut buf = [0u8; MAX_PUBLISH_BYTES];
    let (node, res) = edu();
    let n = encode_publish(&node, &res, &mut buf).unwrap();
    assert_eq!(n, 56 + 24, "cabeça de 52 arredondada a 56 e um BAR");
    assert_eq!(decode_publish(&buf[..n]).unwrap(), (node, res));
    // Nó do ACPI: sem ids PCI, com dois `compatible`.
    let acpi = Node {
        id: 0x1_0000,
        bus: Bus::Acpi,
        pci_id: None,
        class: None,
        compatible: vec!["PNP0501".to_string(), "QEMU0002".to_string()],
    };
    let mut ports = Resources::default();
    ports.bars[2] = Some(Bar {
        io: true,
        prefetch: false,
        base: 0x3f8,
        size: 8,
    });
    let n = encode_publish(&acpi, &ports, &mut buf).unwrap();
    assert_eq!(decode_publish(&buf[..n]).unwrap(), (acpi.clone(), ports));
    // Nó legado (ADR 0049, item 8): portas e IRQs ISA do PS/2.
    let mut ps2 = Resources::default();
    ps2.ports[0] = Some(Ports {
        base: 0x60,
        count: 1,
    });
    ps2.ports[1] = Some(Ports {
        base: 0x64,
        count: 1,
    });
    ps2.irqs[0] = Some(1);
    ps2.irqs[1] = Some(12);
    let n = encode_publish(&acpi, &ps2, &mut buf).unwrap();
    assert_eq!(decode_publish(&buf[..n]).unwrap(), (acpi, ps2));
}

#[test]
fn recusa_o_que_esta_fora_do_formato() {
    let mut buf = [0u8; MAX_PUBLISH_BYTES];
    let (node, res) = edu();
    let n = encode_publish(&node, &res, &mut buf).unwrap();
    let mut bad = buf;
    bad[4] = 2; // barramento
    assert_eq!(decode_publish(&bad[..n]), Err(Error::BadMessage));
    let mut bad = buf;
    bad[5] |= 0x10; // bit de `flags` desconhecido
    assert_eq!(decode_publish(&bad[..n]), Err(Error::BadMessage));
    let mut bad = buf;
    bad[56] = 6; // índice de BAR
    assert_eq!(decode_publish(&bad[..n]), Err(Error::BadMessage));
    assert_eq!(decode_publish(&buf[..n + 8]), Err(Error::BadMessage));
    // BAR repetido e tetos.
    let mut two = res;
    two.bars[1] = two.bars[0];
    let n = encode_publish(&node, &two, &mut buf).unwrap();
    let mut bad = buf;
    bad[56 + 24] = 0;
    assert_eq!(decode_publish(&bad[..n]), Err(Error::BadMessage));
    let long = Node {
        compatible: vec!["x".repeat(MAX_NAME + 1)],
        ..node
    };
    assert_eq!(
        encode_publish(&long, &Resources::default(), &mut buf),
        Err(Error::TooLarge)
    );
}

#[test]
fn rotulos_e_erros() {
    assert_eq!(method_of(label(Method::Publish)), Some(Method::Publish));
    assert_eq!(method_of(label(Method::Publish) | 1), None);
    assert_eq!(method_of(1 << 16 | label(Method::Publish)), None);
    assert_eq!(method_of(osvc_like()), None);
    let mut buf = [0u8; 8];
    let n = encode_error(DevError::Full, &mut buf).unwrap();
    assert_eq!(decode_error(&buf[..n]), Ok(DevError::Full));
    buf[0] = 9;
    assert_eq!(decode_error(&buf[..n]), Err(Error::BadMessage));
}

/// Rótulo de outra interface.
fn osvc_like() -> u64 {
    u64::from(interface_id().wrapping_add(1)) << 32
}
