//! Testes de host da MADT com as tabelas reais do QEMU q35 (`-smp 1, 2, 4,
//! 8`, capturadas pelo próprio kernel) e com tabelas estragadas.

use super::*;
use crate::acpi::tests::{fix_checksum, machine_with};

const SMP: [(usize, &[u8]); 4] = [
    (1, include_bytes!("qemu-q35-smp1.bin")),
    (2, include_bytes!("qemu-q35-smp2.bin")),
    (4, include_bytes!("qemu-q35-smp4.bin")),
    (8, include_bytes!("qemu-q35-smp8.bin")),
];

fn opts(bsp: u32) -> Options {
    Options {
        bsp_apic_id: bsp,
        xapic: true,
        limit: MAX_CPUS,
    }
}

/// MADT com o cabeçalho e o corpo dados, checksum corrigido.
fn madt(entries: &[&[u8]]) -> Vec<u8> {
    let mut t = vec![0u8; HEADER];
    t[..4].copy_from_slice(b"APIC");
    t.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
    t.extend_from_slice(&1u32.to_le_bytes());
    for e in entries {
        t.extend_from_slice(e);
    }
    let len = u32::try_from(t.len()).unwrap();
    t[4..8].copy_from_slice(&len.to_le_bytes());
    let n = t.len();
    fix_checksum(&mut t, 9, n);
    t
}

fn lapic(id: u8, flags: u32) -> Vec<u8> {
    let mut e = vec![0, 8, id, id];
    e.extend_from_slice(&flags.to_le_bytes());
    e
}

fn x2apic(id: u32, flags: u32) -> Vec<u8> {
    let mut e = vec![9, 16, 0, 0];
    e.extend_from_slice(&id.to_le_bytes());
    e.extend_from_slice(&flags.to_le_bytes());
    e.extend_from_slice(&id.to_le_bytes());
    e
}

#[test]
fn tabelas_reais_do_qemu() {
    for (n, table) in SMP {
        let t = parse(table, opts(0)).unwrap();
        assert_eq!(t.count(), n, "-smp {n}");
        assert_eq!(
            t.apic_ids(),
            (0..u32::try_from(n).unwrap()).collect::<Vec<_>>()
        );
        assert!(t.bsp_listed);
        assert_eq!(t.local_apic, 0xfee0_0000);
        assert_eq!(
            t.ioapics(),
            &[IoApic {
                id: 0,
                addr: 0xfec0_0000,
                gsi_base: 0
            }]
        );
        assert_eq!((t.overrides, t.nmis), (5, 1));
        assert_eq!(
            (t.disabled, t.duplicates, t.over_limit, t.unaddressable),
            (0, 0, 0, 0)
        );
    }
}

#[test]
fn bsp_e_sempre_o_zero_e_o_limite_corta() {
    let table = SMP[3].1;
    let t = parse(table, opts(5)).unwrap();
    assert_eq!(t.apic_ids(), &[5, 0, 1, 2, 3, 4, 6, 7]);
    let t = parse(
        table,
        Options {
            limit: 3,
            ..opts(2)
        },
    )
    .unwrap();
    assert_eq!(t.apic_ids(), &[2, 0, 1]);
    assert_eq!(t.over_limit, 5);
    let t = parse(
        table,
        Options {
            limit: 0,
            ..opts(0)
        },
    )
    .unwrap();
    assert_eq!(t.apic_ids(), &[0], "smp=0 vira um núcleo");
}

#[test]
fn desligadas_repetidas_e_sem_endereco_ficam_fora() {
    let t = parse(
        &madt(&[
            &lapic(0, 1),
            &lapic(1, 0),
            &lapic(2, 2),
            &lapic(3, 1),
            &x2apic(3, 1),
            &x2apic(300, 1),
            &x2apic(4, 1),
        ]),
        opts(0),
    )
    .unwrap();
    assert_eq!(t.apic_ids(), &[0, 3, 4]);
    assert_eq!(
        (t.disabled, t.online_capable, t.duplicates, t.unaddressable),
        (2, 1, 1, 1)
    );
    let x2 = Options {
        xapic: false,
        ..opts(0)
    };
    let t = parse(&madt(&[&lapic(0, 1), &x2apic(300, 1)]), x2).unwrap();
    assert_eq!(t.apic_ids(), &[0, 300]);
}

#[test]
fn bsp_ausente_entra_assim_mesmo() {
    let t = parse(&madt(&[&lapic(1, 1)]), opts(7)).unwrap();
    assert_eq!(t.apic_ids(), &[7, 1]);
    assert!(!t.bsp_listed);
}

#[test]
fn override_do_endereco_do_apic() {
    let mut o = vec![5, 12, 0, 0];
    o.extend_from_slice(&0x1_fee0_0000u64.to_le_bytes());
    let t = parse(&madt(&[&lapic(0, 1), &o]), opts(0)).unwrap();
    assert_eq!(t.local_apic, 0x1_fee0_0000);
}

#[test]
fn limite_de_256_cpus() {
    let entries: Vec<Vec<u8>> = (0..300).map(|i| x2apic(i, 1)).collect();
    let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
    let x2 = Options {
        xapic: false,
        ..opts(0)
    };
    let t = parse(&madt(&refs), x2).unwrap();
    assert_eq!(t.count(), MAX_CPUS);
    assert_eq!(t.over_limit, 300 - 256);
}

#[test]
fn recusa_tabelas_estragadas() {
    let mut wrong = SMP[1].1.to_vec();
    wrong[..4].copy_from_slice(b"APIX");
    assert_eq!(parse(&wrong, opts(0)), Err(AcpiError::BadSignature));
    assert_eq!(parse(&SMP[1].1[..40], opts(0)), Err(AcpiError::BadLength));
    // Entrada que passa do fim da tabela.
    let mut long = SMP[2].1.to_vec();
    long[HEADER + 9] = 200;
    assert_eq!(parse(&long, opts(0)), Err(AcpiError::BadLength));
    // Entrada de tamanho zero (laço infinito, se aceita).
    let mut zero = SMP[2].1.to_vec();
    zero[HEADER + 9] = 0;
    assert_eq!(parse(&zero, opts(0)), Err(AcpiError::BadLength));
    // x2APIC curta demais para o tipo.
    let short = madt(&[&lapic(0, 1), &[9, 8, 0, 0, 1, 0, 0, 0]]);
    assert_eq!(parse(&short, opts(0)), Err(AcpiError::BadLength));
}

#[test]
fn acha_a_madt_pelo_rsdp_e_confere_o_checksum() {
    let mut mem = machine_with(SMP[2].1.to_vec());
    let t = read(&mut mem, 0xe_0000, opts(0)).unwrap();
    assert_eq!(t.count(), 4);
    let mut bad = SMP[2].1.to_vec();
    bad[60] ^= 1;
    let mut mem = machine_with(bad);
    assert_eq!(
        read(&mut mem, 0xe_0000, opts(0)),
        Err(AcpiError::BadChecksum)
    );
}
