//! Testes no host com ELFs montados à mão.

use super::*;

const BASE: u64 = 0xffff_ffff_8000_0000;
const R: u32 = 4;
const W: u32 = 2;
const X: u32 = 1;

/// `(tipo, flags, offset, vaddr, filesz, memsz, align)`.
type Ph = (u32, u32, u64, u64, u64, u64, u64);

fn load(flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Ph {
    (PT_LOAD, flags, offset, vaddr, filesz, memsz, PAGE_SIZE)
}

/// Monta um ELF com os program headers logo após o cabeçalho e `len` bytes no total.
fn build(entry: u64, phdrs: &[Ph], len: usize) -> Vec<u8> {
    let mut d = vec![0u8; len];
    d[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\x00");
    d[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    d[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    d[20..24].copy_from_slice(&1u32.to_le_bytes());
    d[24..32].copy_from_slice(&entry.to_le_bytes());
    d[32..40].copy_from_slice(&64u64.to_le_bytes());
    d[52..54].copy_from_slice(&64u16.to_le_bytes());
    d[54..56].copy_from_slice(&56u16.to_le_bytes());
    d[56..58].copy_from_slice(&u16::try_from(phdrs.len()).unwrap().to_le_bytes());
    for (i, p) in phdrs.iter().enumerate() {
        let at = 64 + i * 56;
        d[at..at + 4].copy_from_slice(&p.0.to_le_bytes());
        d[at + 4..at + 8].copy_from_slice(&p.1.to_le_bytes());
        for (j, v) in [p.2, p.3, p.3, p.4, p.5, p.6].iter().enumerate() {
            d[at + 8 + j * 8..at + 16 + j * 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    d
}

/// Kernel típico: texto R-X, dados RW- com BSS e um `PT_GNU_STACK` ignorado.
fn kernel() -> Vec<u8> {
    let mut d = build(
        BASE + 0x10,
        &[
            load(R | X, 0x1000, BASE, 0x100, 0x100),
            load(R | W, 0x2000, BASE + 0x1000, 0x10, 0x3000),
            (0x6474_e551, R | W, 0, 0, 0, 0, 16),
        ],
        0x2010,
    );
    d[0x1000] = 0xcc;
    d[0x2000] = 0x42;
    d
}

fn parse_with(edit: impl FnOnce(&mut Vec<u8>)) -> Result<(), Error> {
    let mut d = kernel();
    edit(&mut d);
    Elf::parse(&d).map(drop)
}

fn single(p: Ph) -> Result<(), Error> {
    Elf::parse(&build(p.3, &[p], 0x3000)).map(drop)
}

#[test]
fn aceita_kernel_valido() {
    let d = kernel();
    let elf = Elf::parse(&d).unwrap();
    assert_eq!(elf.entry(), BASE + 0x10);
    let segs: Vec<_> = elf.segments().collect();
    assert_eq!(segs.len(), 2);
    assert_eq!((segs[0].vaddr, segs[0].memsz), (BASE, 0x100));
    assert_eq!((segs[0].data.len(), segs[0].data[0]), (0x100, 0xcc));
    assert_eq!(segs[0].flags.to_string(), "R-X");
    let mut bss = [0u8; 0x10];
    bss[0] = 0x42;
    assert_eq!((segs[1].memsz, segs[1].data), (0x3000, &bss[..]));
    assert_eq!(segs[1].flags.to_string(), "RW-");
    assert!(segs[1].flags.writable() && !segs[1].flags.executable());
}

#[test]
fn rejeita_cabecalho_invalido() {
    assert_eq!(Elf::parse(&[0x7f, b'E']).unwrap_err(), Error::Truncated);
    assert_eq!(parse_with(|d| d[1] = b'X'), Err(Error::BadMagic));
    assert_eq!(parse_with(|d| d[4] = 1), Err(Error::NotElf64));
    assert_eq!(parse_with(|d| d[5] = 2), Err(Error::NotLittleEndian));
    assert_eq!(parse_with(|d| d[6] = 0), Err(Error::BadVersion));
    assert_eq!(parse_with(|d| d[20] = 2), Err(Error::BadVersion));
    assert_eq!(parse_with(|d| d[16] = 4), Err(Error::NotExecutable));
    assert_eq!(parse_with(|d| d[18] = 40), Err(Error::BadMachine));
    assert_eq!(parse_with(|d| d[54] = 32), Err(Error::BadHeaderSize));
    assert_eq!(parse_with(|d| d[56] = 0), Err(Error::BadPhdrCount));
    assert_eq!(parse_with(|d| d[56] = 65), Err(Error::BadPhdrCount));
    assert_eq!(
        parse_with(|d| d.truncate(64 + 2 * 56)),
        Err(Error::Truncated)
    );
    assert_eq!(parse_with(|d| d[39] = 0xff), Err(Error::Truncated));
}

#[test]
fn rejeita_segmentos_invalidos() {
    let m = u64::MAX;
    let cases = [
        (R, 0x2000, BASE, 0x1001, 0x2000, Error::SegmentOutOfFile),
        (R, m, BASE, 2, 2, Error::SegmentOutOfFile),
        (R, 0x1000, BASE, m, m, Error::SegmentOutOfFile),
        (R | X, 0x1000, BASE, 0x20, 0x10, Error::FileszExceedsMemsz),
        (R | X, 0x1000, BASE + 8, 0x10, 0x10, Error::BadAlignment),
        (R | X, 0x1000, 0x40_0000, 0x10, 0x10, Error::NotHigherHalf),
        (
            R | X,
            0x1000,
            0x7fff_ffff_f000,
            0x10,
            0x10,
            Error::NotHigherHalf,
        ),
        (R | X, 0x1000, BASE, 0x10, m, Error::Overflow),
        (R | X, 0x1000, m - 0xfff, 0x10, 0xfff, Error::Overflow),
        (R | W | X, 0x1000, BASE, 0x10, 0x10, Error::WriteExecute),
    ];
    for (i, (flags, offset, vaddr, filesz, memsz, err)) in cases.into_iter().enumerate() {
        let got = single(load(flags, offset, vaddr, filesz, memsz));
        assert_eq!(got, Err(err), "caso {i}");
    }
    let mut p = load(R | X, 0x1000, BASE, 0x10, 0x10);
    for align in [0x3000, 16] {
        p.6 = align;
        assert_eq!(single(p), Err(Error::BadAlignment));
    }
}

#[test]
fn rejeita_sobreposicao_e_entrada() {
    let text = load(R | X, 0x1000, BASE, 0x100, 0x100);
    let overlap = |vaddr| build(BASE, &[text, load(R, 0x2000, vaddr, 0x10, 0x10)], 0x3000);
    for vaddr in [BASE, BASE - 0x1000] {
        assert_eq!(Elf::parse(&overlap(vaddr)).unwrap_err(), Error::Overlap);
    }
    assert!(Elf::parse(&overlap(BASE + 0x1000)).is_ok());
    let data_only = build(BASE, &[load(R | W, 0x1000, BASE, 0x10, 0x10)], 0x2000);
    assert_eq!(Elf::parse(&data_only).unwrap_err(), Error::BadEntry);
    let outside = build(BASE + 0x100, &[text], 0x2000);
    assert_eq!(Elf::parse(&outside).unwrap_err(), Error::BadEntry);
    let empty = build(BASE, &[load(R | X, 0, 0, 0, 0)], 0x1000);
    assert_eq!(Elf::parse(&empty).unwrap_err(), Error::NoSegments);
}

/// Corta e corrompe o kernel válido byte a byte: nada pode entrar em pânico,
/// e o que for aceito continua obedecendo às invariantes.
#[test]
fn entrada_corrompida_nunca_entra_em_panico() {
    let good = kernel();
    let check = |d: &[u8]| {
        if let Ok(elf) = Elf::parse(d) {
            for s in elf.segments() {
                assert!(s.vaddr >= HIGHER_HALF && s.data.len() as u64 <= s.memsz);
                assert!(!(s.flags.writable() && s.flags.executable()));
            }
        }
    };
    for len in 0..good.len() {
        check(&good[..len]);
    }
    for at in 0..64 + 3 * 56 {
        for v in [0, 1, 0x7f, 0x80, 0xff] {
            let mut d = good.clone();
            d[at] = v;
            check(&d);
        }
    }
}

/// PIE: texto R-X e dados R-- com `.dynamic` em 0x2100 e `.rela.dyn` em 0x2200.
fn pie(relas: &[(u64, u64, u64)], dynamic: &[(u64, u64)]) -> Vec<u8> {
    let mut d = build(
        BASE,
        &[
            load(R | X, 0x1000, BASE, 0x100, 0x100),
            load(R, 0x2000, BASE + 0x1000, 0x400, 0x2000),
            (PT_DYNAMIC, R, 0x2100, BASE + 0x1100, 0x100, 0x100, 8),
        ],
        0x2400,
    );
    d[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
    for (i, (tag, value)) in dynamic.iter().enumerate() {
        let at = 0x2100 + i * 16;
        d[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        d[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }
    for (i, (offset, info, addend)) in relas.iter().enumerate() {
        let at = 0x2200 + i * 24;
        for (j, v) in [offset, info, addend].iter().enumerate() {
            d[at + j * 8..at + j * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
    }
    d
}

fn rela_dyn(count: u64) -> [(u64, u64); 3] {
    [
        (DT_RELA, BASE + 0x1200),
        (DT_RELASZ, count * 24),
        (DT_RELAENT, 24),
    ]
}

#[test]
fn pie_entrega_relocacoes_relativas() {
    let relas = [(BASE + 0x1000, 8, BASE + 0x40), (BASE + 0x2ff8, 8, BASE)];
    let d = pie(&relas, &rela_dyn(2));
    let elf = Elf::parse(&d).unwrap();
    assert!(elf.is_relocatable());
    let got: Vec<_> = elf.relocations().map(|r| (r.vaddr, r.addend)).collect();
    assert_eq!(got, [(BASE + 0x1000, BASE + 0x40), (BASE + 0x2ff8, BASE)]);
    // Sem DT_RELA, ou em ET_EXEC, não há relocações.
    assert_eq!(Elf::parse(&pie(&[], &[])).unwrap().relocations().count(), 0);
    assert!(!Elf::parse(&kernel()).unwrap().is_relocatable());
}

#[test]
fn pie_recusa_dinamico_invalido() {
    let ok = (BASE + 0x1000, 8, 0);
    let bad = |relas: &[(u64, u64, u64)], dynamic: &[(u64, u64)]| {
        Elf::parse(&pie(relas, dynamic)).unwrap_err()
    };
    assert_eq!(
        bad(&[(BASE + 0x1000, 1, 0)], &rela_dyn(1)),
        Error::BadRelocation
    );
    let with_symbol = (BASE + 0x1000, (1 << 32) | 8, 0);
    assert_eq!(bad(&[with_symbol], &rela_dyn(1)), Error::BadRelocation);
    assert_eq!(
        bad(&[(BASE + 0x2ff9, 8, 0)], &rela_dyn(1)),
        Error::BadRelocation
    );
    assert_eq!(bad(&[(BASE - 8, 8, 0)], &rela_dyn(1)), Error::BadRelocation);
    let mut wrong_ent = rela_dyn(1);
    wrong_ent[2].1 = 16;
    assert_eq!(bad(&[ok], &wrong_ent), Error::BadDynamic);
    // `.rela.dyn` além da parte de arquivo do segmento.
    assert_eq!(bad(&[ok], &rela_dyn(30)), Error::BadDynamic);
    let mut outside = rela_dyn(1);
    outside[0].1 = BASE + 0x2000;
    assert_eq!(bad(&[ok], &outside), Error::BadDynamic);
    for tag in DT_REJECTED {
        assert_eq!(bad(&[], &[(tag, 0)]), Error::BadDynamic, "DT {tag}");
    }
    // Dois PT_DYNAMIC.
    let mut two = pie(&[], &[]);
    two[56..58].copy_from_slice(&4u16.to_le_bytes());
    let at = 64 + 3 * 56;
    let copy: Vec<u8> = two[64 + 2 * 56..at].to_vec();
    two[at..at + 56].copy_from_slice(&copy);
    assert_eq!(Elf::parse(&two).unwrap_err(), Error::BadDynamic);
}

#[test]
fn usuario_so_na_metade_baixa() {
    let user = |vaddr: u64, memsz: u64| {
        let p = load(R | X, 0x1000, vaddr, 0x10, memsz);
        Elf::parse_user(&build(vaddr, &[p], 0x2000)).map(drop)
    };
    assert_eq!(user(0x20_0000, 0x10), Ok(()));
    assert_eq!(user(BASE, 0x10), Err(Error::NotUserHalf));
    assert_eq!(user(0x1000, 0x10), Err(Error::NotUserHalf));
    assert_eq!(user(USER_END - 0x1000, 0x2000), Err(Error::NotUserHalf));
    // O kernel continua recusando a metade baixa, e o usuário, o kernel.
    assert_eq!(
        Elf::parse(&build(
            0x20_0000,
            &[load(R | X, 0x1000, 0x20_0000, 0x10, 0x10)],
            0x2000
        ))
        .map(drop),
        Err(Error::NotHigherHalf)
    );
    assert_eq!(
        Elf::parse_user(&kernel()).map(drop),
        Err(Error::NotUserHalf)
    );
}
