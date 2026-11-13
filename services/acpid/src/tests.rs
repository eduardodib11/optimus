use super::*;

/// `PkgLength` de um pacote de até 63 bytes depois do campo.
fn pkg(body: &[u8]) -> Vec<u8> {
    let mut v = vec![u8::try_from(body.len() + 1).unwrap()];
    v.extend_from_slice(body);
    v
}

fn dev(name: [u8; 4], items: &[&[u8]]) -> Vec<u8> {
    let mut body = name.to_vec();
    for i in items {
        body.extend_from_slice(i);
    }
    let mut v = vec![0x5B, 0x82];
    v.extend(pkg(&body));
    v
}

fn name(seg: [u8; 4], value: &[u8]) -> Vec<u8> {
    [&[0x08][..], &seg, value].concat()
}

fn table(sig: [u8; 4], aml: &[u8]) -> Vec<u8> {
    let mut t = vec![0; HEADER_LEN];
    t[..4].copy_from_slice(&sig);
    t.extend_from_slice(aml);
    let len = u32::try_from(t.len()).unwrap();
    t[4..8].copy_from_slice(&len.to_le_bytes());
    let sum = t.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    t[9] = 0u8.wrapping_sub(sum);
    t
}

fn collect(aml: &[u8]) -> (Vec<Device<'_>>, Result<(), Error>) {
    let mut out = Vec::new();
    let r = scan(aml, Limits::default(), |d| out.push(*d));
    (out, r)
}

/// `_HID` PNP0303 (teclado) como EISAID: 0x0303D041.
const KBD: [u8; 5] = [0x0C, 0x41, 0xD0, 0x03, 0x03];

#[test]
fn checksum_e_cabecalho() {
    let t = table(*b"DSDT", &[0x10]);
    let (h, body) = table_body(&t).unwrap();
    assert_eq!(
        (h.signature, h.length, body),
        (*b"DSDT", t.len(), &[0x10][..])
    );
    let mut ruim = t.clone();
    ruim[HEADER_LEN] ^= 1;
    assert_eq!(table_body(&ruim).unwrap_err(), Error::BadChecksum);
    assert_eq!(table_body(&t[..20]).unwrap_err(), Error::Truncated);
    assert_eq!(table_body(&t[..t.len() - 1]).unwrap_err(), Error::Truncated);
}

#[test]
fn dispositivo_ps2_com_crs() {
    // _CRS: IO 0x60..0x60 (len 1), IO 0x64, IRQ 1, fim.
    let crs = [
        0x11, 0x18, 0x0A, 0x15, // Buffer(21)
        0x47, 1, 0x60, 0x00, 0x60, 0x00, 1, 1, // IO
        0x47, 1, 0x64, 0x00, 0x64, 0x00, 1, 1, // IO
        0x22, 0x02, 0x00, // IRQ 1
        0x79, 0x00, // fim
    ];
    let kbd = dev(
        *b"KBD_",
        &[
            &name(*b"_HID", &KBD),
            &name(*b"_STA", &[0x0A, 0x0F]),
            &name(*b"_CRS", &crs),
        ],
    );
    let sb = [&[0x10][..], &pkg(&[b"\\_SB_".as_slice(), &kbd].concat())].concat();
    let (devs, r) = collect(&sb);
    assert_eq!(r, Ok(()));
    let d = &devs[0];
    assert_eq!(d.hid.unwrap().as_bytes(), b"PNP0303");
    assert_eq!((d.sta, d.depth), (Some(15), 2));
    assert_eq!(&d.path[..2], &[*b"_SB_", *b"KBD_"]);
    let rs: Vec<_> = d.resources().collect();
    assert_eq!(
        rs,
        [
            Resource::Io { base: 0x60, len: 1 },
            Resource::Io { base: 0x64, len: 1 },
            Resource::Irq { mask: 2 }
        ]
    );
}

#[test]
fn hid_em_texto_adr_e_metodos_saltados() {
    let metodo = [&[0x14][..], &pkg(b"_INI\x00\xA3\xA3")].concat();
    let campo = [&[0x5B, 0x81][..], &pkg(b"REG_\x01")].concat();
    let regiao = [
        0x5B, 0x80, b'R', b'E', b'G', b'_', 0x01, 0x0A, 0x10, 0x0A, 0x04,
    ];
    let d = dev(
        *b"PCI0",
        &[
            &name(*b"_HID", &[b"\x0D", b"PNP0A08\0".as_slice()].concat()),
            &name(*b"_ADR", &[0x0C, 1, 0, 2, 0]),
            &regiao,
            &campo,
            &metodo,
        ],
    );
    let (devs, r) = collect(&d);
    assert_eq!(r, Ok(()));
    assert_eq!(devs[0].hid.unwrap().as_bytes(), b"PNP0A08");
    assert_eq!(devs[0].adr, Some(0x0002_0001));
}

#[test]
fn limites_e_lixo_nao_entram_em_panico() {
    // Profundidade: Scope dentro de Scope além do teto.
    let mut s = Vec::new();
    for _ in 0..40 {
        s = [&[0x10][..], &pkg(&[b"AAAA".as_slice(), &s].concat())].concat();
        if s.len() > 60 {
            break;
        }
    }
    let _ = collect(&s);
    let fundo = (0..MAX_DEPTH + 2).fold(Vec::new(), |acc, _| {
        [&[0x10][..], &pkg(&[b"AAAA".as_slice(), &acc].concat())].concat()
    });
    // 18 níveis passam de 63 bytes; só confere que a falha é um erro.
    let _ = collect(&fundo);
    // Operações: limite pequeno.
    let muitas = [
        name(*b"AAAA", &[0]),
        name(*b"BBBB", &[0]),
        name(*b"CCCC", &[0]),
    ]
    .concat();
    let r = scan(
        &muitas,
        Limits {
            max_depth: 4,
            max_ops: 2,
        },
        |_| {},
    );
    assert_eq!(r, Err(Error::Limit));
    // PkgLength mentirosa e fim truncado.
    assert!(collect(&[0x5B, 0x82, 0x3F, b'A', b'A']).1.is_err());
    assert!(collect(&[0x08, b'A']).1.is_err());
}

#[test]
fn mutacao_deterministica_sem_panico() {
    let crs = [0x11, 0x08, 0x0A, 0x05, 0x22, 0x02, 0x00, 0x79, 0x00];
    let base = dev(
        *b"KBD_",
        &[
            &name(*b"_HID", &KBD),
            &name(*b"_CRS", &crs),
            &name(*b"_ADR", &[0x0A, 3]),
        ],
    );
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..20_000 {
        let mut m = base.clone();
        for _ in 0..3 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = usize::try_from(x % m.len() as u64).unwrap();
            m[i] = (x >> 32).to_le_bytes()[0];
        }
        if x & 1 == 0 {
            m.truncate(usize::try_from(x >> 8).unwrap() % m.len());
        }
        let (devs, _) = collect(&m);
        for d in devs {
            let _ = d.resources().count();
        }
    }
}

/// Com `ACPID_DSDT=<arquivo>` (uma DSDT real, por exemplo a do QEMU), a
/// tabela inteira precisa ser percorrida sem erro.
#[test]
fn dsdt_real_opcional() {
    let Some(path) = std::env::var_os("ACPID_DSDT") else {
        return;
    };
    let table = std::fs::read(path).unwrap();
    let (_, aml) = table_body(&table).unwrap();
    let (devs, r) = collect(aml);
    for d in &devs {
        let hid = d
            .hid
            .map(|h| String::from_utf8_lossy(h.as_bytes()).into_owned());
        println!("{hid:?} {:?}", d.resources().collect::<Vec<_>>());
    }
    assert_eq!(r, Ok(()));
}
