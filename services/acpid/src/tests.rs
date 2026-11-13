use super::*;

/// Pacote com o `PkgLength` de um ou de dois bytes.
fn pkg(body: &[u8]) -> Vec<u8> {
    let mut v = if body.len() < 63 {
        vec![u8::try_from(body.len() + 1).unwrap()]
    } else {
        let len = body.len() + 2;
        vec![
            0x40 | u8::try_from(len & 15).unwrap(),
            u8::try_from(len >> 4).unwrap(),
        ]
    };
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

fn method(seg: [u8; 4], args: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x14];
    v.extend(pkg(&[&seg[..], &[args], body].concat()));
    v
}

/// Roda o `_STA` e o `_CRS` do primeiro dispositivo de `aml`.
fn run(aml: &[u8], width32: bool) -> (Result<u64, Error>, Result<usize, Error>) {
    let (devs, r) = collect(aml);
    assert_eq!(r, Ok(()));
    let d = devs[0];
    let l = Limits::default();
    (
        d.status(aml, width32, l),
        d.current_resources(aml, width32, l).map(Iterator::count),
    )
}

#[test]
fn sta_com_if_e_nome_do_escopo_de_cima() {
    // Local0 = 0x0B; If (FLAG == 1) { Local0 |= 4 } Else { Return (0) };
    // Return (Local0)
    let body = [
        &[0x70, 0x0A, 0x0B, 0x60, 0xA0][..],
        &pkg(&[
            0x93, b'F', b'L', b'A', b'G', 0x01, 0x7D, 0x60, 0x0A, 0x04, 0x60,
        ]),
        &[0xA1],
        &pkg(&[0xA4, 0x00]),
        &[0xA4, 0x60],
    ]
    .concat();
    for (flag, want) in [(1u8, 0x0F), (0, 0)] {
        let aml = [
            name(*b"FLAG", &[flag]),
            dev(*b"KBD_", &[&method(*b"_STA", 0, &body)]),
        ]
        .concat();
        assert_eq!(run(&aml, false).0, Ok(want));
    }
    // Sem o nome (um campo de região, por exemplo): fora do subconjunto.
    let aml = dev(*b"KBD_", &[&method(*b"_STA", 0, &body)]);
    assert_eq!(run(&aml, false).0, Err(Error::Unsupported));
    // Sem `_STA`: presente e funcionando.
    assert_eq!(run(&dev(*b"KBD_", &[]), false).0, Ok(0x0F));
}

#[test]
fn while_aritmetica_e_largura_dos_inteiros() {
    // Local0 = 0; Local1 = 5; While (Local1) { Local0 += Local1; Local1-- }
    // Return (Local0)
    let soma = [
        &[0x70, 0x00, 0x60, 0x70, 0x0A, 0x05, 0x61, 0xA2][..],
        &pkg(&[0x61, 0x72, 0x60, 0x61, 0x60, 0x76, 0x61]),
        &[0xA4, 0x60],
    ]
    .concat();
    let aml = dev(*b"DEV_", &[&method(*b"_STA", 0, &soma)]);
    assert_eq!(run(&aml, false).0, Ok(15));
    // Return (Not (Zero)) depende da revisão da tabela.
    let not = [0xA4, 0x80, 0x00, 0x00];
    let aml = dev(*b"DEV_", &[&method(*b"_STA", 0, &not)]);
    assert_eq!(run(&aml, true).0, Ok(0xFFFF_FFFF));
    assert_eq!(run(&aml, false).0, Ok(u64::MAX));
    // Divide (7, 2, Local0, Local1); Return (Local0 * 16 + Local1) e a
    // divisão por zero, que aborta.
    let div = [
        0x78, 0x0A, 0x07, 0x0A, 0x02, 0x60, 0x61, 0xA4, 0x72, 0x79, 0x60, 0x0A, 0x04, 0x00, 0x61,
        0x00,
    ];
    let aml = dev(*b"DEV_", &[&method(*b"_STA", 0, &div)]);
    assert_eq!(run(&aml, false).0, Ok(0x13));
    let aml = dev(
        *b"DEV_",
        &[&method(*b"_STA", 0, &[0x78, 0x01, 0x00, 0x00, 0x00])],
    );
    assert_eq!(run(&aml, false).0, Err(Error::Unsupported));
}

#[test]
fn chamada_com_argumento_e_crs_por_metodo() {
    // Method (DBL, 1) { Return (Arg0 << 1) }; _STA: Return (DBL (4) + 1)
    let dbl = method(*b"DBL_", 1, &[0xA4, 0x79, 0x68, 0x01, 0x00]);
    let sta = [0xA4, 0x72, b'D', b'B', b'L', b'_', 0x0A, 0x04, 0x01, 0x00];
    // _CRS: Return (BUF0), com o buffer de uma porta e uma IRQ.
    let buf = [
        0x11, 0x10, 0x0A, 0x0D, 0x47, 0x01, 0x60, 0x00, 0x60, 0x00, 0x01, 0x01, 0x22, 0x02, 0x00,
        0x79, 0x00,
    ];
    let aml = [
        dbl,
        dev(
            *b"KBD_",
            &[
                &name(*b"BUF0", &buf),
                &method(*b"_STA", 0, &sta),
                &method(*b"_CRS", 0, &[0xA4, b'B', b'U', b'F', b'0']),
            ],
        ),
    ]
    .concat();
    assert_eq!(run(&aml, false), (Ok(9), Ok(2)));
}

#[test]
fn prt_muda_com_o_pic_e_resolve_a_ligacao() {
    // Rota do modo PIC: dispositivo 2, INTA, pela ligação LNKA.
    let pic = [&[0x12][..], &pkg(b"\x04\x0C\xFF\xFF\x02\x00\x00LNKA\x00")].concat();
    // Rota do modo APIC: dispositivo 3, INTB, GSI 20.
    let apic = [
        &[0x12][..],
        &pkg(&[4, 0x0C, 0xFF, 0xFF, 3, 0, 0x01, 0x00, 0x0A, 20]),
    ]
    .concat();
    let table = |r: &[u8]| [&[0x12][..], &pkg(&[&[1][..], r].concat())].concat();
    // Method (_PRT) { If (PICF == 0) { Return (PRTP) } Return (PRTA) }
    let prt = [&[0xA0][..], &pkg(b"\x93PICF\x00\xA4PRTP"), b"\xA4PRTA"].concat();
    // _CRS da ligação: interrupção estendida no GSI 17.
    let crs = [
        0x11, 0x0E, 0x0A, 0x0B, 0x89, 0x06, 0x00, 0x09, 0x01, 17, 0, 0, 0, 0x79, 0x00,
    ];
    let aml = [
        name(*b"PICF", &[0]),
        method(*b"_PIC", 1, b"\x70\x68PICF"),
        dev(
            *b"PCI0",
            &[
                &name(*b"PRTP", &table(&pic)),
                &name(*b"PRTA", &table(&apic)),
                &method(*b"_PRT", 0, &prt),
                &dev(*b"LNKA", &[&name(*b"_CRS", &crs)]),
            ],
        ),
    ]
    .concat();
    let (devs, r) = collect(&aml);
    assert_eq!(r, Ok(()));
    let (link, pci) = (devs[0], devs[1]);
    let l = Limits::default();
    let mut state = State::default();
    let routes = |state: &mut State| -> Vec<Route> {
        pci.routes(&aml, false, l, state)
            .unwrap()
            .unwrap()
            .collect()
    };
    let lnka = Route {
        device: 2,
        pin: 0,
        source: Some(*b"LNKA"),
        index: 0,
    };
    assert_eq!(routes(&mut state), [lnka]);
    assert_eq!(route_gsi(&aml, &lnka, false, l), Some(17));
    assert_eq!(pic_mode(&aml, 1, false, l, &mut state), Ok(true));
    let gsi20 = Route {
        device: 3,
        pin: 1,
        source: None,
        index: 20,
    };
    assert_eq!(routes(&mut state), [gsi20]);
    assert_eq!(route_gsi(&aml, &gsi20, false, l), Some(20));
    // Sem `_PRT`, sem `_PIC`, ligação que não existe e rota malformada.
    assert!(link.routes(&aml, false, l, &mut state).unwrap().is_none());
    let so = dev(
        *b"PCI0",
        &[&name(*b"_PRT", &table(&[0x12, 0x03, 0x04, 0x00]))],
    );
    assert_eq!(pic_mode(&so, 1, false, l, &mut state), Ok(false));
    let d = collect(&so).0[0];
    assert_eq!(
        d.routes(&so, false, l, &mut state)
            .unwrap()
            .unwrap()
            .count(),
        0
    );
    let sem = Route {
        source: Some(*b"LNKZ"),
        ..lnka
    };
    assert_eq!(route_gsi(&aml, &sem, false, l), None);
}

#[test]
fn limites_da_execucao() {
    // While (One) {}: estoura as operações.
    let aml = dev(*b"DEV_", &[&method(*b"_STA", 0, &[0xA2, 0x02, 0x01])]);
    assert_eq!(run(&aml, false).0, Err(Error::Limit));
    // Método que chama a si mesmo: estoura o aninhamento ou as buscas.
    let aml = dev(
        *b"DEV_",
        &[&method(*b"_STA", 0, &[0xA4, b'_', b'S', b'T', b'A'])],
    );
    assert_eq!(run(&aml, false).0, Err(Error::Limit));
    // Corpo fora da tabela.
    let fora = Method {
        start: 0,
        end: 99,
        args: 0,
    };
    let r = eval(&aml, &[*b"DEV_"], fora, false, Limits::default());
    assert_eq!(r, Err(Error::Malformed));
}

#[test]
fn mutacao_dos_metodos_sem_panico() {
    let sta = [
        &[0x70, 0x0A, 0x0B, 0x60, 0xA0][..],
        &pkg(&[
            0x93, b'F', b'L', b'A', b'G', 0x01, 0x7D, 0x60, 0x0A, 0x04, 0x60,
        ]),
        &[0xA2],
        &pkg(&[0x60, 0x76, 0x60]),
        &[0xA4, 0x72, b'D', b'B', b'L', b'_', 0x60, 0x01, 0x00],
    ]
    .concat();
    let base = [
        name(*b"FLAG", &[1]),
        method(*b"DBL_", 1, &[0xA4, 0x79, 0x68, 0x01, 0x00]),
        dev(*b"KBD_", &[&method(*b"_STA", 0, &sta)]),
    ]
    .concat();
    let limits = Limits {
        max_ops: 2_000,
        ..Limits::default()
    };
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    for _ in 0..20_000 {
        let mut m = base.clone();
        for _ in 0..2 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = usize::try_from(x % m.len() as u64).unwrap();
            m[i] = (x >> 32).to_le_bytes()[0];
        }
        let mut devs = Vec::new();
        let _ = scan(&m, limits, |d| devs.push(*d));
        for d in devs {
            let _ = d.status(&m, x & 1 == 0, limits);
            let _ = d.current_resources(&m, false, limits).map(Iterator::count);
            let mut state = State::default();
            let _ = pic_mode(&m, x & 3, false, limits, &mut state);
            if let Ok(Some(routes)) = d.routes(&m, false, limits, &mut state) {
                for r in routes {
                    let _ = route_gsi(&m, &r, false, limits);
                }
            }
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
    let (h, aml) = table_body(&table).unwrap();
    let (devs, r) = collect(aml);
    for d in &devs {
        let hid = d
            .hid
            .map(|h| String::from_utf8_lossy(h.as_bytes()).into_owned());
        let sta = d.status(aml, h.width32(), Limits::default());
        let crs = d
            .current_resources(aml, h.width32(), Limits::default())
            .map(Iterator::collect::<Vec<_>>);
        println!("{hid:?} sta={sta:x?} {crs:?}");
    }
    // Rotas INTx no modo APIC: com `_PRT`, toda rota resolve num GSI, direto
    // ou pelo `_CRS` do dispositivo de ligação.
    let l = Limits::default();
    let mut state = State::default();
    let pic = pic_mode(aml, 1, h.width32(), l, &mut state);
    println!("_PIC: {pic:?}");
    for d in &devs {
        let Some(routes) = d.routes(aml, h.width32(), l, &mut state).unwrap() else {
            continue;
        };
        let routes: Vec<Route> = routes.collect();
        println!(
            "_PRT: {} rotas, primeira {:?}",
            routes.len(),
            routes.first()
        );
        assert!(!routes.is_empty());
        for r in routes {
            let gsi = route_gsi(aml, &r, h.width32(), l);
            assert!(gsi.is_some(), "rota sem GSI: {r:?}");
        }
    }
    assert_eq!(r, Ok(()));
}
