use super::convert;
use timed::zone::Zone;

fn be(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap().to_be_bytes()
}

/// `TZif` v2 mínimo: um bloco v1 vazio e um v2 com os dados dados.
fn tzif(times: &[i64], idx: &[u8], types: &[(i32, u8, u8)], chars: &[u8], footer: &str) -> Vec<u8> {
    let head = |t: usize, y: usize, c: usize| {
        let mut h = b"TZif2".to_vec();
        h.extend_from_slice(&[0; 15]);
        for n in [0, 0, 0, t, y, c] {
            h.extend_from_slice(&be(n));
        }
        h
    };
    let mut b = head(0, 1, 1);
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]); // um tipo e uma abreviação vazios
    b.extend(head(times.len(), types.len(), chars.len()));
    for t in times {
        b.extend_from_slice(&t.to_be_bytes());
    }
    b.extend_from_slice(idx);
    for (off, dst, ab) in types {
        b.extend_from_slice(&off.to_be_bytes());
        b.extend_from_slice(&[*dst, *ab]);
    }
    b.extend_from_slice(chars);
    b.extend_from_slice(format!("\n{footer}\n").as_bytes());
    b
}

#[test]
fn converte_e_o_timed_le() {
    let t = tzif(
        &[100, 200],
        &[1, 0],
        &[(-10_800, 0, 0), (-7_200, 1, 4)],
        b"-03\0-02\0",
        "<-03>3",
    );
    let blob = convert(&t, "Teste/Zona").unwrap();
    let z = Zone::parse(&blob).unwrap();
    assert_eq!(z.name(), b"Teste/Zona");
    let l = z.local(150).unwrap();
    assert_eq!((l.offset_s, l.dst, l.abbr()), (-7_200, true, &b"-02"[..]));
    let l = z.local(5_000).unwrap();
    assert_eq!((l.offset_s, l.dst, l.abbr()), (-10_800, false, &b"-03"[..]));
}

#[test]
fn recusa_entradas_ruins() {
    let t = tzif(&[], &[], &[(0, 0, 0)], b"UTC\0", "UTC0");
    assert!(convert(&t, "UTC").is_ok());
    assert!(convert(&t, &"x".repeat(64)).is_err());
    assert!(convert(b"nope", "X").is_err());
    for n in 0..t.len() - 6 {
        assert!(convert(&t[..n], "UTC").is_err(), "truncado em {n}");
    }
    let mut v1 = t.clone();
    v1[4] = 0;
    assert!(convert(&v1, "UTC").is_err());
}

/// Com tzdata no host, os fusos pedidos pela T-359 batem com as datas de
/// transição conhecidas.
#[test]
fn tzdata_do_host() {
    let ler = |n: &str| std::fs::read(format!("/usr/share/zoneinfo/{n}")).ok();
    let (Some(sp), Some(ny)) = (ler("America/Sao_Paulo"), ler("America/New_York")) else {
        return;
    };
    let sp = convert(&sp, "America/Sao_Paulo").unwrap();
    let l = Zone::parse(&sp).unwrap().local(1_700_000_000).unwrap();
    assert_eq!((l.offset_s, l.dst), (-10_800, false));
    let ny = convert(&ny, "America/New_York").unwrap();
    let z = Zone::parse(&ny).unwrap();
    assert_eq!(z.local(1_710_053_999).unwrap().offset_s, -18_000);
    assert_eq!(z.local(1_710_054_000).unwrap().offset_s, -14_400);
    assert_eq!(z.local(1_730_613_599).unwrap().offset_s, -14_400);
    assert_eq!(z.local(1_730_613_600).unwrap().offset_s, -18_000);
}
