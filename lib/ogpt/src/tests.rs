#![allow(clippy::cast_possible_truncation)]

use super::*;

struct Mem {
    d: Vec<u8>,
    ss: usize,
}
impl Disk for Mem {
    fn sector_size(&self) -> usize {
        self.ss
    }
    fn sectors(&self) -> u64 {
        (self.d.len() / self.ss) as u64
    }
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> bool {
        let at = usize::try_from(lba)
            .unwrap_or(usize::MAX)
            .saturating_mul(self.ss);
        match self.d.get(at..at + self.ss) {
            Some(s) => {
                buf.copy_from_slice(s);
                true
            }
            None => false,
        }
    }
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Disco de 4096 setores com `parts` = (nome, primeiro, último).
fn disk(ss: usize, parts: &[(&str, u64, u64)]) -> Mem {
    let total = 4096u64;
    let mut d = vec![0u8; total as usize * ss];
    let ent_sectors = (128 * 128usize).div_ceil(ss);
    let mut ents = vec![0u8; 128 * 128];
    for (i, (name, f, l)) in parts.iter().enumerate() {
        let e = &mut ents[i * 128..(i + 1) * 128];
        e[..16].fill(0xAA);
        e[16] = i as u8 + 1;
        put64(e, 32, *f);
        put64(e, 40, *l);
        for (j, c) in name.encode_utf16().enumerate() {
            e[56 + 2 * j..58 + 2 * j].copy_from_slice(&c.to_le_bytes());
        }
    }
    let first_usable = 2 + ent_sectors as u64;
    let last_usable = total - 2 - ent_sectors as u64;
    for (hdr_lba, ent_lba, alt) in [
        (1u64, 2u64, total - 1),
        (total - 1, total - 1 - ent_sectors as u64, 1),
    ] {
        let mut h = [0u8; 92];
        h[..8].copy_from_slice(b"EFI PART");
        put32(&mut h, 8, 0x0001_0000);
        put32(&mut h, 12, 92);
        put64(&mut h, 24, hdr_lba);
        put64(&mut h, 32, alt);
        put64(&mut h, 40, first_usable);
        put64(&mut h, 48, last_usable);
        h[56..72].fill(7);
        put64(&mut h, 72, ent_lba);
        put32(&mut h, 80, 128);
        put32(&mut h, 84, 128);
        put32(&mut h, 88, crc32(&ents));
        let c = crc32(&h);
        put32(&mut h, 16, c);
        let at = hdr_lba as usize * ss;
        d[at..at + 92].copy_from_slice(&h);
        let at = ent_lba as usize * ss;
        d[at..at + ents.len()].copy_from_slice(&ents);
    }
    Mem { d, ss }
}

#[test]
fn crc32_conhecido() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn le_particoes_nos_dois_tamanhos_de_setor() {
    for ss in [512, 4096] {
        let mut m = disk(ss, &[("sys-a", 256, 999), ("data", 1000, 3000)]);
        let t = parse(&mut m).unwrap();
        assert_eq!(t.len, 2);
        let p: Vec<_> = t.parts().collect();
        assert!(p[0].name_is("sys-a") && !p[0].name_is("sys") && !p[0].name_is("sys-ab"));
        assert_eq!((p[1].first, p[1].sectors()), (1000, 2001));
        assert_eq!(t.disk_guid, [7; 16]);
    }
}

#[test]
fn alinhamento_de_4k() {
    let mut m = disk(512, &[("a", 256, 300), ("b", 301, 400)]);
    let t = parse(&mut m).unwrap();
    let a: Vec<bool> = t.parts().map(|p| p.aligned_4k(512)).collect();
    assert_eq!(a, [true, false]);
}

#[test]
fn cai_para_a_copia_de_reserva() {
    let mut m = disk(512, &[("data", 100, 200)]);
    m.d[512 + 20] ^= 1; // CRC do cabeçalho primário
    assert_eq!(parse(&mut m).unwrap().len, 1);
    let mut m = disk(512, &[("data", 100, 200)]);
    m.d[2 * 512 + 3] ^= 1; // tabela primária
    assert_eq!(parse(&mut m).unwrap().len, 1);
}

#[test]
fn duas_copias_ruins_nao_expoem_nada() {
    let mut m = disk(512, &[("data", 100, 200)]);
    m.d[512 + 20] ^= 1;
    let n = m.d.len();
    m.d[n - 512 + 20] ^= 1;
    assert_eq!(parse(&mut m).unwrap_err(), Error::NoValidCopy);
    assert_eq!(
        parse(&mut Mem {
            d: vec![0; 512 * 4096],
            ss: 512
        })
        .unwrap_err(),
        Error::NoValidCopy
    );
    assert_eq!(
        parse(&mut Mem {
            d: vec![0; 100],
            ss: 100
        })
        .unwrap_err(),
        Error::BadDisk
    );
}

#[test]
fn recusa_sobreposta_invertida_e_fora_da_area() {
    for parts in [
        vec![("a", 100, 200), ("b", 200, 300)],
        vec![("a", 300, 200)],
        vec![("a", 10, 200)],
        vec![("a", 100, 5000)],
    ] {
        let mut m = disk(512, &parts);
        assert_eq!(parse(&mut m).unwrap_err(), Error::NoValidCopy, "{parts:?}");
    }
}

#[test]
fn bytes_aleatorios_nao_causam_panico() {
    let mut s = 0x1234_5678u32;
    for _ in 0..200 {
        let mut m = disk(512, &[("a", 100, 200)]);
        for _ in 0..8 {
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let at = (s >> 8) as usize % (3 * 512);
            m.d[at] ^= (s & 0xff) as u8;
        }
        let _ = parse(&mut m);
    }
}
