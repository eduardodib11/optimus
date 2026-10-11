//! Testes no host do formato OBFS: ida e volta, recusas e entrada
//! adulterada sem pânico.

use super::*;

fn sample() -> Vec<u8> {
    let big: Vec<u8> = (0..5000u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    build(&[
        ("root", b"\x7fELF root"),
        ("vazio", b""),
        ("svc/grande", &big),
    ])
    .unwrap()
}

/// Regrava o hash da tabela depois de mexer nela (para testar o que vem
/// depois da checagem do hash).
fn rehash(img: &mut [u8]) {
    // Com a contagem adulterada, refaz sobre as 3 entradas reais.
    let count = usize::try_from(u32_at(img, 8)).unwrap().min(3);
    let hash = blake3::hash(&img[HEADER_LEN..HEADER_LEN + count * ENTRY_LEN]);
    img[40..72].copy_from_slice(&hash);
}

#[test]
fn ida_e_volta() {
    let img = sample();
    assert_eq!(img.len() % 4096, 0);
    let image = Image::parse(&img).unwrap();
    assert_eq!(image.len(), 3);
    let names: Vec<_> = image.entries().map(|e| e.name).collect();
    assert_eq!(names, ["root", "vazio", "svc/grande"]);
    let root = image.find("root").unwrap();
    assert_eq!((root.offset, root.data), (4096, &b"\x7fELF root"[..]));
    assert_eq!(image.find("svc/grande").unwrap().data.len(), 5000);
    assert!(image.find("nada").is_none());
    assert!(image.entries().all(|e| e.offset % ALIGN == 0));
    assert_eq!(image.verify(), Ok(()));
}

#[test]
fn dados_adulterados_falham_na_verificacao() {
    let mut img = sample();
    let at = usize::try_from(
        Image::parse(&img)
            .unwrap()
            .find("svc/grande")
            .unwrap()
            .offset,
    )
    .unwrap();
    img[at + 4999] ^= 1;
    let image = Image::parse(&img).unwrap();
    assert_eq!(image.verify(), Err((Error::DataHash, "svc/grande")));
    assert!(image.find("root").unwrap().verify());
}

#[test]
fn recusas_do_cabecalho() {
    let img = sample();
    let with = |at: usize, bytes: &[u8]| {
        let mut m = img.clone();
        m[at..at + bytes.len()].copy_from_slice(bytes);
        Image::parse(&m).err()
    };
    assert_eq!(Image::parse(&img[..100]).err(), Some(Error::Truncated));
    assert_eq!(Image::parse(&img[..4096]).err(), Some(Error::Truncated));
    assert_eq!(with(0, b"OBFX"), Some(Error::BadMagic));
    assert_eq!(with(4, &2u32.to_le_bytes()), Some(Error::BadVersion));
    assert_eq!(with(12, &1u32.to_le_bytes()), Some(Error::Reserved));
    assert_eq!(with(100, &[1]), Some(Error::Reserved));
    assert_eq!(with(8, &0u32.to_le_bytes()), Some(Error::BadCount));
    assert_eq!(with(8, &2000u32.to_le_bytes()), Some(Error::BadCount));
    assert_eq!(with(16, &64u64.to_le_bytes()), Some(Error::BadLayout));
    assert_eq!(with(24, &8192u64.to_le_bytes()), Some(Error::BadLayout));
    assert_eq!(with(32, &4097u64.to_le_bytes()), Some(Error::BadLayout));
    assert_eq!(with(HEADER_LEN, b"x"), Some(Error::TableHash));
    let mut longer = img.clone();
    longer.extend_from_slice(&[0; 4096]);
    assert_eq!(Image::parse(&longer).err(), Some(Error::BadLayout));
}

#[test]
fn recusas_da_tabela() {
    let img = sample();
    let entry1 = HEADER_LEN + ENTRY_LEN;
    let with = |at: usize, bytes: &[u8]| {
        let mut m = img.clone();
        m[at..at + bytes.len()].copy_from_slice(bytes);
        rehash(&mut m);
        Image::parse(&m).err()
    };
    assert_eq!(with(entry1, b"root\0"), Some(Error::DuplicateName));
    assert_eq!(with(entry1, &[0]), Some(Error::BadName));
    assert_eq!(with(entry1 + 10, b"z"), Some(Error::BadName));
    assert_eq!(with(entry1, b"\xff"), Some(Error::BadName));
    assert_eq!(with(entry1, b"a\n"), Some(Error::BadName));
    assert_eq!(with(entry1 + 120, &[1]), Some(Error::Reserved));
    // Desalinhado, antes do anterior, fora da imagem e com soma que estoura.
    assert_eq!(
        with(entry1 + 64, &4097u64.to_le_bytes()),
        Some(Error::BadData)
    );
    assert_eq!(with(entry1 + 64, &0u64.to_le_bytes()), Some(Error::BadData));
    assert_eq!(
        with(entry1 + 72, &(1u64 << 40).to_le_bytes()),
        Some(Error::BadData)
    );
    assert_eq!(
        with(entry1 + 72, &u64::MAX.to_le_bytes()),
        Some(Error::BadData)
    );
    assert!(
        with(HEADER_LEN + 80, &[0xaa]).is_none(),
        "hash dos dados só no verify"
    );
}

#[test]
fn montagem_recusa_nomes_ruins() {
    assert_eq!(build(&[]).err(), Some(Error::BadCount));
    assert_eq!(build(&[("", b"x")]).err(), Some(Error::BadName));
    let long = "a".repeat(NAME_LEN + 1);
    assert_eq!(build(&[(&long, b"x")]).err(), Some(Error::BadName));
    assert_eq!(
        build(&[("a", b"x"), ("a", b"y")]).err(),
        Some(Error::DuplicateName)
    );
    let exact = "b".repeat(NAME_LEN);
    let img = build(&[(&exact, b"x")]).unwrap();
    assert_eq!(
        Image::parse(&img).unwrap().entries().next().unwrap().name,
        exact
    );
}

/// Entrada adulterada ao acaso (com e sem o hash da tabela refeito) vira
/// erro ou imagem válida, nunca pânico.
#[test]
fn adulteracao_aleatoria_nunca_entra_em_panico() {
    let img = sample();
    let mut rng = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for round in 0..20_000 {
        let mut m = img.clone();
        for _ in 0..=next() % 4 {
            let at = usize::try_from(next()).unwrap() % (HEADER_LEN + 3 * ENTRY_LEN);
            m[at] = next().to_le_bytes()[0];
        }
        if round % 2 == 0 {
            rehash(&mut m);
        }
        let cut = if round % 7 == 0 {
            usize::try_from(next()).unwrap() % m.len()
        } else {
            m.len()
        };
        if let Ok(image) = Image::parse(&m[..cut]) {
            for e in image.entries() {
                let _ = e.verify();
            }
        }
    }
}
