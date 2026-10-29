//! Testes no host: vetores dourados da ADR 0033, erros de canonicidade e
//! propriedades com um gerador determinístico.

use crate::{Error, Reader, Writer};

/// Linha de `optimus.fs.DirPage`: a entrada de `vec<DirEntry, 8>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    name: String,
    kind: u8,
    size: u64,
    modified: i64,
}

/// `DirPage { entries: vec<DirEntry, 8>, next: u64 }`, cabeça de 16 bytes;
/// cada `DirEntry` tem 32 bytes de cabeça.
const PAGE_HEAD: usize = 16;
const ENTRY: usize = 32;
const NAME_MAX: usize = 255;
const ENTRIES_MAX: usize = 8;

fn encode_page(buf: &mut [u8], rows: &[Row], next: u64) -> Result<usize, Error> {
    let mut w = Writer::new(buf, PAGE_HEAD)?;
    let region = w.vec(rows.len(), ENTRY, ENTRIES_MAX)?;
    w.u64(next)?;
    // Cada elemento escreve a cabeça na região e o nome depois dela, na
    // ordem da cauda canônica.
    for (i, row) in rows.iter().enumerate() {
        let at = region + i * ENTRY;
        w.seek(at);
        w.string(&row.name, NAME_MAX)?;
        w.u8(row.kind)?;
        w.seek(at + 16);
        w.u64(row.size)?;
        w.i64(row.modified)?;
    }
    Ok(w.finish())
}

fn decode_page(body: &[u8]) -> Result<(Vec<Row>, u64), Error> {
    let mut r = Reader::new(body, PAGE_HEAD)?;
    let entries = r.vec(ENTRIES_MAX, ENTRY)?;
    let next = r.u64()?;
    let mut rows = Vec::with_capacity(entries.count());
    for i in 0..entries.count() {
        r.seek(entries.off() + i * ENTRY);
        let name = r.string(NAME_MAX)?.to_owned();
        let kind = r.u8()?;
        r.seek(entries.off() + i * ENTRY + 16);
        let size = r.u64()?;
        let modified = r.i64()?;
        rows.push(Row {
            name,
            kind,
            size,
            modified,
        });
    }
    r.finish().map(|()| (rows, next))
}

/// xorshift64*: gerador determinístico para os testes de propriedade.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn string(&mut self, max: usize) -> String {
        let len = usize::try_from(self.below(u64::try_from(max).unwrap_or(0) + 1)).unwrap_or(0);
        (0..len)
            .map(|_| char::from(b'a' + u8::try_from(self.below(26)).unwrap_or(0)))
            .collect()
    }
}

#[test]
fn trash_vetor_dourado() {
    // trash("a/b"): cabeça com o ponteiro, cauda "a/b" e enchimento.
    let mut buf = [0xAA; 16];
    let mut w = Writer::new(&mut buf, 8).unwrap();
    w.string("a/b", 1024).unwrap();
    let len = w.finish();
    assert_eq!(len, 16);
    assert_eq!(
        buf,
        [8, 0, 0, 0, 3, 0, 0, 0, b'a', b'/', b'b', 0, 0, 0, 0, 0]
    );

    let mut r = Reader::new(&buf, 8).unwrap();
    assert_eq!(r.string(1024).unwrap(), "a/b");
    r.finish().unwrap();
}

#[test]
fn erro_vetor_dourado() {
    // Err(NotDirectory): um u8 de valor 1 e corpo de 8 bytes.
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf, 1).unwrap();
    w.u8(1).unwrap();
    assert_eq!(w.finish(), 8);
    assert_eq!(buf, [1, 0, 0, 0, 0, 0, 0, 0]);
    let mut r = Reader::new(&buf, 1).unwrap();
    assert_eq!(r.u8().unwrap(), 1);
    r.finish().unwrap();
}

#[test]
fn list_vetor_dourado() {
    // Resposta de list() com uma entrada "ab", 300 bytes e modified do ADR.
    let rows = [Row {
        name: "ab".into(),
        kind: 0,
        size: 300,
        modified: 1_700_000_000_000_000_000,
    }];
    let mut buf = [0u8; 56];
    let n = encode_page(&mut buf, &rows, 0).unwrap();
    assert_eq!(n, 56);
    let words: Vec<u64> = buf
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    assert_eq!(
        words,
        [
            0x0000_0001_0000_0010,
            0,
            0x0000_0002_0000_0030,
            0,
            0x0000_0000_0000_012c,
            0x1797_9cfe_362a_0000,
            0x0000_0000_0000_6261,
        ]
    );
    assert_eq!(decode_page(&buf).unwrap(), (rows.to_vec(), 0));
}

#[test]
fn cauda_fora_do_lugar_e_rejeitada() {
    // Ponteiro que pula um byte do cursor (desloc 9 em vez de 8).
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&[9, 0, 0, 0, 1, 0, 0, 0]);
    buf[9] = b'x';
    let mut r = Reader::new(&buf, 8).unwrap();
    assert_eq!(r.string(16), Err(Error::BadMessage));
}

#[test]
fn regiao_sobreposta_e_fim_do_corpo_sao_rejeitados() {
    // Região que volta à cabeça (desloc 0).
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(
        Reader::new(&buf, 8).unwrap().string(8),
        Err(Error::BadMessage)
    );
    // Região que passa do fim do corpo.
    buf[..8].copy_from_slice(&[8, 0, 0, 0, 9, 0, 0, 0]);
    assert_eq!(
        Reader::new(&buf, 8).unwrap().string(16),
        Err(Error::BadMessage)
    );
}

#[test]
fn limites_utf8_bool_e_sobra_sao_rejeitados() {
    // Passa do limite declarado.
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf, 8).unwrap();
    w.string("abc", 1024).unwrap();
    assert_eq!(
        Reader::new(&buf, 8).unwrap().string(2),
        Err(Error::BadMessage)
    );
    // UTF-8 inválido.
    buf[8] = 0xFF;
    assert_eq!(
        Reader::new(&buf, 8).unwrap().string(1024),
        Err(Error::BadMessage)
    );
    // bool fora de 0 e 1.
    let bool_buf = [2u8, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        Reader::new(&bool_buf, 1).unwrap().bool(),
        Err(Error::BadMessage)
    );
    // Byte na cauda que nenhuma região usa.
    let mut sobra = [0u8; 24];
    let mut w = Writer::new(&mut sobra, 8).unwrap();
    w.string("a", 8).unwrap();
    assert_eq!(w.finish(), 16);
    sobra[20] = 7;
    assert_eq!(
        Reader::new(&sobra, 8).unwrap().finish(),
        Err(Error::BadMessage)
    );
    // Corpo que não é múltiplo de 8.
    assert_eq!(
        Reader::new(&buf[..9], 1).map(|_| ()),
        Err(Error::BadMessage)
    );
}

#[test]
fn escrita_recusa_o_que_nao_cabe() {
    let mut pequeno = [0u8; 8];
    assert_eq!(
        Writer::new(&mut pequeno, 8).unwrap().string("abc", 8),
        Err(Error::TooLarge)
    );
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf, 8).unwrap();
    assert_eq!(w.string("abc", 2), Err(Error::TooLarge));
    assert_eq!(w.vec(9, 1, 8), Err(Error::TooLarge));
    assert_eq!(
        Writer::new(&mut [0u8; 4], 8).map(|_| ()),
        Err(Error::TooLarge)
    );
}

#[test]
fn ida_e_volta_com_gerador_determinista() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut buf = [0u8; 4096];
    for _ in 0..2000 {
        let n = usize::try_from(rng.below(ENTRIES_MAX as u64 + 1)).unwrap_or(0);
        let rows: Vec<Row> = (0..n)
            .map(|_| Row {
                name: rng.string(NAME_MAX),
                kind: u8::try_from(rng.below(3)).unwrap_or(0),
                size: rng.next(),
                modified: i64::from_le_bytes(rng.next().to_le_bytes()),
            })
            .collect();
        let next = rng.next();
        let len = encode_page(&mut buf, &rows, next).unwrap();
        assert_eq!(decode_page(&buf[..len]).unwrap(), (rows, next));
    }
}

#[test]
fn corpo_aleatorio_nunca_entra_em_panico() {
    // Entrada arbitrária: ou é recusada, ou é um valor que reescreve igual
    // em valor (idempotência da decodificação).
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let mut buf = [0u8; 512];
    let mut aceitos = 0;
    for _ in 0..200_000 {
        let len = usize::try_from(rng.below(64)).unwrap_or(0) * 8;
        for b in &mut buf[..len] {
            *b = u8::try_from(rng.below(256)).unwrap_or(0);
        }
        // Metade das entradas usa cabeça válida, para chegar até as regiões.
        if rng.below(2) == 0 && len >= 16 {
            // Ponteiro de `entries` no fim da cabeça, com contagem pequena.
            buf[..8].copy_from_slice(&[16, 0, 0, 0, 0, 0, 0, 0]);
            buf[4] = u8::try_from(rng.below(8)).unwrap_or(0);
        }
        if let Ok((rows, next)) = decode_page(&buf[..len]) {
            aceitos += 1;
            let mut out = [0u8; 4096];
            let n = encode_page(&mut out, &rows, next).unwrap();
            assert_eq!(decode_page(&out[..n]).unwrap(), (rows, next));
        }
    }
    assert!(aceitos > 0, "o gerador não chegou a corpos válidos");
}
