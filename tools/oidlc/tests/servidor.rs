//! Testes do servidor gerado (T-344): o módulo gerado do `fs.oidl` é
//! compilado aqui e os vetores da ADR 0033 (seção 6) são conferidos byte a
//! byte, nos dois sentidos.

#[allow(
    dead_code,
    unused,
    non_upper_case_globals,
    non_camel_case_types,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
#[path = "golden/gen/fs_servidor.rs"]
mod fs;

use std::fs as stdfs;
use std::path::Path;

use fs::{Contexto, Despacho, DirEntry, DirPage, Directory, Entrada, EntryKind, FsError};

/// Interface fingida: grava o que chegou e responde com valores fixos.
#[derive(Default)]
struct Falso {
    visto: Option<(String, u64)>,
}

const ENTRADAS: [DirEntry<'static>; 1] = [DirEntry {
    name: "ab",
    kind: EntryKind::File,
    size: 300,
    modified: 1_700_000_000_000_000_000,
}];

impl Directory for Falso {
    fn list(&mut self, _ctx: &Contexto, path: &str, cursor: u64) -> Result<DirPage<'_>, FsError> {
        self.visto = Some((path.to_string(), cursor));
        Ok(DirPage {
            entries: &ENTRADAS,
            next: 0,
        })
    }

    fn trash(&mut self, _ctx: &Contexto, path: &str) -> Result<(), FsError> {
        if path == "x" {
            Err(FsError::NotDirectory)
        } else {
            Ok(())
        }
    }

    fn open(
        &mut self,
        _ctx: &Contexto,
        _path: &str,
        _flags: fs::OpenFlags,
    ) -> Result<u64, FsError> {
        Err(FsError::NotFound)
    }
}

/// Monta o corpo a partir de palavras de 64 bits little-endian, como na ADR.
fn corpo(palavras: &[u64]) -> Vec<u8> {
    palavras.iter().flat_map(|p| p.to_le_bytes()).collect()
}

fn despacha(s: &mut Falso, rotulo: u64, corpo: &[u8]) -> (Option<Despacho>, Vec<u8>) {
    let mut saida = vec![0u8; 4096];
    let mut caps = [0u64; 4];
    let e = Entrada {
        rotulo,
        badge: 7,
        corpo,
        caps: &[],
    };
    let d = fs::despacha_directory(s, 0, &e, &mut saida, &mut caps);
    let n = d.as_ref().map_or(0, |d| d.corpo);
    saida.truncate(n);
    (d, saida)
}

const ID: u64 = 0xA17C_D8BB;

#[test]
fn id_da_interface_bate_com_a_adr() {
    assert_eq!(fs::ID_DIRECTORY, 0xA17C_D8BB);
}

#[test]
fn list_pedido_da_adr_decodifica_path_e_cursor() {
    // ADR 0033, seção 6: list("d", 0) → rótulo 0xA17CD8BB_00000000, 3 palavras.
    let body = corpo(&[0x0000_0001_0000_0010, 0, 0x64]);
    let mut s = Falso::default();
    let (d, _) = despacha(&mut s, ID << 32, &body);
    assert!(d.is_some());
    assert_eq!(s.visto, Some(("d".to_string(), 0)));
}

#[test]
fn list_resposta_da_adr_bate_byte_a_byte() {
    // ADR 0033, seção 6: Ok(DirPage{ entries: [{ab, File, 300, ts}], next: 0 }), 56 bytes.
    let esperado = corpo(&[
        0x0000_0001_0000_0010,
        0x0000_0000_0000_0000,
        0x0000_0002_0000_0030,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_012c,
        0x1797_9cfe_362a_0000,
        0x0000_0000_0000_6261,
    ]);
    let body = corpo(&[0x0000_0001_0000_0010, 0, 0x64]);
    let mut s = Falso::default();
    let (d, saida) = despacha(&mut s, ID << 32, &body);
    let d = d.expect("resposta");
    assert_eq!(d.rotulo, 0, "Ok");
    assert_eq!(saida, esperado);
}

#[test]
fn trash_pedido_da_adr_e_ok_sem_corpo() {
    // trash("a/b"): método 1, 2 palavras: cabeça (desloc 8, len 3) e "a/b".
    let body = corpo(&[0x0000_0003_0000_0008, 0x0000_0000_0062_2f61]);
    let mut s = Falso::default();
    let (d, saida) = despacha(&mut s, (ID << 32) | 1, &body);
    let d = d.expect("resposta");
    assert_eq!(d.rotulo, 0);
    assert!(saida.is_empty());
}

#[test]
fn erro_de_dominio_da_adr() {
    // Err(NotDirectory): rótulo 0x4000_0000_0000_0000, uma palavra com o valor 1.
    let body = corpo(&[0x0000_0001_0000_0008, 0x0000_0000_0078_0000 | 0x78]);
    let mut s = Falso::default();
    let (d, saida) = despacha(&mut s, (ID << 32) | 1, &body);
    let d = d.expect("resposta");
    assert_eq!(d.rotulo, 0x4000_0000_0000_0000);
    assert_eq!(saida, corpo(&[1]));
}

#[test]
fn rotulo_de_outra_interface_e_erro_de_protocolo_1() {
    let mut s = Falso::default();
    let (d, _) = despacha(&mut s, 0xDEAD_BEEF_0000_0000, &[]);
    assert_eq!(d.expect("protocolo").rotulo, 0x8000_0000_0000_0001);
}

#[test]
fn metodo_desconhecido_e_erro_de_protocolo_2() {
    let mut s = Falso::default();
    let (d, _) = despacha(&mut s, ID << 32 | 9, &[]);
    assert_eq!(d.expect("protocolo").rotulo, 0x8000_0000_0000_0002);
}

#[test]
fn corpo_grande_demais_e_too_large() {
    let mut s = Falso::default();
    let body = vec![0u8; 1048];
    let (d, _) = despacha(&mut s, ID << 32, &body);
    assert_eq!(d.expect("protocolo").rotulo, 0x8000_0000_0000_0005);
}

#[test]
fn ponteiro_fora_do_lugar_e_bad_message() {
    // Ponteiro com desloc 0 (dentro da cabeça): fora do lugar da cauda.
    let body = corpo(&[0x0000_0003_0000_0000, 0x0000_0000_0062_2f61]);
    let mut s = Falso::default();
    let (d, _) = despacha(&mut s, (ID << 32) | 1, &body);
    assert_eq!(d.expect("protocolo").rotulo, 0x8000_0000_0000_0004);
}

#[test]
fn gerado_bate_com_o_golden() {
    let file = oidlc::parse(
        &stdfs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/valid/fs.oidl"),
        )
        .expect("leitura"),
    )
    .expect("sintaxe");
    let gerado = oidlc::servidor::formata(&oidlc::servidor::gera_servidor(&file).expect("gera"));
    let golden = stdfs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/gen/fs_servidor.rs"),
    )
    .expect("golden");
    assert_eq!(gerado, golden, "rode o gerador de novo e atualize o golden");
}
