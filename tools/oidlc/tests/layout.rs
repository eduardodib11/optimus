//! Testes do layout de fio (T-343): números da ADR 0033 e propriedades
//! (determinismo, alinhamento, sem sobreposição) sobre tipos gerados.

use std::fs;
use std::path::Path;

use oidlc::ast::Decl;
use oidlc::layout::{Layouts, MAX_CORPO, PALAVRAS_BUFFER, PALAVRAS_REGISTRADORES, Via, via};
use oidlc::parse;

fn sdd() -> oidlc::ast::File {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/valid/fs.oidl"),
    )
    .expect("leitura");
    parse(&src).expect("sintaxe")
}

fn metodo<'a>(file: &'a oidlc::ast::File, iface: &str, nome: &str) -> &'a oidlc::ast::Method {
    file.decls
        .iter()
        .find_map(|d| match d {
            Decl::Interface(i) if i.name.name == iface => {
                i.methods.iter().find(|m| m.name.name == nome)
            }
            _ => None,
        })
        .expect("método")
}

#[test]
fn list_cabe_nos_numeros_da_adr() {
    // ADR 0033, seção 5: pedido 16 + 1024; resposta 16 + 8×32 + 8×256 = 2320.
    let file = sdd();
    let l = Layouts::new(&file);
    let m = metodo(&file, "Directory", "list");
    let (pedido, resposta) = l.metodo(m).expect("layout");
    assert_eq!(pedido.tamanho, 16);
    assert_eq!(pedido.pior_caso, 16 + 1024);
    let (ok, err) = resposta.expect("tem resultado");
    assert_eq!(ok.pior_caso, 2320);
    assert!(ok.pior_caso <= MAX_CORPO);
    assert_eq!(err.pior_caso, 8, "FsError ocupa 1 byte, arredondado a 8");
}

#[test]
fn direntry_tem_offsets_fixos() {
    // name(ptr 8, alin 4) @0, kind(u8) @8, size(u64) @16, modified(i64) @24.
    let file = sdd();
    let l = Layouts::new(&file);
    let st = file
        .decls
        .iter()
        .find_map(|d| match d {
            Decl::Struct(s) if s.name.name == "DirEntry" => Some(s),
            _ => None,
        })
        .expect("DirEntry");
    let c = l.cabeca_de(&st.fields).expect("layout");
    let offs: Vec<u64> = c.campos.iter().map(|x| x.deslocamento).collect();
    assert_eq!(offs, [0, 8, 16, 24]);
    assert_eq!(c.tamanho, 32);
}

#[test]
fn trash_e_open_tem_os_pesos_esperados() {
    let file = sdd();
    let l = Layouts::new(&file);
    // trash(path: string<1024>): cabeça de 8 bytes (ponteiro), cauda até 1024.
    let (pedido, _) = l
        .metodo(metodo(&file, "Directory", "trash"))
        .expect("layout");
    assert_eq!(pedido.tamanho, 8);
    assert_eq!(pedido.pior_caso, 8 + 1024);
    // open devolve handle<File>: a resposta de sucesso não tem corpo (só cap).
    let (_, resposta) = l
        .metodo(metodo(&file, "Directory", "open"))
        .expect("layout");
    let (ok, _) = resposta.expect("resultado");
    assert_eq!(ok.pior_caso, 0);
}

#[test]
fn transporte_segue_a_adr() {
    assert_eq!(via(0), Via::Registradores { palavras: 0 });
    assert_eq!(via(48), Via::Registradores { palavras: 6 });
    assert_eq!(via(56), Via::Buffer { palavras: 7 });
    assert_eq!(via(4032), Via::Buffer { palavras: 504 });
    assert_eq!(PALAVRAS_REGISTRADORES * 8, 48);
    assert_eq!(PALAVRAS_BUFFER * 8, 4032);
}

#[test]
fn metodo_acima_de_4032_bytes_e_recusado() {
    let src = "package optimus.fs @1.0;\ninterface I { m(a: string<4000>, b: string<100>) -> result<(), u8>; }";
    let file = parse(src).expect("sintaxe");
    let erros = Layouts::new(&file).confere_tamanhos();
    assert_eq!(erros.len(), 1, "{erros:?}");
    assert!(erros[0].msg.contains("pedido de 'm'"), "{erros:?}");
}

/// Gerador determinístico (LCG) para as propriedades.
struct Lcg(u64);

impl Lcg {
    fn prox(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % n
    }
}

fn tipo_aleatorio(gerador: &mut Lcg) -> String {
    match gerador.prox(7) {
        0 => "u8".into(),
        1 => "u16".into(),
        2 => "u32".into(),
        3 => "u64".into(),
        4 => "bool".into(),
        5 => format!("string<{}>", 1 + gerador.prox(300)),
        _ => format!("vec<u32, {}>", 1 + gerador.prox(16)),
    }
}

#[test]
fn propriedades_offsets_alinhados_sem_sobreposicao_e_deterministas() {
    let mut gerador = Lcg(0x5EED_0343);
    for caso in 0..300 {
        let n = 1 + gerador.prox(6);
        let campos: Vec<String> = (0..n)
            .map(|i| format!("c{i}: {}", tipo_aleatorio(&mut gerador)))
            .collect();
        let src = format!(
            "package optimus.fs @1.0;\nstruct S {{ {} }}",
            campos.join(", ")
        );
        let file = parse(&src).unwrap_or_else(|e| panic!("caso {caso}: {e}"));
        let Decl::Struct(st) = &file.decls[0] else {
            panic!("caso {caso}: esperava struct");
        };
        let l = Layouts::new(&file);
        let a = l.cabeca_de(&st.fields).expect("layout");
        let b = l.cabeca_de(&st.fields).expect("layout");
        assert_eq!(a, b, "caso {caso}: layout não é determinístico");

        let mut fim = 0u64;
        for c in &a.campos {
            assert_eq!(
                c.deslocamento % c.medida.alinhamento,
                0,
                "caso {caso}: {} desalinhado",
                c.nome
            );
            assert!(
                c.deslocamento >= fim,
                "caso {caso}: {} sobrepõe o anterior",
                c.nome
            );
            fim = c.deslocamento + c.medida.tamanho;
        }
        assert!(a.tamanho >= fim, "caso {caso}: cabeça menor que os campos");
        assert!(
            a.pior_caso >= a.tamanho,
            "caso {caso}: pior caso menor que a cabeça"
        );
    }
}
