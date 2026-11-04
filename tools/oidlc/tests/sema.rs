//! Testes dourados da análise semântica (T-342) e da compatibilidade entre
//! versões (ADR 0033, seção 8).

use std::fs;
use std::path::Path;

use oidlc::{analyze, check_compat, parse};

fn dourados() -> Vec<std::path::PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/sema");
    let mut v: Vec<_> = fs::read_dir(&dir)
        .expect("diretório dourado")
        .map(|e| e.expect("entrada").path())
        .filter(|p| p.extension().is_some_and(|x| x == "oidl"))
        .collect();
    v.sort();
    assert!(v.len() >= 10, "casos dourados demais poucos");
    v
}

#[test]
fn casos_dourados_dao_os_erros_esperados() {
    for path in dourados() {
        let src = fs::read_to_string(&path).expect("leitura");
        let file = parse(&src).unwrap_or_else(|e| panic!("{}: sintaxe: {e}", path.display()));
        let got: Vec<String> = analyze(&file).iter().map(ToString::to_string).collect();
        let want = fs::read_to_string(path.with_extension("err")).expect("arquivo .err");
        let want: Vec<&str> = want.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(got, want, "{}", path.display());
    }
}

#[test]
fn exemplos_do_sdd_sao_semanticamente_validos() {
    for nome in ["valid/fs.oidl", "valid/tudo.oidl"] {
        let src = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/golden")
                .join(nome),
        )
        .expect("leitura");
        let file = parse(&src).expect("sintaxe");
        assert!(analyze(&file).is_empty(), "{nome}: {:?}", analyze(&file));
    }
}

fn compat(velho: &str, novo: &str) -> Vec<String> {
    let a = parse(velho).expect("sintaxe do velho");
    let b = parse(novo).expect("sintaxe do novo");
    check_compat(&a, &b)
        .iter()
        .map(ToString::to_string)
        .collect()
}

const BASE: &str = "package optimus.fs @1.0;\n";

#[test]
fn metodo_novo_em_versao_menor_passa() {
    let velho = format!("{BASE}interface I {{ a() -> result<(), u8>; }}");
    let novo =
        "package optimus.fs @1.1;\ninterface I { a() -> result<(), u8>; b() -> result<(), u8>; }";
    assert!(compat(&velho, novo).is_empty());
}

#[test]
fn metodo_novo_sem_subir_versao_menor_falha() {
    let velho = format!("{BASE}interface I {{ a() -> result<(), u8>; }}");
    let novo = format!("{BASE}interface I {{ a() -> result<(), u8>; b() -> result<(), u8>; }}");
    let erros = compat(&velho, &novo);
    assert_eq!(erros.len(), 1, "{erros:?}");
    assert!(
        erros[0].contains("acréscimo sem subir a versão menor"),
        "{erros:?}"
    );
}

#[test]
fn remover_metodo_em_versao_menor_falha() {
    let velho = format!("{BASE}interface I {{ a() -> result<(), u8>; b() -> result<(), u8>; }}");
    let novo = "package optimus.fs @1.1;\ninterface I { a() -> result<(), u8>; }";
    let erros = compat(&velho, novo);
    assert_eq!(erros.len(), 1, "{erros:?}");
    assert!(erros[0].contains("removeu o método 'b'"), "{erros:?}");
}

#[test]
fn mudar_assinatura_em_versao_menor_falha() {
    let velho = format!("{BASE}interface I {{ a(x: u8) -> result<(), u8>; }}");
    let novo = "package optimus.fs @1.1;\ninterface I { a(x: u16) -> result<(), u8>; }";
    let erros = compat(&velho, novo);
    assert!(
        erros.iter().any(|e| e.contains("mudou o método 'a'")),
        "{erros:?}"
    );
}

#[test]
fn mudanca_incompativel_em_versao_maior_passa() {
    let velho = format!("{BASE}interface I {{ a(x: u8) -> result<(), u8>; }}");
    let novo = "package optimus.fs @2.0;\ninterface I { a(x: u16) -> result<(), u8>; }";
    assert!(compat(&velho, novo).is_empty());
}

#[test]
fn versao_nova_nao_pode_voltar() {
    let velho = "package optimus.fs @1.3;\n";
    let novo = "package optimus.fs @1.2;\n";
    assert_eq!(compat(velho, novo).len(), 1);
}

#[test]
fn campo_novo_em_struct_falha_por_mudar_o_layout() {
    let velho = format!("{BASE}struct S {{ a: u8 }}");
    let novo = "package optimus.fs @1.1;\nstruct S { a: u8, b: u8 }";
    let erros = compat(&velho, novo);
    assert!(
        erros.iter().any(|e| e.contains("mudou os campos")),
        "{erros:?}"
    );
}

#[test]
fn variante_nova_so_em_enum_open() {
    let fechada = format!("{BASE}enum E : u8 {{ A }}");
    let aberta = format!("{BASE}open enum E : u8 {{ A }}");
    let nova = "package optimus.fs @1.1;\nenum E : u8 { A, B }";
    let nova_aberta = "package optimus.fs @1.1;\nopen enum E : u8 { A, B }";
    assert!(
        !compat(&fechada, nova).is_empty(),
        "enum fechado não pode crescer"
    );
    assert!(
        compat(&aberta, nova_aberta).is_empty(),
        "enum open pode crescer"
    );
}

#[test]
fn tipo_novo_em_versao_menor_passa() {
    let velho = format!("{BASE}struct S {{ a: u8 }}");
    let novo = "package optimus.fs @1.1;\nstruct S { a: u8 }\nstruct T { b: u8 }";
    assert!(compat(&velho, novo).is_empty());
}
