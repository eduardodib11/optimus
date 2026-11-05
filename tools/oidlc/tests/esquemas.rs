//! Esquemas de ferramentas (T-346): golden do exemplo `optimus.fs` do SDD.

use oidlc::esquemas::gera_esquemas;
use oidlc::parser::parse;

const FS: &str = include_str!("golden/valid/fs.oidl");
const GOLDEN: &str = include_str!("golden/esquemas/fs.json");

#[test]
fn fs_gera_o_golden() {
    let file = parse(FS).expect("fs.oidl deve analisar");
    let json = gera_esquemas(&file).expect("fs.oidl tem só tipos com esquema");
    assert_eq!(json, GOLDEN);
}

#[test]
fn so_metodos_com_tool_entram() {
    let file = parse(FS).expect("analisa");
    let json = gera_esquemas(&file).expect("gera");
    assert!(json.contains("optimus.fs.Directory.list"));
    assert!(json.contains("optimus.fs.Directory.trash"));
    assert!(!json.contains("Directory.open"), "open não tem @tool");
    assert!(!json.contains("File.size"), "size não tem @tool");
}

#[test]
fn risco_e_descricao_saem_do_tool() {
    let file = parse(FS).expect("analisa");
    let json = gera_esquemas(&file).expect("gera");
    assert!(json.contains("\"risco\": \"R2\""));
    assert!(json.contains("\"descricao\": \"Move um item para a lixeira\""));
}

#[test]
fn texto_escapa_aspas_e_barras() {
    let src = "package optimus.t @1.0;\ninterface I {\n    @tool(risk = R0, desc = \"a \\\"b\\\" \\\\ c\")\n    m() -> result<(), u8>;\n}\n";
    let file = parse(src).expect("analisa");
    let json = gera_esquemas(&file).expect("gera");
    assert!(json.contains(r#""descricao": "a \"b\" \\ c""#), "{json}");
}
