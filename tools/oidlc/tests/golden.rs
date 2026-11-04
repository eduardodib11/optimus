//! Testes dourados do léxico e do parser (T-341): arquivos válidos entram
//! sem erro; cada inválido sai com a linha e a coluna do `.err` ao lado.

use std::fs;
use std::path::{Path, PathBuf};

fn oidl_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = fs::read_dir(dir)
        .expect("diretório dourado")
        .map(|e| e.expect("entrada").path())
        .filter(|p| p.extension().is_some_and(|x| x == "oidl"))
        .collect();
    v.sort();
    assert!(!v.is_empty(), "sem casos em {}", dir.display());
    v
}

fn golden(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(sub)
}

#[test]
fn validos_entram_sem_erro() {
    for path in oidl_files(&golden("valid")) {
        let src = fs::read_to_string(&path).expect("leitura");
        if let Err(e) = oidlc::parse(&src) {
            panic!("{}: {e}", path.display());
        }
    }
}

#[test]
fn invalidos_dao_linha_e_coluna() {
    for path in oidl_files(&golden("invalid")) {
        let src = fs::read_to_string(&path).expect("leitura");
        let want = fs::read_to_string(path.with_extension("err")).expect("arquivo .err");
        let got = match oidlc::parse(&src) {
            Ok(_) => panic!("{} deveria falhar", path.display()),
            Err(e) => e.to_string(),
        };
        assert_eq!(got, want.trim_end(), "{}", path.display());
    }
}

#[test]
fn fs_tem_o_formato_do_sdd() {
    let src = fs::read_to_string(golden("valid/fs.oidl")).expect("leitura");
    let file = oidlc::parse(&src).expect("parse");
    assert_eq!(file.package.version.major, 1);
    assert_eq!(file.decls.len(), 7);
    let oidlc::ast::Decl::Interface(dir) = &file.decls[6] else {
        panic!("última declaração deveria ser interface");
    };
    let nomes: Vec<&str> = dir.methods.iter().map(|m| m.name.name.as_str()).collect();
    assert_eq!(
        nomes,
        ["list", "trash", "open"],
        "ordinal = ordem da declaração"
    );
}
