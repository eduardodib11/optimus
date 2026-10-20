//! Liga o `utest` com o script de usuário do `ostd` (`lib/ostd/user.ld`) e,
//! com `UTEST_FALHA` no ambiente, liga o teste que falha de propósito
//! (`cfg(utest_falha)`).

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = format!("{dir}/../../lib/ostd/user.ld");
    println!("cargo:rerun-if-changed={script}");
    println!("cargo:rustc-link-arg-bin=utest=-T{script}");
    println!("cargo:rustc-check-cfg=cfg(utest_falha)");
    println!("cargo:rerun-if-env-changed=UTEST_FALHA");
    if std::env::var_os("UTEST_FALHA").is_some_and(|v| v == "1") {
        println!("cargo:rustc-cfg=utest_falha");
    }
}
