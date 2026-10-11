//! Liga o `okfuzz` com o script de usuário do `ostd` (`lib/ostd/user.ld`),
//! como o `root`.

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = format!("{dir}/../../lib/ostd/user.ld");
    println!("cargo:rerun-if-changed={script}");
    println!("cargo:rustc-link-arg-bin=okfuzz=-T{script}");
}
