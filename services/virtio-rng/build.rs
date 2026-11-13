//! Liga o binário do `virtio-rng` com o script de usuário do `ostd`.

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let script = format!("{dir}/../../lib/ostd/user.ld");
    println!("cargo:rerun-if-changed={script}");
    println!("cargo:rustc-link-arg-bin=virtio-rng=-T{script}");
}
