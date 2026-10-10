//! Liga o `okernel` com `linker.ld`, que o põe na metade alta.
//!
//! O modelo de código e a relocação estática vão pelo `xtask` (ADR 0025).

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rustc-link-arg-bin=okernel=-T{dir}/linker.ld");
}
