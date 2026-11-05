//! Liga o `okernel` com `linker.ld`, que o põe na metade alta.
//!
//! O modelo de código e a relocação estática vão pelo `xtask` (ADR 0025).

fn main() {
    // `DEBUG_PRINT` só existe nas imagens de teste e de fuzzing (ADR 0036,
    // item 5): o `xtask` liga `OPTIMUS_KTEST_DEBUG` nelas.
    println!("cargo:rustc-check-cfg=cfg(ktest_debug)");
    println!("cargo:rerun-if-env-changed=OPTIMUS_KTEST_DEBUG");
    if std::env::var_os("OPTIMUS_KTEST_DEBUG").is_some() {
        println!("cargo:rustc-cfg=ktest_debug");
    }
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rustc-link-arg-bin=okernel=-T{dir}/linker.ld");
}
