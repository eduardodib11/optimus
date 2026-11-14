//! P8 (segredo não vaza por formatação) e utilidades de tempo constante.

use super::*;

/// Truque de resolução por autoref: `IMPLS` é `true` só se `T: Trait`.
macro_rules! implementa {
    ($t:ty, $($tr:tt)+) => {{
        #[allow(dead_code)]
        trait Nao { const IMPLS: bool = false; }
        impl<T: ?Sized> Nao for T {}
        struct Sonda<T: ?Sized>(core::marker::PhantomData<T>);
        #[allow(dead_code)]
        impl<T: ?Sized + $($tr)+> Sonda<T> { const IMPLS: bool = true; }
        <Sonda<$t>>::IMPLS
    }};
}

#[test]
fn segredo_nao_formata_nem_copia() {
    assert!(!implementa!(Secret<32>, core::fmt::Debug));
    assert!(!implementa!(Secret<32>, core::fmt::Display));
    assert!(!implementa!(Secret<32>, Clone));
    assert!(!implementa!(Secret<32>, Copy));
    // A sonda enxerga o que existe de fato.
    assert!(implementa!(u8, core::fmt::Debug));
}

#[test]
fn ct_eq_e_wipe() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
    let mut b = [7u8; 16];
    wipe(&mut b);
    assert_eq!(b, [0; 16]);
}

#[test]
fn take_zera_a_origem() {
    let mut k = [9u8; 32];
    let s = Secret::take(&mut k);
    assert_eq!(k, [0; 32]);
    assert_eq!(s.expose(), &[9; 32]);
    assert!(s.ct_eq(&Secret::take(&mut [9u8; 32])));
}
