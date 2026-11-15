//! P7: o nonce não vem do chamador; contador único por época; época
//! separa chaves.

use std::collections::HashSet;

use super::*;

fn base() -> Secret<32> {
    Secret::take(&mut [0x11u8; 32])
}

#[test]
fn contadores_nunca_se_repetem() {
    let mut s = EpochSealer::new(&base(), 7, &[1; SALT_LEN]);
    let mut vistos = HashSet::new();
    for _ in 0..2000 {
        let mut b = [0u8; 16];
        let r = s.seal(b"a", &mut b).unwrap();
        assert!(vistos.insert(r.nonce), "nonce repetido");
        assert_eq!(r.nonce[..4], 7u32.to_be_bytes());
    }
}

#[test]
fn ida_e_volta_e_adulteracao() {
    let (sal, mut s) = (
        [9u8; SALT_LEN],
        EpochSealer::new(&base(), 3, &[9; SALT_LEN]),
    );
    let o = EpochOpener::new(&base(), 3, &sal);
    let mut b = *b"conteudo do bloco";
    let r = s.seal(b"aad", &mut b).unwrap();
    assert_ne!(&b, b"conteudo do bloco");
    let mut copia = b;
    o.open(&r, b"aad", &mut copia).unwrap();
    assert_eq!(&copia, b"conteudo do bloco");
    // Outro endereço (AAD) falha, e o buffer fica zerado.
    let mut c2 = b;
    assert_eq!(o.open(&r, b"outro", &mut c2), Err(Error::Auth));
    assert_eq!(c2, [0; 17]);
}

#[test]
fn epoca_e_sal_separam_as_chaves() {
    let mut s = EpochSealer::new(&base(), 3, &[1; SALT_LEN]);
    let mut b = [0u8; 8];
    let r = s.seal(b"", &mut b).unwrap();
    // Mesmo número de época com outro sal (queda antes de gravar a época).
    let outro_sal = EpochOpener::new(&base(), 3, &[2; SALT_LEN]);
    assert_eq!(outro_sal.open(&r, b"", &mut b.clone()), Err(Error::Auth));
    // Outra época.
    let outra = EpochOpener::new(&base(), 4, &[1; SALT_LEN]);
    assert_eq!(outra.open(&r, b"", &mut b), Err(Error::WrongEpoch));
}

#[test]
fn contador_esgotado() {
    let mut s = EpochSealer::new(&base(), 1, &[0; SALT_LEN]);
    s.next = u64::MAX;
    assert_eq!(s.seal(b"", &mut [0u8; 1]), Err(Error::EpochExhausted));
}
