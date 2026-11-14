#![allow(clippy::many_single_char_names)]

use super::*;

/// Resumo de teste (não é SHA-256): só precisa mudar quando a entrada muda.
struct Fake;
impl Sha256 for Fake {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in data.iter().enumerate() {
            let s = &mut out[i % 32];
            *s = s
                .wrapping_mul(31)
                .wrapping_add(*b)
                .wrapping_add(i.to_le_bytes()[0]);
        }
        out
    }
}

fn ptr() -> BlockPtr {
    BlockPtr {
        addr: 77,
        birth: 9,
        logical: 5000,
        physical: 8192,
        level: 2,
        kind: PtrKind::Data,
        compression: Compression::Lz4,
        integrity: Integrity::Aead,
        nonce: [7; 12],
        auth: {
            let mut a = [0u8; 32];
            a[..16].fill(0xab);
            a
        },
    }
}

fn sb() -> Superblock {
    Superblock {
        uuid: [3; 16],
        txg: 41,
        integrity: Integrity::Hash,
        root: BlockPtr {
            integrity: Integrity::Hash,
            nonce: [0; 12],
            ..ptr()
        },
        volume_blocks: 1 << 20,
        epochs: 2,
        free_blocks: 1000,
    }
}

#[test]
fn ponteiro_ida_e_volta() {
    let p = ptr();
    assert_eq!(BlockPtr::decode(&p.encode()), Ok(p));
    assert!(BlockPtr::null().is_null());
    assert_eq!(
        BlockPtr::decode(&BlockPtr::null().encode()),
        Ok(BlockPtr::null())
    );
    assert!(!p.is_null());
}

#[test]
fn ponteiro_recusa_lixo() {
    let mut b = ptr().encode();
    assert_eq!(BlockPtr::decode(&b[..71]), Err(Error::BadLen));
    b[21] = 1; // físico não múltiplo de 4 KiB
    assert_eq!(BlockPtr::decode(&b), Err(Error::BadField));
    let mut b = ptr().encode();
    b[18] = 0xff; // lógico acima de 128 KiB
    assert_eq!(BlockPtr::decode(&b), Err(Error::BadField));
    let mut b = ptr().encode();
    b[25] = 9; // tipo de bloco desconhecido
    assert_eq!(BlockPtr::decode(&b), Err(Error::BadField));
    let mut b = ptr().encode();
    b[60] = 1; // tag AEAD com bytes finais sujos
    assert_eq!(BlockPtr::decode(&b), Err(Error::Reserved));
    let mut p = ptr();
    p.integrity = Integrity::Hash;
    assert_eq!(BlockPtr::decode(&p.encode()), Err(Error::Reserved)); // nonce no modo hash
}

#[test]
fn superbloco_ida_e_volta() {
    let s = sb();
    let b = s.encode(&Fake);
    assert_eq!(Superblock::decode(&b, &Fake), Ok(s));
}

#[test]
fn superbloco_rasgado_e_recusado() {
    let b = sb().encode(&Fake);
    // Qualquer byte alterado antes do SHA-256 falha na conferência.
    for at in [0usize, 9, 33, 60, 130, 500, SB_SHA_OFFSET - 1] {
        let mut c = b;
        c[at] ^= 1;
        assert!(Superblock::decode(&c, &Fake).is_err(), "byte {at}");
    }
    let mut c = b;
    c[SB_SHA_OFFSET] ^= 1;
    assert_eq!(Superblock::decode(&c, &Fake), Err(Error::BadChecksum));
    assert_eq!(Superblock::decode(&b[..100], &Fake), Err(Error::BadLen));
    // Bloco de zeros (nunca gravado).
    assert_eq!(
        Superblock::decode(&[0; BLOCK_SIZE], &Fake),
        Err(Error::BadMagic)
    );
}

#[test]
fn superbloco_recusa_campos_fora_do_dominio() {
    let mut s = sb();
    s.free_blocks = s.volume_blocks + 1;
    assert_eq!(
        Superblock::decode(&s.encode(&Fake), &Fake),
        Err(Error::BadField)
    );
    let mut s = sb();
    s.volume_blocks = 4;
    assert_eq!(
        Superblock::decode(&s.encode(&Fake), &Fake),
        Err(Error::BadField)
    );
}

#[test]
fn no_e_chave() {
    let h = NodeHeader {
        level: 1,
        count: 40,
        tree: 5,
        txg: 8,
        addr: 99,
    };
    assert_eq!(NodeHeader::decode(&h.encode()), Ok(h));
    let mut b = h.encode();
    b[0] = 0;
    assert_eq!(NodeHeader::decode(&b), Err(Error::BadMagic));
    let mut b = h.encode();
    b[40] = 1;
    assert_eq!(NodeHeader::decode(&b), Err(Error::Reserved));
    assert_eq!(NodeHeader::decode(&b[..10]), Err(Error::BadLen));

    let k = Key {
        object: 4,
        kind: KeyKind::Extent,
        offset: 4096,
    };
    assert_eq!(Key::decode(&k.encode()), Ok(k));
    let mut b = k.encode();
    b[8] = 7;
    assert_eq!(Key::decode(&b), Err(Error::BadField));
    // Ordem lexicográfica: objeto, tipo, deslocamento.
    let a = Key {
        object: 4,
        kind: KeyKind::Inode,
        offset: 99,
    };
    let c = Key {
        object: 4,
        kind: KeyKind::Dirent,
        offset: 0,
    };
    let d = Key {
        object: 5,
        kind: KeyKind::Inode,
        offset: 0,
    };
    assert!(a < c && c < k && k < d);
}
