//! Comportamento da ADR 0053, itens 2 a 4.

use super::*;

const UUID: [u8; UUID_LEN] = [7; UUID_LEN];

fn mestra() -> Secret<KEY_LEN> {
    let mut m = [0xA5u8; KEY_LEN];
    m[0] = 1;
    Secret::take(&mut m)
}

/// Slot de senha com parâmetros pequenos, para o teste rodar rápido.
fn slot_senha(pwd: &[u8], index: u8) -> Slot {
    let mut s = Slot {
        kind: KIND_PASSWORD,
        m_kib: 64,
        t: 1,
        salt: [3; SALT_LEN],
        nonce: [0; NONCE_LEN],
        wrapped: [0; KEY_LEN],
        tag: [0; TAG_LEN],
    };
    let mut work = vec![[0u64; 128]; s.work_blocks()];
    let kek = kek_password(pwd, &s, &mut work).unwrap();
    s = wrap(
        &mestra(),
        &kek,
        &UUID,
        index,
        KIND_PASSWORD,
        64,
        1,
        s.salt,
        [9; NONCE_LEN],
    )
    .unwrap();
    s
}

fn abre(s: &Slot, pwd: &[u8], index: u8) -> Result<Secret<KEY_LEN>, Error> {
    let mut work = vec![[0u64; 128]; s.work_blocks()];
    let kek = kek_password(pwd, s, &mut work)?;
    unwrap(s, &kek, &UUID, index)
}

#[test]
fn senha_certa_abre_e_errada_nao() {
    let s = slot_senha(b"correto", 0);
    assert!(abre(&s, b"correto", 0).unwrap().ct_eq(&mestra()));
    assert_eq!(abre(&s, b"errado", 0).err(), Some(Error::Auth));
    assert_eq!(abre(&s, b"", 0).err(), Some(Error::Auth));
}

#[test]
fn a_k_mestra_nao_aparece_em_claro_no_slot() {
    let s = slot_senha(b"x", 0);
    let b = s.to_bytes();
    assert!(!b.windows(KEY_LEN).any(|w| w == mestra().expose()));
    assert_ne!(s.wrapped, *mestra().expose());
}

#[test]
fn aad_prende_parametros_indice_e_uuid() {
    let s = slot_senha(b"p", 2);
    assert!(abre(&s, b"p", 2).is_ok());
    // Outro índice.
    assert_eq!(abre(&s, b"p", 3).err(), Some(Error::Auth));
    // Outro UUID.
    let mut work = vec![[0u64; 128]; s.work_blocks()];
    let kek = kek_password(b"p", &s, &mut work).unwrap();
    assert_eq!(unwrap(&s, &kek, &[8; UUID_LEN], 2).err(), Some(Error::Auth));
    // Parâmetro adulterado: a KEK muda e o AAD também.
    let mut mexido = s;
    mexido.t = 2;
    assert_eq!(abre(&mexido, b"p", 2).err(), Some(Error::Auth));
    // Tipo adulterado.
    let mut outro_tipo = s;
    outro_tipo.kind = KIND_RECOVERY;
    assert_eq!(unwrap(&outro_tipo, &kek, &UUID, 2).err(), Some(Error::Auth));
    // Bit trocado no embrulho ou na tag.
    let mut embrulho = s;
    embrulho.wrapped[0] ^= 1;
    assert_eq!(unwrap(&embrulho, &kek, &UUID, 2).err(), Some(Error::Auth));
    let mut tag = s;
    tag.tag[0] ^= 1;
    assert_eq!(unwrap(&tag, &kek, &UUID, 2).err(), Some(Error::Auth));
}

#[test]
fn limites_recusam_antes_de_gastar_memoria() {
    let mut s = slot_senha(b"p", 0);
    s.m_kib = MAX_M_KIB + 1;
    assert_eq!(s.check(), Err(Error::Limits));
    assert_eq!(kek_password(b"p", &s, &mut []).err(), Some(Error::Limits));
    s.m_kib = 64;
    s.t = MAX_T + 1;
    assert_eq!(s.check(), Err(Error::Limits));
    s.t = 0;
    assert_eq!(s.check(), Err(Error::Limits));
    s.t = MAX_T;
    s.m_kib = MAX_M_KIB;
    assert_eq!(s.check(), Ok(()));
    s.kind = 3;
    assert_eq!(s.check(), Err(Error::BadKind));
    s.kind = 0;
    assert_eq!(s.check(), Err(Error::BadKind));
    // Memória de trabalho pequena demais.
    let p = slot_senha(b"p", 0);
    assert_eq!(
        kek_password(b"p", &p, &mut [[0u64; 128]; 4]).err(),
        Some(Error::WorkTooSmall)
    );
}

#[test]
fn serializa_e_recusa_cabecalho_adulterado() {
    let s = slot_senha(b"p", 0);
    assert_eq!(Slot::from_bytes(&s.to_bytes()), Ok(s));
    let mut b = s.to_bytes();
    b[0] = 9;
    assert_eq!(Slot::from_bytes(&b), Err(Error::BadKind));
    let mut b = s.to_bytes();
    b[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Slot::from_bytes(&b), Err(Error::Limits));
    assert_eq!(s.to_bytes().len(), SLOT_LEN);
}

#[test]
fn recuperacao_abre_o_slot() {
    let mut r = [0x42u8; KEY_LEN];
    let rec = Secret::take(&mut r);
    let salt = [5; SALT_LEN];
    let kek = kek_recovery(&rec, &salt);
    let s = wrap(
        &mestra(),
        &kek,
        &UUID,
        1,
        KIND_RECOVERY,
        0,
        0,
        salt,
        [1; NONCE_LEN],
    )
    .unwrap();
    assert!(
        unwrap(&s, &kek_recovery(&rec, &salt), &UUID, 1)
            .unwrap()
            .ct_eq(&mestra())
    );
    let mut o = [0x43u8; KEY_LEN];
    let outra = Secret::take(&mut o);
    assert_eq!(
        unwrap(&s, &kek_recovery(&outra, &salt), &UUID, 1).err(),
        Some(Error::Auth)
    );
}

#[test]
fn chaves_derivadas_sao_distintas_e_presas_ao_uuid() {
    let k = VolumeKeys::derive(&mestra(), &UUID);
    assert!(!k.cab.ct_eq(&k.meta));
    assert!(!k.cab.ct_eq(&k.nome));
    assert!(!k.meta.ct_eq(&k.nome));
    let d0 = dataset_key(&mestra(), &UUID, 0);
    let d1 = dataset_key(&mestra(), &UUID, 1);
    assert!(!d0.ct_eq(&d1));
    assert!(!d0.ct_eq(&k.meta));
    let k2 = VolumeKeys::derive(&mestra(), &UUID);
    assert!(k.meta.ct_eq(&k2.meta));
    let k3 = VolumeKeys::derive(&mestra(), &[8; UUID_LEN]);
    assert!(!k.meta.ct_eq(&k3.meta));
}

#[test]
fn mac_do_cabecalho() {
    let k = VolumeKeys::derive(&mestra(), &UUID);
    let h = b"OPTFSVH1 cabecalho";
    let mac = header_mac(&k.cab, h);
    assert_eq!(header_verify(&k.cab, h, &mac), Ok(()));
    assert_eq!(
        header_verify(&k.cab, b"OPTFSVH1 cabecalhO", &mac),
        Err(Error::BadHeaderMac)
    );
    let mut m2 = mac;
    m2[31] ^= 1;
    assert_eq!(header_verify(&k.cab, h, &m2), Err(Error::BadHeaderMac));
    assert_eq!(header_verify(&k.meta, h, &mac), Err(Error::BadHeaderMac));
}

#[test]
fn espera_dobra_de_1_a_60_segundos() {
    let v: Vec<u32> = (0..10).map(retry_delay_secs).collect();
    assert_eq!(v, [0, 1, 2, 4, 8, 16, 32, 60, 60, 60]);
    assert_eq!(retry_delay_secs(u32::MAX), 60);
}

#[test]
fn base32_da_chave_de_recuperacao() {
    let zero = Secret::<KEY_LEN>::zeroed();
    let t = recovery_encode(&zero);
    let texto = core::str::from_utf8(t.expose()).unwrap();
    assert_eq!(texto.len(), RECOVERY_TEXT_LEN);
    assert_eq!(
        texto,
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"
    );
    let mut b = [0u8; KEY_LEN];
    let mut v = 11u8;
    for x in &mut b {
        *x = v;
        v = v.wrapping_add(37);
    }
    let k = Secret::take(&mut b);
    let t = recovery_encode(&k);
    assert_eq!(
        core::str::from_utf8(t.expose())
            .unwrap()
            .matches('-')
            .count(),
        12
    );
    assert!(recovery_eq(&recovery_decode(t.expose()).unwrap(), &k));
    // Minúsculas, espaços no lugar dos hífens e sem separador.
    let txt = core::str::from_utf8(t.expose()).unwrap();
    assert!(recovery_eq(
        &recovery_decode(txt.to_lowercase().as_bytes()).unwrap(),
        &k
    ));
    assert!(recovery_eq(
        &recovery_decode(txt.replace('-', " ").as_bytes()).unwrap(),
        &k
    ));
    assert!(recovery_eq(
        &recovery_decode(txt.replace('-', "").as_bytes()).unwrap(),
        &k
    ));
}

#[test]
fn base32_recusa_o_que_nao_e_canonico() {
    let ok = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA";
    assert!(recovery_decode(ok.as_bytes()).is_ok());
    assert_eq!(
        recovery_decode(&ok.as_bytes()[..63]).err(),
        Some(Error::BadEncoding)
    );
    assert_eq!(recovery_decode(b"").err(), Some(Error::BadEncoding));
    assert_eq!(
        recovery_decode(format!("{ok}A").as_bytes()).err(),
        Some(Error::BadEncoding)
    );
    assert_eq!(
        recovery_decode(
            ok.replace(
                "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA",
                "1AAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"
            )
            .as_bytes()
        )
        .err(),
        Some(Error::BadEncoding)
    );
    // Último caractere com bits de enchimento não nulos.
    let ruim = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAB";
    assert_eq!(
        recovery_decode(ruim.as_bytes()).err(),
        Some(Error::BadEncoding)
    );
}

#[test]
fn kek_por_senha_e_deterministica_e_depende_do_sal() {
    // Mesmos parâmetros duas vezes dão a mesma KEK; sal diferente, outra.
    let a = slot_senha(b"s", 0);
    let mut w = vec![[0u64; 128]; a.work_blocks()];
    let k1 = kek_password(b"s", &a, &mut w).unwrap();
    let k2 = kek_password(b"s", &a, &mut w).unwrap();
    assert!(k1.ct_eq(&k2));
    let mut b = a;
    b.salt[0] ^= 1;
    let k3 = kek_password(b"s", &b, &mut w).unwrap();
    assert!(!k1.ct_eq(&k3));
}

#[test]
fn hexadecimal_de_ida_e_volta_e_recusas() {
    let mut h = [0u8; 8];
    assert_eq!(to_hex(&[0x00, 0xab, 0x7f, 0xff], &mut h), 8);
    assert_eq!(&h, b"00ab7fff");
    assert_eq!(to_hex(&[1, 2, 3], &mut [0u8; 5]), 0);
    let mut b = [0u8; 4];
    assert_eq!(from_hex(b"00AB7fff", &mut b), Ok(4));
    assert_eq!(b, [0x00, 0xab, 0x7f, 0xff]);
    assert_eq!(from_hex(b"0", &mut b), Err(Error::BadEncoding));
    assert_eq!(from_hex(b"0g", &mut b), Err(Error::BadEncoding));
    assert_eq!(from_hex(b"0000000000", &mut b), Err(Error::BadEncoding));
}
