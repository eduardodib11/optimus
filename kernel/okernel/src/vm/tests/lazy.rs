//! Testes no host do `MemoryObject` `LAZY` (T-360; ADR 0038, itens 1 e 2).

use super::*;
use crate::sync::SpinLock;
use crate::vm::AddressSpace;

const U: u64 = 0x40_0000;

fn space(quota: &Arc<MemoryQuota>, p: &'static Leaked) -> Arc<SharedAddressSpace> {
    Arc::new(SpinLock::new(AddressSpace::new(quota, p).unwrap()))
}

const RW: Perms = Perms {
    write: true,
    exec: false,
    raw: false,
    uncached: false,
};

#[test]
fn nasce_sem_frames_e_cobra_so_metadados() {
    let (fake, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let mo = MemoryObject::new_lazy(&quota, 64 * P, p).unwrap();
    assert!(mo.is_lazy() && mo.pages() == 64);
    assert_eq!(fake.frames_live.load(Ordering::Relaxed), 0);
    assert_eq!(quota.used(), mo.charged());
    assert!(mo.charged() < 64 * 9 + 128, "≈ 8 bytes por página");
    assert_eq!(mo.frame(0), None);
    assert_eq!(
        MemoryObject::new_lazy(&quota, P + 1, p).err(),
        Some(Error::InvalidArgument)
    );
}

#[test]
fn commit_debita_a_cota_dona_uma_vez_por_pagina() {
    let (fake, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let mo = MemoryObject::new_lazy(&quota, 8 * P, p).unwrap();
    let base = quota.used();
    let committed = lazy_committed();
    mo.commit(2, 3, false).unwrap();
    assert_eq!(quota.used(), base + 3 * P);
    assert_eq!(fake.frames_live.load(Ordering::Relaxed), 3);
    assert!(lazy_committed() >= committed + 3);
    // Oculta: comprometida, mas fora das visões normais.
    assert_eq!(mo.frame(2), None);
    // Idempotente: comprometer de novo não cobra.
    mo.commit(0, 8, false).unwrap();
    assert_eq!(quota.used(), base + 8 * P);
    mo.publish(0, 8).unwrap();
    assert!((0..8).all(|i| mo.frame(i).is_some()));
    mo.zero(0, 8);
    assert_eq!(fake.zeroed.load(Ordering::Relaxed), 8);
    drop(mo);
    assert_eq!(fake.frames_live.load(Ordering::Relaxed), 0);
    assert_eq!(quota.used(), 0);
}

#[test]
fn sem_cota_no_dono_o_commit_para() {
    let (fake, p) = platform(100);
    let quota = MemoryQuota::root(4096);
    let mo = MemoryObject::new_lazy(&quota, 4 * P, p).unwrap();
    assert_eq!(mo.commit(0, 4, true), Err(Error::QuotaExceeded));
    // Nenhuma página coube (a cota já tinha os metadados).
    assert_eq!(fake.frames_live.load(Ordering::Relaxed), 0);
    assert_eq!(quota.used(), mo.charged());
    // Sem frame livre: a cota volta.
    let (_, tight) = platform(0);
    let big = MemoryQuota::root(1 << 20);
    let mo = MemoryObject::new_lazy(&big, P, tight).unwrap();
    let before = big.used();
    assert_eq!(mo.commit(0, 1, false), Err(Error::QuotaExceeded));
    assert_eq!(big.used(), before);
}

#[test]
fn publicar_instala_em_todos_os_espacos() {
    let (_, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let mo = Arc::new(MemoryObject::new_lazy(&quota, 4 * P, p).unwrap());
    mo.commit(0, 1, true).unwrap();
    let (a, b) = (space(&quota, p), space(&quota, p));
    mo.map_into(&a, U, 0, 4 * P, RW, RW).unwrap();
    // Só a página presente entra no mapeamento.
    assert!(a.lock().query(U).is_some());
    assert!(a.lock().query(U + P).is_none());
    mo.map_into(&b, U + 16 * P, P, 3 * P, Perms::default(), RW)
        .unwrap();
    mo.commit(1, 2, false).unwrap();
    assert!(a.lock().query(U + P).is_none(), "oculta não aparece");
    mo.publish(1, 2).unwrap();
    let (frame, perms) = a.lock().query(U + P).unwrap();
    assert_eq!(Some(frame), mo.frame(1));
    assert!(perms.write);
    let (frame_b, perms_b) = b.lock().query(U + 16 * P).unwrap();
    assert!(frame_b == frame && !perms_b.write);
    assert_eq!(mo.publish(3, 1), Err(Error::InvalidArgument), "ausente");
    // Fora da faixa de `b` (página 0) e espaço já sem região do objeto.
    b.lock().unmap(U + 16 * P, 3 * P).unwrap();
    mo.commit(3, 1, true).unwrap();
    assert!(a.lock().query(U + 3 * P).is_some());
    assert!(b.lock().query(U + 18 * P).is_none());
    // `AddressSpace::map` não aceita objeto `LAZY` (a ordem de travas).
    assert_eq!(
        a.lock().map(U + 32 * P, &mo, 0, P, RW, RW),
        Err(Error::InvalidArgument)
    );
    drop(b);
    // A entrada do espaço morto sai na limpeza do próximo mapeamento.
    mo.map_into(&a, U + 64 * P, 0, P, RW, RW).unwrap();
}

const RAW: Perms = Perms {
    write: true,
    exec: false,
    raw: true,
    uncached: false,
};

#[test]
fn visao_raw_mostra_as_ocultas() {
    let (_, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let mo = Arc::new(MemoryObject::new_lazy(&quota, 2 * P, p).unwrap());
    let (client, memd) = (space(&quota, p), space(&quota, p));
    mo.map_into(&client, U, 0, 2 * P, RW, RW).unwrap();
    // Sem `EVICT` na capability, o máximo não deixa `RAW`.
    assert_eq!(
        mo.map_into(&memd, U, 0, 2 * P, RAW, RW),
        Err(Error::AccessDenied)
    );
    mo.map_into(&memd, U, 0, 2 * P, RAW, RAW).unwrap();
    mo.commit(0, 1, false).unwrap();
    assert!(memd.lock().query(U).is_some(), "oculta aparece na RAW");
    assert!(client.lock().query(U).is_none());
    mo.publish(0, 1).unwrap();
    assert!(client.lock().query(U).is_some());
}

#[test]
fn hide_e_decommit_tiram_com_shootdown_antes_de_liberar() {
    let (fake, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let mo = Arc::new(MemoryObject::new_lazy(&quota, 2 * P, p).unwrap());
    let (client, memd) = (space(&quota, p), space(&quota, p));
    mo.map_into(&client, U, 0, 2 * P, RW, RW).unwrap();
    mo.map_into(&memd, U + 8 * P, 0, 2 * P, RAW, RAW).unwrap();
    mo.commit(0, 2, true).unwrap();
    let used = quota.used();
    fake.flushes.lock().unwrap().clear();
    mo.hide(0, 1).unwrap();
    assert!(client.lock().query(U).is_none() && memd.lock().query(U + 8 * P).is_some());
    assert!(mo.frame(0).is_none(), "oculta");
    assert_eq!(
        fake.flushes.lock().unwrap().as_slice(),
        &[(U, 1, fake.frames_live.load(Ordering::Relaxed))]
    );
    // Idempotente.
    mo.hide(0, 1).unwrap();
    assert_eq!(fake.flushes.lock().unwrap().len(), 1);
    let live = fake.frames_live.load(Ordering::Relaxed);
    fake.flushes.lock().unwrap().clear();
    // A página 1 está presente: é ocultada antes de sair da RAW.
    mo.decommit(0, 2).unwrap();
    let flushes = fake.flushes.lock().unwrap().clone();
    // Cada página: o shootdown vem com o frame dela ainda vivo, e só depois
    // ele volta (invariante 1). A 0 só sai da RAW; a 1 sai da visão normal
    // e depois da RAW.
    let want = [
        (U + 8 * P, 1, live),
        (U + P, 1, live - 1),
        (U + 9 * P, 1, live - 1),
    ];
    assert_eq!(flushes.as_slice(), &want, "{flushes:x?}");
    assert_eq!(fake.frames_live.load(Ordering::Relaxed), live - 2);
    assert_eq!(quota.used(), used - 2 * P);
    assert!(memd.lock().query(U + 8 * P).is_none() && client.lock().query(U + P).is_none());
    // Reacesso: o `COMMIT` traz a página zerada de volta, cobrada de novo.
    mo.commit(1, 1, true).unwrap();
    assert!(client.lock().query(U + P).is_some());
    assert_eq!(quota.used(), used - P);
}

#[test]
fn age_le_e_limpa_o_bit_de_acesso() {
    let (_, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let mo = Arc::new(MemoryObject::new_lazy(&quota, 4 * P, p).unwrap());
    let client = space(&quota, p);
    mo.map_into(&client, U, 0, 4 * P, RW, RW).unwrap();
    mo.commit(0, 3, true).unwrap();
    mo.hide(2, 1).unwrap();
    // A plataforma falsa não liga o bit A: nenhuma página usada.
    assert_eq!(mo.age(0, 4), Ok(0));
    let eager = MemoryObject::new(&quota, P, p).unwrap();
    assert_eq!(eager.age(0, 1), Err(Error::NotSupported));
    assert_eq!(eager.hide(0, 1), Err(Error::NotSupported));
}
