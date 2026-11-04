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
