//! Testes no host de `AddressSpace` e das syscalls de VM.

use std::sync::atomic::Ordering;

use kabi::vm::{EXEC, WRITE};

use super::*;
use crate::cap::Object;
use crate::vm::tests::{Fake, KERNEL_ENTRY, P, platform};

const U: u64 = 0x40_0000;
const RW: Perms = Perms {
    write: true,
    exec: false,
};
const RX: Perms = Perms {
    write: false,
    exec: true,
};
const ALL: Perms = Perms {
    write: true,
    exec: true,
};

fn setup(
    pages: u64,
) -> (
    &'static Fake,
    Arc<MemoryQuota>,
    AddressSpace,
    Arc<MemoryObject>,
) {
    let (fake, p) = platform(1000);
    let quota = MemoryQuota::root(1 << 24);
    let space = AddressSpace::new(&quota, p).unwrap();
    let mo = Arc::new(MemoryObject::new(&quota, pages * P, p).unwrap());
    (fake, quota, space, mo)
}

#[test]
fn espaco_copia_a_metade_alta_e_cobra_tabelas() {
    let (fake, quota, mut space, mo) = setup(4);
    let root = space.root();
    assert_eq!(space.live_tables(), 1);
    assert_eq!(space.tables.memory().table(root)[ENTRIES - 1], KERNEL_ENTRY);
    let base = space.charged();
    space.map(U, &mo, 0, 2 * P, RW, ALL).unwrap();
    // PDPT, PD e PT novos mais a região.
    assert_eq!(space.live_tables(), 4);
    assert_eq!(space.charged(), base + 3 * P + Region::BYTES);
    assert_eq!(space.query(U + P), Some((mo.frame(1).unwrap(), RW)));
    assert_eq!(space.query(U + 2 * P), None);
    let used = quota.used();
    drop(space);
    assert_eq!(quota.used(), used - base - 3 * P - Region::BYTES);
    assert_eq!(fake.tables_live.load(Ordering::Relaxed), 0);
    drop(mo);
    assert_eq!(quota.used(), 0);
    assert_eq!(fake.frames_live.load(Ordering::Relaxed), 0);
}

#[test]
fn faixa_alinhamento_e_sobreposicao() {
    let (_, _, mut space, mo) = setup(4);
    let bad = [
        (0, P),
        (USER_START - P, P),
        (USER_END - P, 2 * P),
        (U + 1, P),
        (U, P + 1),
        (U, 0),
        (0xffff_8000_0000_0000, P),
    ];
    for (start, len) in bad {
        assert_eq!(
            space.map(start, &mo, 0, len, RW, ALL),
            Err(Error::InvalidArgument)
        );
    }
    assert_eq!(
        space.map(U, &mo, 3 * P, 2 * P, RW, ALL),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        space.map(U, &mo, 1, P, RW, ALL),
        Err(Error::InvalidArgument)
    );
    space.map(USER_END - P, &mo, 0, P, RW, ALL).unwrap();
    space.map(USER_START, &mo, 0, P, RW, ALL).unwrap();
    space.map(U, &mo, 0, 2 * P, RW, ALL).unwrap();
    assert_eq!(
        space.map(U + P, &mo, 0, P, RW, ALL),
        Err(Error::InvalidArgument)
    );
    assert_eq!(space.regions(), 3);
}

#[test]
fn w_xor_x_e_maximo_da_capability() {
    assert_eq!(Perms::from_flags(WRITE | EXEC), Err(Error::InvalidArgument));
    assert_eq!(Perms::from_flags(1 << 5), Err(Error::InvalidArgument));
    assert_eq!(Perms::from_flags(EXEC), Ok(RX));
    let (_, _, mut space, mo) = setup(2);
    assert_eq!(space.map(U, &mo, 0, P, RW, RX), Err(Error::AccessDenied));
    space.map(U, &mo, 0, 2 * P, RX, RX).unwrap();
    assert_eq!(space.protect(U, P, RW), Err(Error::AccessDenied));
    assert_eq!(space.query(U), Some((mo.frame(0).unwrap(), RX)));
}

#[test]
fn protect_parte_regioes_e_exige_tudo_mapeado() {
    let (fake, _, mut space, mo) = setup(4);
    space.map(U, &mo, 0, 4 * P, RW, ALL).unwrap();
    space.protect(U + P, P, RX).unwrap();
    assert_eq!(space.regions(), 3);
    assert_eq!(space.query(U + P).unwrap().1, RX);
    assert_eq!(space.query(U).unwrap().1, RW);
    assert_eq!(space.query(U + 2 * P).unwrap().1, RW);
    assert!(
        fake.flushes
            .lock()
            .unwrap()
            .iter()
            .any(|&(s, n, _)| (s, n) == (U + P, 1))
    );
    // Buraco na faixa: nada muda.
    assert_eq!(
        space.protect(U, 5 * P, Perms::default()),
        Err(Error::InvalidArgument)
    );
    assert_eq!(space.query(U).unwrap().1, RW);
    space.protect(U, 4 * P, Perms::default()).unwrap();
    assert_eq!(space.query(U + 3 * P).unwrap().1, Perms::default());
}

#[test]
fn unmap_parte_regioes_e_libera_o_objeto() {
    let (fake, quota, mut space, mo) = setup(4);
    space.map(U, &mo, 0, 4 * P, RW, ALL).unwrap();
    let frame2 = mo.frame(2).unwrap();
    space.unmap(U + P, P).unwrap();
    assert_eq!(space.regions(), 2);
    assert_eq!(space.query(U + P), None);
    assert_eq!(space.query(U + 2 * P).unwrap().0, frame2);
    // Faixa sem nada mapeado também vale, sem shootdown.
    let flushes = fake.flushes.lock().unwrap().len();
    space.unmap(U + 0x10_0000, P).unwrap();
    assert_eq!(fake.flushes.lock().unwrap().len(), flushes);
    let weak = Arc::downgrade(&mo);
    drop(mo);
    assert!(weak.upgrade().is_some(), "as regiões seguram o objeto");
    let live = fake.frames_live.load(Ordering::Relaxed);
    space.unmap(U, 4 * P).unwrap();
    assert_eq!(space.regions(), 0);
    assert!(weak.upgrade().is_none());
    // Um shootdown para a faixa toda, antes de os frames do objeto saírem.
    let last = *fake.flushes.lock().unwrap().last().unwrap();
    assert_eq!(last, (U, 4, live));
    assert!(fake.frames_live.load(Ordering::Relaxed) < live);
    let tables = space.live_tables();
    assert_eq!(
        quota.used(),
        object_bytes::<SharedAddressSpace>() + tables * P
    );
    drop(space);
    assert_eq!(fake.frames_live.load(Ordering::Relaxed), 0);
}

#[test]
fn falta_de_frame_no_meio_desfaz_tudo() {
    let (fake, p) = platform(6);
    let quota = MemoryQuota::root(1 << 24);
    let mut space = AddressSpace::new(&quota, p).unwrap();
    let mo = Arc::new(MemoryObject::new(&quota, 2 * P, p).unwrap());
    let before = (quota.used(), fake.frames_live.load(Ordering::Relaxed));
    // PML4 + 2 páginas = 3 frames; sobram 3 para 4 tabelas (2 PTs).
    let far = U + 2 * 0x20_0000 - P;
    assert_eq!(
        space.map(far, &mo, 0, 2 * P, RW, ALL),
        Err(Error::QuotaExceeded)
    );
    assert_eq!(space.query(far), None);
    assert_eq!(space.regions(), 0);
    // Tabelas que sobraram vazias continuam cobradas, como as vivas.
    let tables = space.live_tables();
    assert_eq!(quota.used(), before.0 + (tables - 1) * P);
    let small = MemoryQuota::root(object_bytes::<SharedAddressSpace>() + 2 * P);
    let (_, roomy) = platform(100);
    let mut tight = AddressSpace::new(&small, roomy).unwrap();
    assert_eq!(tight.map(U, &mo, 0, P, RW, ALL), Err(Error::QuotaExceeded));
    assert_eq!(tight.live_tables(), 1);
}

fn caps(as_rights: Rights, mo_rights: Rights) -> (Cap, Cap, &'static Fake) {
    let (fake, p) = platform(100);
    let quota = MemoryQuota::root(1 << 24);
    let space = AddressSpace::new(&quota, p).unwrap();
    let mo = MemoryObject::new(&quota, 2 * P, p).unwrap();
    let a = Cap {
        object: Object::AddressSpace(Arc::new(SpinLock::new(space))),
        rights: as_rights,
        badge: 0,
    };
    let m = Cap {
        object: Object::MemoryObject(Arc::new(mo)),
        rights: mo_rights,
        badge: 0,
    };
    (a, m, fake)
}

#[test]
fn syscalls_conferem_os_direitos() {
    let mo_all = Rights::MAP | Rights::READ | Rights::WRITE | Rights::EXEC;
    let as_all = Rights::MAP | Rights::UNMAP;
    // Sem MAP no espaço ou no objeto: AccessDenied.
    let (a, m, _) = caps(Rights::UNMAP, mo_all);
    assert_eq!(vm_map(&a, &m, U, 0, P, 0), Err(Error::AccessDenied));
    let (a, m, _) = caps(as_all, Rights::READ | Rights::WRITE);
    assert_eq!(vm_map(&a, &m, U, 0, P, 0), Err(Error::AccessDenied));
    // Sem WRITE no objeto, só leitura passa.
    let (a, m, _) = caps(as_all, Rights::MAP | Rights::READ | Rights::EXEC);
    assert_eq!(vm_map(&a, &m, U, 0, P, WRITE), Err(Error::AccessDenied));
    assert_eq!(
        vm_map(&a, &m, U, 0, P, WRITE | EXEC),
        Err(Error::InvalidArgument)
    );
    vm_map(&a, &m, U, 0, 2 * P, EXEC).unwrap();
    assert_eq!(vm_protect(&a, U, P, WRITE), Err(Error::AccessDenied));
    vm_protect(&a, U, P, 0).unwrap();
    // Tipos trocados.
    assert_eq!(vm_map(&m, &a, U, 0, P, 0), Err(Error::WrongType));
    assert_eq!(vm_unmap(&m, U, P), Err(Error::WrongType));
    // UNMAP e MAP separados.
    let no_unmap = Cap {
        rights: Rights::MAP,
        ..a.clone()
    };
    assert_eq!(vm_unmap(&no_unmap, U, P), Err(Error::AccessDenied));
    let no_map = Cap {
        rights: Rights::UNMAP,
        ..a.clone()
    };
    assert_eq!(vm_protect(&no_map, U, P, 0), Err(Error::AccessDenied));
    vm_unmap(&no_map, U, 2 * P).unwrap();
}
