//! Testes no host de `mem_op` e de `obj_create` com `LAZY` (T-360; ADR
//! 0038, item 2): direitos, domínio e fatias.

use kabi::mem::{AGE, CACHE, COMMIT, DECOMMIT, HIDE, LAZY, PUBLISH, PUBLISH_FLAG, ZERO};

use super::*;

fn lazy(space: &Arc<SharedCapSpace>, q: u64, pages: u64) -> u64 {
    let ty = ObjectType::MemoryObject.to_raw();
    call(
        space,
        Syscall::ObjCreate,
        [q, ty, pages * PAGE_SIZE, LAZY, 0, 0],
    )
    .unwrap()[0]
}

fn op(
    space: &Arc<SharedCapSpace>,
    m: u64,
    op: u64,
    off: u64,
    len: u64,
    flags: u64,
) -> Result<Values, Error> {
    call(space, Syscall::MemOp, [m, op, off, len, flags, 0])
}

#[test]
fn obj_create_lazy_da_evict_e_recusa_flags_estranhas() {
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let m = lazy(&space, q, 4);
    let rights = get(&space, m).rights;
    assert!(rights.contains(Rights::EVICT | Rights::READ | Rights::WRITE | Rights::MAP));
    let ty = |t: ObjectType| t.to_raw();
    let bad = [
        [q, ty(ObjectType::MemoryObject), PAGE_SIZE, 2, 0, 0],
        [q, ty(ObjectType::Endpoint), 0, LAZY, 0, 0],
    ];
    for a in bad {
        assert_eq!(
            call(&space, Syscall::ObjCreate, a),
            Err(Error::InvalidArgument)
        );
    }
    // Sem `LAZY`, o criador não recebe `EVICT`.
    let eager = call(
        &space,
        Syscall::ObjCreate,
        [q, ty(ObjectType::MemoryObject), PAGE_SIZE, 0, 0, 0],
    );
    assert!(
        !get(&space, eager.unwrap()[0])
            .rights
            .contains(Rights::EVICT)
    );
}

#[test]
fn mem_op_confere_direitos_e_dominio() {
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let m = lazy(&space, q, 4);
    let p = PAGE_SIZE;
    assert_eq!(op(&space, m, 7, 0, p, 0), Err(Error::InvalidArgument));
    assert_eq!(op(&space, m, COMMIT, 1, p, 0), Err(Error::InvalidArgument));
    assert_eq!(
        op(&space, m, COMMIT, 0, p + 1, 0),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        op(&space, m, COMMIT, 3 * p, 2 * p, 0),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        op(&space, m, COMMIT, u64::MAX - p + 1, p, 0),
        Err(Error::InvalidArgument)
    );
    assert_eq!(op(&space, m, COMMIT, 0, p, 2), Err(Error::InvalidArgument));
    assert_eq!(op(&space, m, ZERO, 0, p, 1), Err(Error::InvalidArgument));
    for o in [CACHE, HIDE, DECOMMIT, AGE] {
        assert_eq!(op(&space, m, o, 0, p, 0), Err(Error::NotSupported), "{o}");
    }
    // Página ausente não se publica.
    assert_eq!(op(&space, m, PUBLISH, 0, p, 0), Err(Error::InvalidArgument));
    assert_eq!(op(&space, m, COMMIT, 0, 4 * p, PUBLISH_FLAG), Ok([0; 3]));
    assert_eq!(op(&space, m, ZERO, 0, 4 * p, 0), Ok([0; 3]));
    // Sem `EVICT`, `PUBLISH` é recusado; sem `WRITE`, `COMMIT` e `ZERO`.
    let rw = u64::from((Rights::READ | Rights::WRITE | Rights::MAP).bits());
    let [m_rw, ..] = call(&space, Syscall::CapMint, [m, rw, 0, 0, 0, 0]).unwrap();
    assert_eq!(op(&space, m_rw, PUBLISH, 0, p, 0), Err(Error::AccessDenied));
    assert_eq!(op(&space, m_rw, COMMIT, 0, p, 0), Ok([0; 3]));
    let ev = u64::from((Rights::READ | Rights::EVICT).bits());
    let [m_ev, ..] = call(&space, Syscall::CapMint, [m, ev, 0, 0, 0, 0]).unwrap();
    assert_eq!(op(&space, m_ev, COMMIT, 0, p, 0), Err(Error::AccessDenied));
    assert_eq!(op(&space, m_ev, ZERO, 0, p, 0), Err(Error::AccessDenied));
    assert_eq!(op(&space, m_ev, PUBLISH, 0, p, 0), Ok([0; 3]));
    let ntfy = create(&space, q, ObjectType::Notification);
    assert_eq!(op(&space, ntfy, COMMIT, 0, p, 0), Err(Error::WrongType));
}

#[test]
fn mem_op_roda_em_fatias_e_cobra_o_dono() {
    platform::install(fake_platform(1000).1);
    let (root, space, q) = setup();
    let pages = 3 * MEM_OP_SLICE + 1;
    let m = lazy(&space, q, pages);
    let before = root.used();
    let mut env = Fake::default();
    let a = [m, COMMIT, 0, pages * PAGE_SIZE, 0, 0];
    assert_eq!(invoke(&space, Syscall::MemOp, a, 4, &mut env), Ok([0; 3]));
    assert_eq!(env.preempts, 3, "uma preempção entre fatias");
    assert_eq!(root.used(), before + pages * PAGE_SIZE);
    // Quem só tem a cópia não paga: a cota é a do dono.
    assert_eq!(op(&space, m, COMMIT, 0, pages * PAGE_SIZE, 0), Ok([0; 3]));
    assert_eq!(root.used(), before + pages * PAGE_SIZE);
}
