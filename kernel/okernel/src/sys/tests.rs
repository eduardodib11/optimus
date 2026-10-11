//! Testes no host do despacho portável de syscalls.

use alloc::sync::Arc;

use kabi::vm::{PAGE_SIZE, WRITE};

use super::*;
use crate::cap::{Cap, MemoryQuota, Object, default_rights};
use crate::platform;
use crate::sync::SpinLock;
use crate::vm::tests::platform as fake_platform;

fn setup() -> (Arc<MemoryQuota>, SharedCapSpace, u64) {
    let root = MemoryQuota::root(64 << 20);
    let space = SpinLock::new(crate::cap::CapSpace::new(&root).unwrap());
    let q = space
        .lock()
        .insert(Cap {
            object: Object::MemoryQuota(Arc::clone(&root)),
            rights: default_rights(ObjectType::MemoryQuota),
            badge: 0,
        })
        .unwrap();
    (root, space, u64::from(q.raw()))
}

fn call(space: &SharedCapSpace, c: Syscall, a: [u64; 6]) -> Result<Values, Error> {
    invoke(space, c, a, 4, &mut || {})
}

#[test]
fn mint_info_delete_e_revoke() {
    let (_root, space, q) = setup();
    let create = u64::from(Rights::CREATE.bits());
    let [h, ..] = call(&space, Syscall::CapMint, [q, create, 7, 0, 0, 0]).unwrap();
    let info = call(&space, Syscall::CapInfo, [h, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(info, [ObjectType::MemoryQuota.to_raw(), create, 7]);
    // Direitos inexistentes ou handle fora de 32 bits.
    assert_eq!(
        call(&space, Syscall::CapMint, [q, 1 << 40, 0, 0, 0, 0]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        call(&space, Syscall::CapInfo, [1 << 32, 0, 0, 0, 0, 0]),
        Err(Error::InvalidHandle)
    );
    for _ in 0..20 {
        call(&space, Syscall::CapMint, [h, create, 0, 0, 0, 0]).unwrap();
    }
    let mut slices = 0;
    invoke(
        &space,
        Syscall::CapRevoke,
        [h, 0, 0, 0, 0, 0],
        4,
        &mut || {
            slices += 1;
        },
    )
    .unwrap();
    assert!(slices > 1, "revogação fatiada");
    assert_eq!(space.lock().len(), 2);
    call(&space, Syscall::CapDelete, [h, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(
        call(&space, Syscall::CapInfo, [h, 0, 0, 0, 0, 0]),
        Err(Error::InvalidHandle)
    );
}

#[test]
fn obj_create_e_vm_por_handles() {
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let ty = |t: ObjectType| t.to_raw();
    assert_eq!(
        call(&space, Syscall::ObjCreate, [q, 99, 0, 0, 0, 0]),
        Err(Error::InvalidArgument)
    );
    let [a, ..] = call(
        &space,
        Syscall::ObjCreate,
        [q, ty(ObjectType::AddressSpace), 0, 0, 0, 0],
    )
    .unwrap();
    let [m, ..] = call(
        &space,
        Syscall::ObjCreate,
        [q, ty(ObjectType::MemoryObject), 2 * PAGE_SIZE, 0, 0, 0],
    )
    .unwrap();
    let va = 0x40_0000;
    // O objeto sem MAP não mapeia.
    let read = u64::from((Rights::READ | Rights::WRITE).bits());
    let [m_ro, ..] = call(&space, Syscall::CapMint, [m, read, 0, 0, 0, 0]).unwrap();
    let map = |obj| call(&space, Syscall::VmMap, [a, obj, va, 0, PAGE_SIZE, WRITE]);
    assert_eq!(map(m_ro), Err(Error::AccessDenied));
    assert_eq!(map(a), Err(Error::WrongType));
    assert_eq!(map(m), Ok([0; 3]));
    assert_eq!(map(m), Err(Error::InvalidArgument));
    assert_eq!(
        call(&space, Syscall::VmProtect, [a, va, PAGE_SIZE, 0, 0, 0]),
        Ok([0; 3])
    );
    assert_eq!(
        call(&space, Syscall::VmUnmap, [a, va, PAGE_SIZE, 0, 0, 0]),
        Ok([0; 3])
    );
}

#[test]
fn as_outras_nao_sao_suportadas_aqui() {
    let (_root, space, _) = setup();
    for &c in Syscall::ALL {
        let handled = matches!(
            c,
            Syscall::CapMint
                | Syscall::CapDelete
                | Syscall::CapRevoke
                | Syscall::CapInfo
                | Syscall::ObjCreate
                | Syscall::VmMap
                | Syscall::VmUnmap
                | Syscall::VmProtect
                | Syscall::SchedConfigure
                | Syscall::SchedBind
        );
        if !handled {
            assert_eq!(call(&space, c, [0; 6]), Err(Error::NotSupported), "{c:?}");
        }
    }
}

#[test]
fn sched_configure_e_bind_conferem_direitos() {
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let create =
        |t: ObjectType| call(&space, Syscall::ObjCreate, [q, t.to_raw(), 0, 0, 0, 0]).unwrap()[0];
    let (sc, t) = (create(ObjectType::SchedContext), create(ObjectType::Thread));
    let ms = 1_000_000;
    let conf = |sc| {
        call(
            &space,
            Syscall::SchedConfigure,
            [sc, ms, 10 * ms, 120, 0, 0],
        )
    };
    let bind_only = u64::from(Rights::BIND.bits());
    let [sc_bind, ..] = call(&space, Syscall::CapMint, [sc, bind_only, 0, 0, 0, 0]).unwrap();
    assert_eq!(conf(sc_bind), Err(Error::AccessDenied));
    assert_eq!(conf(t), Err(Error::WrongType));
    assert_eq!(
        call(&space, Syscall::SchedConfigure, [sc, 2 * ms, ms, 1, 0, 0]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(conf(sc), Ok([0; 3]));
    let read = u64::from(Rights::READ_STATE.bits());
    let [t_ro, ..] = call(&space, Syscall::CapMint, [t, read, 0, 0, 0, 0]).unwrap();
    let bind = |sc, t| call(&space, Syscall::SchedBind, [sc, t, 0, 0, 0, 0]);
    assert_eq!(bind(sc, t_ro), Err(Error::AccessDenied));
    assert_eq!(bind(sc_bind, t), Ok([0; 3]));
    assert_eq!(bind(sc, t), Err(Error::Busy));
    let thread = space
        .lock()
        .get(Handle::from_raw(u32::try_from(t).unwrap()))
        .unwrap()
        .clone();
    let bound = thread.object.as_thread().unwrap().sched_context().unwrap();
    assert_eq!(bound.params().map(|p| p.priority), Some(120));
}
