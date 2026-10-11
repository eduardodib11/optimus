//! Testes no host do objeto `Thread`.

use core::sync::atomic::Ordering as O;

use super::*;
use crate::cap::CapSpace;
use crate::vm::AddressSpace;
use crate::vm::tests::platform;

#[test]
fn cobra_pilha_e_fpu_e_devolve() {
    let (fake, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let t = Thread::new(&quota, p).unwrap();
    assert_eq!(fake.stacks_live.load(O::Relaxed), 1);
    assert_eq!(t.fpu_bytes(), 832);
    assert!(t.charged() >= KERNEL_STACK_BYTES + 832);
    assert_eq!(quota.used(), t.charged());
    assert_eq!(t.fpu_area() % 64, 0);
    assert_eq!((t.state(), t.root()), (RunState::Inactive, None));
    assert_eq!(&t.fpu[0].0[..2], &[0x7f, 0x03]);
    assert_eq!(&t.fpu[0].0[24..28], &[0x80, 0x1f, 0, 0]);
    drop(t);
    assert_eq!((quota.used(), fake.stacks_live.load(O::Relaxed)), (0, 0));
    let small = MemoryQuota::root(KERNEL_STACK_BYTES);
    assert_eq!(Thread::new(&small, p).unwrap_err(), Error::QuotaExceeded);
    assert_eq!(fake.stacks_live.load(O::Relaxed), 0);
}

#[test]
fn configura_so_antes_de_iniciar() {
    let (_, p) = platform(100);
    let quota = MemoryQuota::root(1 << 24);
    let t = Thread::new(&quota, p).unwrap();
    let cspace = Arc::new(SpinLock::new(CapSpace::new(&quota).unwrap()));
    let aspace = Arc::new(SpinLock::new(AddressSpace::new(&quota, p).unwrap()));
    let root = aspace.lock().root();
    t.configure(Arc::clone(&cspace), Arc::clone(&aspace))
        .unwrap();
    assert_eq!(t.root(), Some(root.0));
    assert!(t.cspace().is_some_and(|c| Arc::ptr_eq(&c, &cspace)));
    t.set_state(RunState::Ready);
    assert_eq!(t.configure(cspace, aspace), Err(Error::Busy));
    for s in [RunState::Running, RunState::Throttled, RunState::Exited] {
        t.set_state(s);
        assert_eq!(t.state(), s);
    }
}
