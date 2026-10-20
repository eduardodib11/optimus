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
    assert!(t.aspace().is_some_and(|a| Arc::ptr_eq(&a, &aspace)));
    t.set_wake_value(0b101);
    assert_eq!(t.wake_value(), 0b101);
    t.set_state(RunState::Ready);
    assert_eq!(t.configure(cspace, aspace), Err(Error::Busy));
    for s in [
        RunState::Running,
        RunState::Throttled,
        RunState::Exited,
        RunState::Blocked,
    ] {
        t.set_state(s);
        assert_eq!(t.state(), s);
    }
}

#[test]
fn so_um_despertar_vence() {
    let (_, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let t = Thread::new(&quota, p).unwrap();
    assert!(!t.on_cpu());
    for s in [RunState::Inactive, RunState::Ready, RunState::Running] {
        t.set_state(s);
        assert!(!t.claim_wake());
        assert_eq!(t.state(), s);
    }
    t.set_state(RunState::Blocked);
    let t = Arc::new(t);
    let won: usize = std::thread::scope(|scope| {
        let handles: std::vec::Vec<_> = (0..4)
            .map(|_| scope.spawn(|| usize::from(t.claim_wake())))
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });
    assert_eq!((won, t.state()), (1, RunState::Ready));
    t.set_on_cpu(true);
    assert!(t.on_cpu());
}

#[test]
fn tls_so_na_metade_de_usuario() {
    let (_, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let t = Thread::new(&quota, p).unwrap();
    assert_eq!(t.tls(), 0);
    for va in [0x1234_5678, 0, USER_END - 1, 8] {
        assert_eq!(t.set_tls(va), Ok(()));
        assert_eq!(t.tls(), va);
    }
    // Não canônico (daria #GP no WRMSR), metade alta e o próprio fim.
    for bad in [
        USER_END,
        0x0000_8000_0000_1000,
        0xffff_8000_0000_0000,
        u64::MAX,
    ] {
        assert_eq!(t.set_tls(bad), Err(Error::InvalidArgument));
        assert_eq!(t.tls(), 8);
    }
}

#[test]
fn registro_de_morte_so_a_primeira() {
    use kabi::exit::{CAUSE_EXITED, CAUSE_FAULTED};
    let (_, p) = platform(100);
    let quota = MemoryQuota::root(1 << 20);
    let t = Thread::new(&quota, p).unwrap();
    assert_eq!(t.death(), None);
    t.record_death(0, 1, 2);
    assert_eq!(t.death(), None);
    t.record_death(CAUSE_EXITED, kabi::exit::PANIC_CODE, 0);
    t.record_death(CAUSE_FAULTED, 14, 0xdead);
    assert_eq!(t.death(), Some((CAUSE_EXITED, kabi::exit::PANIC_CODE, 0)));
}
