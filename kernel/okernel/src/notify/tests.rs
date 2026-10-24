//! Testes no host de `Notification` e `Interrupt`.

use super::*;
use crate::vm::tests::platform;

fn thread(quota: &Arc<MemoryQuota>) -> Arc<Thread> {
    Arc::new(Thread::new(quota, platform(100).1).unwrap())
}

#[test]
fn sinal_sem_espera_fica_pendente_e_acumula() {
    let quota = MemoryQuota::root(1 << 20);
    let n = Arc::new(Notification::new(&quota).unwrap());
    assert!(quota.used() > 0);
    assert!(n.signal(0b01).is_none());
    assert!(n.signal(0b10).is_none());
    assert_eq!(n.pending(), 0b11);
    let t = thread(&quota);
    assert_eq!(n.wait(&t), Ok(Wait::Ready(0b11)));
    assert_eq!((n.pending(), n.poll()), (0, 0));
    assert!(n.signal(0b100).is_none());
    assert_eq!(n.poll(), 0b100);
    drop((n, t));
    assert_eq!(quota.used(), 0);
}

#[test]
fn espera_bloqueia_e_o_sinal_acorda_em_ordem() {
    let quota = MemoryQuota::root(1 << 20);
    let n = Arc::new(Notification::new(&quota).unwrap());
    let (a, b) = (thread(&quota), thread(&quota));
    assert_eq!(n.wait(&a), Ok(Wait::Blocked));
    assert_eq!(n.wait(&b), Ok(Wait::Blocked));
    assert_eq!((a.state(), n.waiters()), (RunState::Blocked, 2));
    let (first, word) = n.signal(0b1000).unwrap();
    assert!(Arc::ptr_eq(&first, &a) && word == 0b1000);
    assert_eq!(n.pending(), 0);
    let (second, word) = n.signal(1).unwrap();
    assert!(Arc::ptr_eq(&second, &b) && word == 1);
    assert!(n.signal(0).is_none());
    assert_eq!(n.waiters(), 0);
}

#[test]
fn interrupcao_mascara_ate_o_ack() {
    let quota = MemoryQuota::root(1 << 20);
    let n = Arc::new(Notification::new(&quota).unwrap());
    let irq = Interrupt::new(&quota, 0x40).unwrap();
    assert!(irq.fire().is_none(), "sem ligação não sinaliza");
    assert_eq!(irq.bind(Arc::clone(&n), 64), Err(Error::InvalidArgument));
    assert_eq!(
        irq.bind(Arc::clone(&n), u64::MAX),
        Err(Error::InvalidArgument)
    );
    irq.bind(Arc::clone(&n), 5).unwrap();
    assert_eq!(irq.bind(Arc::clone(&n), 6), Err(Error::Busy));
    let (target, bits) = irq.fire().unwrap();
    assert!(Arc::ptr_eq(&target, &n) && bits == 1 << 5);
    // Mascarada: o segundo disparo espera o ack.
    assert!(irq.fire().is_none());
    assert_eq!(irq.ack().map(|(_, b)| b), Some(1 << 5));
    assert!(irq.fire().is_none());
    assert!(irq.ack().is_some());
    assert!(irq.ack().is_none());
    assert!(irq.fire().is_some());
    assert_eq!(irq.vector(), 0x40);
}

/// Quem espera numa notificação que morre acorda com `PeerClosed` (ADR
/// 0032, item 6), e o erro vale só para esse despertar.
#[test]
fn notificacao_destruida_acorda_com_peer_closed() {
    use core::sync::atomic::Ordering;
    let quota = MemoryQuota::root(1 << 20);
    let (fake, leaked) = platform(100);
    let n = Arc::new(Notification::new(&quota).unwrap());
    let t = Arc::new(Thread::new(&quota, leaked).unwrap());
    assert_eq!(n.wait(&t), Ok(Wait::Blocked));
    let before = fake.woken.load(Ordering::Relaxed);
    drop(n);
    assert_eq!(fake.woken.load(Ordering::Relaxed) - before, 1);
    assert_eq!(t.take_wake_error(), Some(Error::PeerClosed));
    assert_eq!(t.take_wake_error(), None);
}
