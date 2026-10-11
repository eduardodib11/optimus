//! Testes no host de `Endpoint`, `Reply` e do cancelamento por prazo.

use alloc::sync::Arc;

use kabi::ObjectType;

use super::*;
use crate::cap::obj_create;
use crate::vm::tests::platform;

fn thread(quota: &Arc<MemoryQuota>) -> Arc<Thread> {
    Arc::new(Thread::new(quota, platform(100).1).unwrap())
}

#[test]
fn obj_create_cobra_e_devolve() {
    let quota = MemoryQuota::root(1 << 20);
    let ep = obj_create(&quota, ObjectType::Endpoint, 0).unwrap();
    let reply = obj_create(&quota, ObjectType::Reply, 0).unwrap();
    assert_eq!(ep.object_type(), ObjectType::Endpoint);
    assert_eq!(reply.object_type(), ObjectType::Reply);
    assert!(ep.as_endpoint().is_ok() && ep.as_reply().is_err());
    assert!(reply.as_reply().is_ok() && reply.as_endpoint().is_err());
    assert!(quota.used() > 0);
    drop((ep, reply));
    assert_eq!(quota.used(), 0);
    for ty in [ObjectType::Endpoint, ObjectType::Reply] {
        assert_eq!(
            obj_create(&quota, ty, 1).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            obj_create(&MemoryQuota::root(8), ty, 0).unwrap_err(),
            Error::QuotaExceeded
        );
    }
}

#[test]
fn filas_fifo_e_remocao() {
    let quota = MemoryQuota::root(1 << 22);
    let ep = Endpoint::new(&quota).unwrap();
    let (a, b, c) = (thread(&quota), thread(&quota), thread(&quota));
    ep.push_sender(&a).unwrap();
    ep.push_sender(&b).unwrap();
    ep.push_receiver(&c).unwrap();
    assert_eq!(ep.queued(), (2, 1));
    assert!(ep.remove(&a));
    assert!(!ep.remove(&a));
    assert!(Arc::ptr_eq(&ep.pop_sender().unwrap(), &b));
    assert!(ep.pop_sender().is_none());
    assert!(Arc::ptr_eq(&ep.pop_receiver().unwrap(), &c));
    assert_eq!(ep.queued(), (0, 0));
}

#[test]
fn reply_de_uso_unico() {
    let quota = MemoryQuota::root(1 << 22);
    let reply = Reply::new(&quota).unwrap();
    let (a, b) = (thread(&quota), thread(&quota));
    assert!(!reply.pending() && reply.grant().is_none());
    reply.bind(Arc::clone(&a), true).unwrap();
    assert_eq!(reply.bind(Arc::clone(&b), false), Err(Error::Busy));
    assert!(reply.holds(&a) && !reply.holds(&b));
    assert_eq!(reply.grant(), Some(true));
    assert!(!reply.remove(&b));
    let (who, grant) = reply.take().unwrap();
    assert!(Arc::ptr_eq(&who, &a) && grant);
    assert!(reply.take().is_none());
    reply.bind(Arc::clone(&b), false).unwrap();
    assert!(reply.remove(&b) && !reply.pending());
}

#[test]
fn cancelar_tira_da_fila_e_do_reply() {
    let quota = MemoryQuota::root(1 << 22);
    let ep = Arc::new(Endpoint::new(&quota).unwrap());
    let reply = Arc::new(Reply::new(&quota).unwrap());
    let (a, b, c) = (thread(&quota), thread(&quota), thread(&quota));
    a.ipc().lock().blocked = Blocked::Send(Arc::downgrade(&ep));
    a.ipc().lock().out = Some(Outgoing::default());
    ep.push_sender(&a).unwrap();
    b.ipc().lock().blocked = Blocked::Reply(Arc::downgrade(&reply));
    reply.bind(Arc::clone(&b), false).unwrap();
    assert!(cancel(&a, Error::TimedOut));
    assert!(cancel(&b, Error::TimedOut));
    assert!(!cancel(&c, Error::TimedOut));
    assert_eq!(ep.queued(), (0, 0));
    assert!(!reply.pending());
    for t in [&a, &b] {
        let slot = t.ipc().lock();
        assert_eq!(slot.result, Err(Error::TimedOut));
        assert!(matches!(slot.blocked, Blocked::None) && slot.out.is_none());
    }
    // Endpoint já destruído: o cancelamento só limpa a thread.
    let gone = Arc::new(Endpoint::new(&quota).unwrap());
    c.ipc().lock().blocked = Blocked::Recv(Arc::downgrade(&gone), Arc::clone(&reply), true);
    drop(gone);
    assert!(cancel(&c, Error::TimedOut));
}

#[test]
fn buffer_de_ipc_so_alinhado_e_de_usuario() {
    let quota = MemoryQuota::root(1 << 22);
    let t = thread(&quota);
    assert_eq!(t.ipc_buffer(), None);
    t.set_ipc_buffer(0x50_0000).unwrap();
    assert_eq!(t.ipc_buffer(), Some(0x50_0000));
    for bad in [0x50_0008, 0x1000, kabi::vm::USER_END, 0xffff_ffff_ffff_f000] {
        assert_eq!(t.set_ipc_buffer(bad), Err(Error::InvalidArgument));
    }
    t.set_ipc_buffer(0).unwrap();
    assert_eq!(t.ipc_buffer(), None);
}
