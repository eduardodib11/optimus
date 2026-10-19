//! Testes no host da tabela de futex.

use alloc::vec::Vec;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc as StdArc, Barrier};

use super::*;
use crate::cap::MemoryQuota;
use crate::vm::tests::platform;

fn threads(n: usize) -> Vec<Arc<Thread>> {
    let quota = MemoryQuota::root(1 << 22);
    (0..n)
        .map(|_| Arc::new(Thread::new(&quota, platform(100).1).unwrap()))
        .collect()
}

#[test]
fn valor_mudado_nao_bloqueia() {
    let table = FutexTable::new();
    let t = threads(1);
    assert_eq!(
        table.wait(0x1000, &t[0], 2, || Some(1)),
        Err(Error::WouldBlock)
    );
    assert_eq!(
        table.wait(0x1000, &t[0], 2, || None),
        Err(Error::InvalidArgument)
    );
    assert_eq!(table.waiting(0x1000), 0);
    assert_eq!(t[0].state(), RunState::Inactive);
    assert_eq!(table.stats().stale, 1);
}

#[test]
fn acorda_por_chave_em_ordem_e_ate_o_maximo() {
    let table = FutexTable::new();
    let t = threads(4);
    for (i, th) in t.iter().enumerate() {
        let key = if i == 2 { 0x2000 } else { 0x1000 };
        table.wait(key, th, 7, || Some(7)).unwrap();
        assert_eq!(th.state(), RunState::Blocked);
    }
    assert_eq!((table.waiting(0x1000), table.waiting(0x2000)), (3, 1));
    let mut woken = Vec::new();
    assert_eq!(table.wake(0x1000, 2, &mut |th| woken.push(th)), 2);
    assert!(Arc::ptr_eq(&woken[0], &t[0]) && Arc::ptr_eq(&woken[1], &t[1]));
    assert_eq!(table.wake(0x3000, 9, &mut |_| panic!("chave errada")), 0);
    assert_eq!(table.wake(0x1000, u64::MAX, &mut |th| woken.push(th)), 1);
    assert!(Arc::ptr_eq(&woken[2], &t[3]));
    assert_eq!(table.waiting(0x2000), 1);
    let stats = table.stats();
    assert_eq!((stats.blocked, stats.woken, stats.stale), (4, 3, 0));
}

/// A leitura acontece com a trava na mão: o `wake` de outra thread do host
/// (como o unlock de um mutex de usuário) não passa entre a leitura e o
/// enfileiramento, então nenhum despertar se perde.
#[test]
fn leitura_e_enfileiramento_sao_atomicos_quanto_ao_wake() {
    let table: &'static FutexTable = Box::leak(Box::new(FutexTable::new()));
    let word = StdArc::new(AtomicU32::new(1));
    let t = threads(1).pop().unwrap();
    let barrier = StdArc::new(Barrier::new(2));
    let waker = {
        let (word, barrier) = (StdArc::clone(&word), StdArc::clone(&barrier));
        std::thread::spawn(move || {
            barrier.wait();
            word.store(0, Ordering::SeqCst);
            // Acorda até achar alguém, ou até a espera ser recusada.
            loop {
                if table.wake(0x1000, 1, &mut |_| {}) > 0 {
                    return true;
                }
                if table.stats().stale > 0 {
                    return false;
                }
                std::thread::yield_now();
            }
        })
    };
    let res = table.wait(0x1000, &t, 1, || {
        barrier.wait();
        std::thread::sleep(std::time::Duration::from_millis(20));
        Some(word.load(Ordering::SeqCst))
    });
    let woke = waker.join().unwrap();
    assert_eq!(res.is_ok(), woke);
    assert_eq!(table.waiting(0x1000), 0);
}

/// Palavras vizinhas (o caso de mutexes num mesmo vetor) se espalham pelos
/// baldes, e a mesma chave cai sempre no mesmo.
#[test]
fn chaves_vizinhas_se_espalham_pelos_baldes() {
    let used: std::collections::BTreeSet<usize> =
        (0..64u64).map(|i| bucket_of(0x1000 + 4 * i)).collect();
    assert!(used.len() >= BUCKETS / 2, "{} baldes", used.len());
    assert!(used.iter().all(|&b| b < BUCKETS));
    assert_eq!(bucket_of(0x1234_5678), bucket_of(0x1234_5678));
}
