//! Testes de host da caixa de pedidos entre CPUs (T-322).

use super::*;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::vec::Vec;

static RAN: AtomicU64 = AtomicU64::new(0);

fn add(arg: u64) {
    RAN.fetch_add(arg, Ordering::Relaxed);
}

#[test]
fn caixa_vazia_nao_faz_nada() {
    let m = Mailbox::new();
    assert_eq!(m.poll(), 0);
    assert!(!m.take_resched());
    assert_eq!(m.handled(), [0, 0, 0]);
}

#[test]
fn resched_liga_e_e_consumido_uma_vez() {
    let m = Mailbox::new();
    m.post(RESCHED);
    m.post(RESCHED);
    assert!(!m.resched_pending());
    assert_eq!(m.poll(), RESCHED);
    assert!(m.resched_pending());
    assert!(m.take_resched());
    assert!(!m.take_resched());
    assert_eq!(m.poll(), 0);
    assert_eq!(m.handled(), [1, 0, 0]);
}

#[test]
fn funcao_remota_roda_uma_vez_com_o_argumento() {
    static HERE: AtomicU64 = AtomicU64::new(0);
    fn put(arg: u64) {
        HERE.store(arg, Ordering::Relaxed);
    }
    let m = Mailbox::new();
    assert!(m.claim_call());
    assert!(!m.claim_call());
    m.post_call(put, 42);
    assert!(!m.call_done());
    assert_eq!(m.poll(), CALL);
    assert!(m.call_done());
    assert_eq!(HERE.load(Ordering::Relaxed), 42);
    assert_eq!(m.poll(), 0);
    m.release_call();
    assert!(m.claim_call());
    m.release_call();
    assert_eq!(m.handled(), [0, 1, 0]);
}

/// Quatro CPUs de mentira, cada uma pedindo funções às outras e atendendo a
/// própria caixa enquanto espera: nenhum pedido se perde nem roda duas
/// vezes, e quem pede uma à outra ao mesmo tempo não trava.
#[test]
fn pedidos_cruzados_entre_quatro_cpus() {
    const CPUS: usize = 4;
    const CALLS: u64 = 2_000;
    let boxes: Arc<Vec<Mailbox>> = Arc::new((0..CPUS).map(|_| Mailbox::new()).collect());
    let finished = Arc::new(AtomicUsize::new(0));
    let before = RAN.load(Ordering::Relaxed);
    let threads: Vec<_> = (0..CPUS)
        .map(|me| {
            let boxes = Arc::clone(&boxes);
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                for i in 0..CALLS {
                    let to = (me + 1 + usize::try_from(i).unwrap() % (CPUS - 1)) % CPUS;
                    let target = &boxes[to];
                    while !target.claim_call() {
                        boxes[me].poll();
                        std::hint::spin_loop();
                    }
                    target.post_call(add, 1);
                    while !target.call_done() {
                        boxes[me].poll();
                        std::hint::spin_loop();
                    }
                    target.release_call();
                }
                finished.fetch_add(1, Ordering::AcqRel);
                // Segue atendendo até todas terminarem.
                while finished.load(Ordering::Acquire) < CPUS {
                    boxes[me].poll();
                    std::hint::spin_loop();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let calls: u64 = boxes.iter().map(|b| b.handled()[1]).sum();
    assert_eq!(calls, CALLS * CPUS as u64);
    // Outros testes podem somar em `RAN` ao mesmo tempo, mas só com
    // argumento 1 e sem descontar: ao menos os pedidos deste teste.
    assert!(RAN.load(Ordering::Relaxed) - before >= CALLS * CPUS as u64);
}
