//! Testes de host do protocolo de shootdown (T-326).

use super::*;
use std::sync::atomic::AtomicBool;
use std::vec::Vec;

#[test]
fn faixa_grande_vira_tudo() {
    assert_eq!(
        Flush::range(0x1000, 32),
        Flush::Pages {
            start: 0x1000,
            pages: 32
        }
    );
    assert_eq!(Flush::range(0x1000, 33), Flush::All);
    assert!(applies(KERNEL_ROOT, 0x5000));
    assert!(applies(0x5000, 0x5000));
    assert!(!applies(0x5000, 0x6000));
}

#[test]
fn pedido_lido_como_gravado_e_confirmado_por_todos() {
    let r = Request::new();
    assert!(r.done());
    r.post(0x7000, Flush::range(0x40_0000, 3), 2);
    assert_eq!(
        r.read(),
        (
            0x7000,
            Flush::Pages {
                start: 0x40_0000,
                pages: 3
            }
        )
    );
    assert_eq!(r.pending(), 2);
    r.ack();
    assert!(!r.done());
    r.ack();
    assert!(r.done());
    r.post(KERNEL_ROOT, Flush::All, 1);
    assert_eq!(r.read(), (KERNEL_ROOT, Flush::All));
}

#[test]
fn caixa_de_entrada_entrega_cada_cpu_uma_vez() {
    let inbox = Inbox::new();
    for cpu in [3, 64, 200, 3, 255] {
        inbox.signal(cpu);
    }
    inbox.signal(256);
    let mut got = Vec::new();
    inbox.drain(&mut |c| got.push(c));
    assert_eq!(got, [3, 64, 200, 255]);
    got.clear();
    inbox.drain(&mut |c| got.push(c));
    assert!(got.is_empty());
}

/// Quatro "CPUs" fazem rodadas de shootdown umas para as outras ao mesmo
/// tempo, cada uma atendendo a própria caixa enquanto espera: toda rodada
/// termina e cada alvo invalida cada pedido exatamente uma vez.
#[test]
fn rodadas_cruzadas_terminam() {
    const CPUS_N: usize = 4;
    const OTHERS: u32 = 3;
    const ROUNDS: u64 = 2000;
    struct Cpu {
        request: Request,
        inbox: Inbox,
        /// Invalidações feitas aqui, por CPU que pediu.
        served: [AtomicU64; CPUS_N],
    }
    let cpus: Vec<Cpu> = (0..CPUS_N)
        .map(|_| Cpu {
            request: Request::new(),
            inbox: Inbox::new(),
            served: [const { AtomicU64::new(0) }; CPUS_N],
        })
        .collect();
    let stop = AtomicBool::new(false);
    let serve = |me: usize| {
        cpus[me].inbox.drain(&mut |from| {
            let (root, flush) = cpus[from].request.read();
            assert_eq!(root, from as u64 + 1);
            assert_eq!(
                flush,
                Flush::Pages {
                    start: 0x1000,
                    pages: 1
                }
            );
            cpus[me].served[from].fetch_add(1, Ordering::Relaxed);
            cpus[from].request.ack();
        });
    };
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..CPUS_N)
            .map(|me| {
                let (cpus, serve) = (&cpus, &serve);
                s.spawn(move || {
                    for _ in 0..ROUNDS {
                        let req = &cpus[me].request;
                        req.post(me as u64 + 1, Flush::range(0x1000, 1), OTHERS);
                        for t in (0..CPUS_N).filter(|&t| t != me) {
                            cpus[t].inbox.signal(me);
                        }
                        while !req.done() {
                            serve(me);
                            std::hint::spin_loop();
                        }
                    }
                })
            })
            .collect();
        // Quem terminou segue atendendo até todas terminarem.
        let helpers: Vec<_> = (0..CPUS_N)
            .map(|me| {
                let (serve, stop) = (&serve, &stop);
                s.spawn(move || {
                    while !stop.load(Ordering::Acquire) {
                        serve(me);
                        std::hint::spin_loop();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Release);
        for h in helpers {
            h.join().unwrap();
        }
    });
    for (me, cpu) in cpus.iter().enumerate() {
        for (from, n) in cpu.served.iter().enumerate() {
            let want = if from == me { 0 } else { ROUNDS };
            assert_eq!(n.load(Ordering::Relaxed), want);
        }
    }
}
