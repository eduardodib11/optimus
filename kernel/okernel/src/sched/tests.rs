//! Testes no host da fila de prontas e do orçamento.

use alloc::sync::Arc;

use super::*;
use crate::cap::MemoryQuota;

const MS: u64 = 1_000_000;

#[test]
fn parametros_validos() {
    let p = Params::new(10 * MS, 50 * MS, 200).unwrap();
    assert_eq!(
        (p.budget_ns, p.period_ns, p.priority),
        (10 * MS, 50 * MS, 200)
    );
    assert!(!p.unlimited());
    assert!(Params::new(MS, MS, 0).unwrap().unlimited());
    for (b, per, prio) in [
        (MS, MS, 256),
        (2 * MS, MS, 1),
        (1, MS, 1),
        (MIN_BUDGET_NS, MIN_PERIOD_NS - 1, 1),
    ] {
        assert_eq!(Params::new(b, per, prio), Err(Error::InvalidArgument));
    }
}

#[test]
fn orcamento_esgota_e_volta_no_proximo_periodo() {
    let p = Params::new(10 * MS, 50 * MS, 100).unwrap();
    let mut b = Budget::default();
    assert!(!b.exhausted(&p));
    b.activate(&p, 1000);
    assert_eq!((b.remaining, b.replenish_at), (10 * MS, 1000 + 50 * MS));
    // Ativar de novo não recomeça a janela.
    b.activate(&p, 5000);
    assert_eq!(b.replenish_at, 1000 + 50 * MS);
    assert_eq!(b.deadline(&p, 2000), Some(2000 + 10 * MS));
    b.consume(&p, 4 * MS);
    b.consume(&p, 7 * MS);
    assert!(b.exhausted(&p));
    // Antes do fim da janela, nada volta.
    assert!(!b.refill(&p, 1000 + 50 * MS - 1));
    assert!(b.exhausted(&p));
    assert!(b.refill(&p, 1000 + 50 * MS));
    assert_eq!((b.remaining, b.replenish_at), (10 * MS, 1000 + 100 * MS));
    // Atrasos alinham ao próximo limite de período, sem acumular.
    b.consume(&p, MS);
    assert!(b.refill(&p, 1000 + 230 * MS));
    assert_eq!((b.remaining, b.replenish_at), (10 * MS, 1000 + 250 * MS));
    // Sem limite: nunca esgota.
    let free = Params::new(MS, MS, 1).unwrap();
    let mut f = Budget::default();
    f.activate(&free, 0);
    f.consume(&free, 100 * MS);
    assert!(!f.exhausted(&free));
    assert_eq!(f.deadline(&free, 0), None);
}

#[test]
fn fila_por_prioridade_e_round_robin() {
    let mut q = RunQueue::new();
    assert!(q.is_empty());
    assert_eq!(q.highest(), None);
    for (prio, item) in [
        (10, 'a'),
        (200, 'b'),
        (10, 'c'),
        (255, 'd'),
        (0, 'e'),
        (200, 'f'),
    ] {
        q.push(prio, item).unwrap();
    }
    assert_eq!((q.len(), q.highest()), (6, Some(255)));
    let order: alloc::vec::Vec<_> = core::iter::from_fn(|| q.pop()).collect();
    assert_eq!(
        order,
        [
            (255, 'd'),
            (200, 'b'),
            (200, 'f'),
            (10, 'a'),
            (10, 'c'),
            (0, 'e')
        ]
    );
    assert!(q.is_empty());
    // Todos os 256 níveis, nas quatro palavras do bitmap.
    let mut q = RunQueue::new();
    for prio in 0..=255u8 {
        q.push(prio, prio).unwrap();
    }
    for expected in (0..=255u8).rev() {
        assert_eq!(q.pop(), Some((expected, expected)));
    }
}

#[test]
fn sched_context_configura_e_liga_uma_vez() {
    let quota = MemoryQuota::root(1 << 10);
    let sc = Arc::new(SchedContext::new(quota.charge(64).unwrap()));
    assert_eq!(sc.params(), None);
    let p = Params::new(MS, 4 * MS, 0).unwrap();
    sc.configure(p);
    assert_eq!(sc.params(), Some(p));
    let mut b = sc.budget();
    b.activate(&p, 7);
    sc.set_budget(b);
    assert_eq!(sc.budget(), b);
    // Reconfigurar recomeça a janela.
    sc.configure(Params::new(MS, 8 * MS, 255).unwrap());
    assert_eq!(sc.budget(), Budget::default());
    assert_eq!(sc.params().map(|p| p.priority), Some(255));
    assert!(sc.try_bind());
    assert!(!sc.try_bind());
    drop(sc);
    assert_eq!(quota.used(), 0);
}

#[test]
fn sched_context_comeca_com_todas_as_cpus() {
    use kabi::sched::CpuMask;
    let quota = MemoryQuota::root(1 << 10);
    let sc = SchedContext::new(quota.charge(64).unwrap());
    assert_eq!(sc.mask(), CpuMask::ALL);
    assert!(sc.allows(0) && sc.allows(255));
    sc.set_mask(CpuMask::only(2).with(130));
    assert_eq!(sc.mask(), CpuMask::only(2).with(130));
    assert!(sc.allows(2) && sc.allows(130));
    assert!(!sc.allows(0) && !sc.allows(3) && !sc.allows(256));
    // Reconfigurar o orçamento não mexe na máscara.
    sc.configure(Params::new(MS, MS, 3).unwrap());
    assert_eq!(sc.mask(), CpuMask::only(2).with(130));
}

#[test]
fn roubo_tira_o_primeiro_que_serve_do_nivel_mais_alto() {
    let mut q = RunQueue::new();
    for (prio, item) in [(5, 50), (9, 90), (9, 91), (9, 92), (1, 10)] {
        q.push(prio, item).unwrap();
    }
    // O 90 não serve: sai o 91, e a ordem do nível segue.
    assert_eq!(q.take_where(0, |_, t| *t != 90), Some((9, 91)));
    // A partir do nível 6, nada abaixo de 90 serve (o 5 fica de fora).
    assert_eq!(q.take_where(6, |_, t| *t < 90), None);
    assert_eq!(q.take_where(0, |p, _| p < 9), Some((5, 50)));
    assert_eq!(q.highest(), Some(9));
    assert_eq!(q.pop(), Some((9, 90)));
    assert_eq!(q.pop(), Some((9, 92)));
    assert_eq!(q.take_where(0, |_, _| true), Some((1, 10)));
    assert!(q.is_empty());
    assert_eq!(q.highest(), None);
}
