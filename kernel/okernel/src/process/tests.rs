//! Testes no host de processos e eventos de ciclo de vida (T-348).

use alloc::vec::Vec;

use super::*;
use crate::cap::{CapSpace, MemoryQuota};
use crate::notify::{Notification, Wait};
use crate::sync::SpinLock;
use crate::thread::RunState;
use crate::vm::AddressSpace;
use crate::vm::tests::platform;
use kabi::sched::CpuMask;

/// Ambiente falso: guarda quem foi acordado e quem levou a IPI.
#[derive(Default)]
struct Fake {
    woken: Vec<(Arc<Thread>, u64)>,
    kicked: u32,
}

impl Env for Fake {
    fn preempt(&mut self) {}
    fn wake(&mut self, thread: Arc<Thread>, value: u64) {
        self.woken.push((thread, value));
    }
    fn current(&self) -> Option<Arc<Thread>> {
        None
    }
    fn block(&mut self) {}
    fn read_u32(&mut self, _addr: u64) -> Option<u32> {
        None
    }
    fn now(&self) -> u64 {
        0
    }
    fn block_until(&mut self, _deadline: u64) {}
    fn handoff(&mut self, _to: Arc<Thread>, _deadline: u64) {}
    fn read_buffer(&mut self, _thread: &Thread, _at: usize, _out: &mut [u64]) -> bool {
        false
    }
    fn write_buffer(&mut self, _thread: &Thread, _at: usize, _data: &[u64]) -> bool {
        false
    }
    fn online_cpus(&self) -> CpuMask {
        CpuMask([1, 0, 0, 0])
    }
    fn kick(&mut self, _t: &Thread) {
        self.kicked += 1;
    }
}

struct World {
    quota: Arc<MemoryQuota>,
    aspace: Arc<crate::vm::SharedAddressSpace>,
}

impl World {
    fn new() -> Self {
        let (_, p) = platform(10_000);
        let quota = MemoryQuota::root(64 << 20);
        let aspace = Arc::new(SpinLock::new(AddressSpace::new(&quota, p).unwrap()));
        Self { quota, aspace }
    }

    fn space(&self) -> Arc<SharedCapSpace> {
        Arc::new(SpinLock::new(CapSpace::new(&self.quota).unwrap()))
    }

    /// Uma thread ligada a `space`, ainda inativa.
    fn thread(&self, space: &Arc<SharedCapSpace>) -> Arc<Thread> {
        let t = Arc::new(Thread::new(&self.quota, platform(10_000).1).unwrap());
        t.configure(Arc::clone(space), Arc::clone(&self.aspace))
            .unwrap();
        t
    }

    /// Uma thread de `space` "iniciada" (contada e fora de `Inactive`), como
    /// `thread_start` a deixa.
    fn started(&self, space: &Arc<SharedCapSpace>) -> Arc<Thread> {
        let t = self.thread(space);
        assert!(t.claim_start());
        on_start(space, &t).unwrap();
        t.set_state(RunState::Running);
        t
    }

    fn ntfy(&self) -> Arc<Notification> {
        Arc::new(Notification::new(&self.quota).unwrap())
    }
}

/// O que `thread_exit` faz no kernel: grava e chama `thread_died`.
fn exit(t: &Arc<Thread>, cause: u8, code: u64, env: &mut Fake) {
    if t.kill_requested() {
        t.record_death(CAUSE_KILLED, 0, 0);
    } else {
        t.record_death(cause, code, 0);
    }
    thread_died(t, env);
    t.set_state(RunState::Exited);
}

#[test]
fn morte_da_thread_e_do_processo_sinalizam_uma_vez() {
    let w = World::new();
    let space = w.space();
    let n = w.ntfy();
    let (a, b) = (w.started(&space), w.started(&space));
    assert!(a.bind_death(Some((Arc::clone(&n), 0b01))).0.is_none());
    bind(&space, Some((Arc::clone(&n), 0b10)), &mut Fake::default());
    assert_eq!(space.lock().process().live(), 2);
    let mut env = Fake::default();
    exit(&a, CAUSE_EXITED, 7, &mut env);
    assert_eq!(n.poll(), 0b01, "só a thread");
    assert_eq!(record(&space), Record::default(), "o processo vive");
    // Morrer de novo não sinaliza nem desconta.
    thread_died(&a, &mut env);
    assert_eq!((n.poll(), space.lock().process().live()), (0, 1));
    exit(&b, CAUSE_EXITED, 9, &mut env);
    assert_eq!(n.poll(), 0b10);
    // O registro do processo: a última saída normal.
    assert_eq!(record(&space), Record::exited(9));
    assert!(space.lock().process().dead());
    // Ligar depois da morte sinaliza já, e de novo a cada ligação.
    bind(&space, Some((Arc::clone(&n), 0b100)), &mut env);
    let (now, _) = a.bind_death(Some((Arc::clone(&n), 0b1000)));
    assert!(now.is_some_and(|(_, bits)| bits == 0b1000));
    assert_eq!(n.poll(), 0b100);
}

#[test]
fn a_primeira_morte_anormal_fica_no_processo() {
    let w = World::new();
    let space = w.space();
    let (a, b, c) = (w.started(&space), w.started(&space), w.started(&space));
    let mut env = Fake::default();
    exit(&a, CAUSE_EXITED, 1, &mut env);
    b.record_death(CAUSE_FAULTED, 14, 0xdead);
    thread_died(&b, &mut env);
    exit(&c, CAUSE_EXITED, 3, &mut env);
    assert_eq!(
        record(&space),
        Record {
            cause: CAUSE_FAULTED,
            code: 14,
            aux: 0xdead
        }
    );
}

#[test]
fn ligacao_troca_e_desliga() {
    let w = World::new();
    let space = w.space();
    let (n1, n2) = (w.ntfy(), w.ntfy());
    let t = w.started(&space);
    let mut env = Fake::default();
    let (_, old) = t.bind_death(Some((Arc::clone(&n1), 1)));
    assert!(old.is_none());
    let (_, old) = t.bind_death(Some((Arc::clone(&n2), 2)));
    assert!(old.is_some_and(|(n, b)| Arc::ptr_eq(&n, &n1) && b == 1));
    bind(&space, Some((Arc::clone(&n2), 4)), &mut env);
    bind(&space, None, &mut env);
    exit(&t, CAUSE_EXITED, 0, &mut env);
    assert_eq!((n1.poll(), n2.poll()), (0, 2), "desligado não sinaliza");
}

#[test]
fn limite_de_threads_e_partida_em_processo_encerrado() {
    let w = World::new();
    let space = w.space();
    space.lock().process_mut().set_limit(2);
    let (a, _b) = (w.started(&space), w.started(&space));
    let c = w.thread(&space);
    assert_eq!(on_start(&space, &c), Err(Error::QuotaExceeded));
    let mut env = Fake::default();
    exit(&a, CAUSE_EXITED, 0, &mut env);
    on_start(&space, &c).unwrap();
    undo_start(&space, &c, &mut env);
    assert_eq!(space.lock().process().live(), 1);
    destroy(&space, Record::killed(), None, &mut env);
    assert_eq!(on_start(&space, &c), Err(Error::PeerClosed));
}

#[test]
fn desfazer_a_ultima_partida_mata_o_processo_que_ja_rodou() {
    let w = World::new();
    let space = w.space();
    let n = w.ntfy();
    bind(&space, Some((Arc::clone(&n), 1)), &mut Fake::default());
    let mut env = Fake::default();
    // Nunca rodou: a partida desfeita não mata.
    let never = w.thread(&space);
    on_start(&space, &never).unwrap();
    undo_start(&space, &never, &mut env);
    assert!(!space.lock().process().dead());
    let ran = w.started(&space);
    let last = w.thread(&space);
    on_start(&space, &last).unwrap();
    exit(&ran, CAUSE_EXITED, 5, &mut env);
    assert_eq!(n.poll(), 0);
    undo_start(&space, &last, &mut env);
    assert_eq!((n.poll(), record(&space)), (1, Record::exited(5)));
}

#[test]
fn encerrar_sem_threads_mata_ja_e_esvazia_a_tabela() {
    let w = World::new();
    let space = w.space();
    let n = w.ntfy();
    let mut env = Fake::default();
    bind(&space, Some((Arc::clone(&n), 1)), &mut env);
    for _ in 0..40 {
        space
            .lock()
            .insert(crate::cap::Cap {
                object: crate::cap::Object::Notification(w.ntfy()),
                rights: kabi::Rights::ALL,
                badge: 0,
            })
            .unwrap();
    }
    destroy(&space, Record::killed(), None, &mut env);
    assert_eq!(n.poll(), 1);
    assert_eq!(record(&space), Record::killed());
    assert_eq!(space.lock().len(), 0);
    // Encerrar de novo não muda nada.
    destroy(&space, Record::exited(3), None, &mut env);
    assert_eq!((n.poll(), record(&space)), (0, Record::killed()));
}

#[test]
fn encerrar_marca_as_vivas_tira_as_que_esperam_e_mata_as_inativas() {
    let w = World::new();
    let space = w.space();
    let events = w.ntfy();
    let mut env = Fake::default();
    bind(&space, Some((Arc::clone(&events), 1 << 63)), &mut env);
    // Uma rodando, uma esperando numa notificação, uma nunca iniciada (fora
    // das vivas: não conta) e quem encerra (EXIT_GROUP).
    let running = w.started(&space);
    let waiting = w.started(&space);
    let idle = w.thread(&space);
    let me = w.started(&space);
    for (i, t) in [&running, &waiting, &idle, &me].into_iter().enumerate() {
        assert!(
            t.bind_death(Some((Arc::clone(&events), 1 << i)))
                .0
                .is_none()
        );
    }
    let wait_on = w.ntfy();
    waiting.set_state(RunState::Running);
    assert_eq!(wait_on.wait(&waiting), Ok(Wait::Blocked));
    destroy(&space, Record::exited(42), Some(&me), &mut env);
    assert!(running.kill_requested() && waiting.kill_requested());
    assert!(!me.kill_requested());
    assert_eq!(env.kicked, 2);
    // A que esperava saiu da fila e acordou; a que rodava só foi marcada.
    assert_eq!(wait_on.waiters(), 0);
    assert_eq!(env.woken.len(), 1);
    assert!(Arc::ptr_eq(&env.woken[0].0, &waiting));
    assert_eq!(events.poll(), 0, "ninguém morreu ainda");
    // A inativa, encerrada por DESTROY dela, morre já.
    kill(&idle, &mut env);
    assert_eq!(idle.death(), Some((CAUSE_KILLED, 0, 0)));
    assert_eq!(idle.state(), RunState::Exited);
    assert_eq!(events.poll(), 1 << 2);
    // Cada uma morre no caminho de saída; o processo, com a última.
    exit(&running, CAUSE_EXITED, 0, &mut env);
    exit(&waiting, CAUSE_EXITED, 0, &mut env);
    assert_eq!(running.death(), Some((CAUSE_KILLED, 0, 0)));
    assert_eq!(events.poll(), 0b11);
    exit(&me, CAUSE_EXITED, 42, &mut env);
    assert_eq!(events.poll(), (1 << 3) | (1 << 63));
    // EXIT_GROUP fixou a causa: Exited com o código, apesar das Killed.
    assert_eq!(record(&space), Record::exited(42));
    // Encerrar uma morta não faz nada.
    kill(&running, &mut env);
    assert_eq!(events.poll(), 0);
}

#[test]
fn cem_processos_criados_e_encerrados_sem_perder_evento() {
    let w = World::new();
    let n = w.ntfy();
    let mut env = Fake::default();
    let mut seen = 0u64;
    for round in 0..100u32 {
        let bit = 1u64 << (round % 64);
        let space = w.space();
        bind(&space, Some((Arc::clone(&n), bit)), &mut env);
        let threads: Vec<_> = (0..=round % 3).map(|_| w.started(&space)).collect();
        destroy(&space, Record::killed(), None, &mut env);
        // Antes da última thread morrer, nada.
        assert_eq!(n.pending() & bit, 0);
        for t in &threads {
            exit(t, CAUSE_EXITED, 0, &mut env);
        }
        assert_eq!(n.poll(), bit, "rodada {round}");
        assert_eq!(record(&space), Record::killed());
        seen += 1;
    }
    assert_eq!(seen, 100);
}
