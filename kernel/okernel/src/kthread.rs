//! Threads de usuário no kernel: partida, troca de contexto, fila de
//! prontas e entrada das syscalls (T-206; SDD v1.0, seções 6.1, 6.6 e 14).
//!
//! Cada thread tem pilha de kernel própria. A entrada no kernel (SYSCALL ou
//! interrupção vinda do anel 3) salva os registradores de usuário num quadro
//! no topo dessa pilha; trocar de thread é trocar de pilha de kernel
//! ([`switch_context`]), salvar e restaurar o estado de FPU (XSAVE) e, se
//! preciso, o CR3. O contexto de boot é a thread ociosa: roda quando
//! ninguém mais está pronto, sempre com o CR3 do kernel.
//!
//! O kernel não é preemptível (ADR 0009) e roda com interrupções desligadas;
//! elas só chegam no anel 3 ou no ocioso. Por isso a fila tem uma trava
//! simples, nunca segura durante a troca.
//!
//! Estado por CPU (ADR 0032, item 1; T-323): cada CPU tem a sua `Sched`
//! (atual, fila de prontas, sem orçamento, prazos de IPC, morta pendente e
//! registro), sob a trava `RunQueue` com a chave do id da CPU. A `Thread`
//! guarda a CPU dona (`Thread::cpu`): a fila e os prazos dela são os dessa
//! CPU.
//!
//! Toda CPU roda threads (T-324): o ocioso de cada AP pega as prontas da
//! própria fila. `Thread::on_cpu` marca a pilha de kernel em uso, da
//! escolha até a próxima terminar a troca ([`finish_switch`]), e nenhuma
//! outra CPU roda a thread enquanto isso (ADR 0032, I1 e I3). [`wake`]
//! ganha a thread com um `compare_exchange` de `Blocked` para `Ready`,
//! escolhe a CPU pelo resumo atômico de cada uma (prioridade da atual e
//! prontas) e manda o IPI de reescalonar quando o destino está ocioso ou
//! roda algo menos prioritário. A troca direta do IPC só acontece com a
//! outra thread já nesta CPU; entre CPUs, o despertar comum (a migração do
//! servidor que segue quem chama vem com o T-327).
//!
//! Escalonamento (T-207, seção 6.6): prioridade fixa de 256 níveis com
//! round-robin de [`DEFAULT_SLICE_NS`] dentro do nível; cada thread roda
//! sobre o orçamento do seu `SchedContext` e, sem orçamento, espera o fim
//! da janela fora da fila. Sem tick: a cada decisão o timer do APIC é
//! armado para o próximo evento (fim da fatia, fim do orçamento da atual ou
//! reabastecimento de uma thread em espera). O consumo é medido pelo
//! relógio nas decisões (syscalls de troca e interrupções do timer).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use alloc::boxed::Box;
use kabi::MAX_CPUS;

use kabi::vm::{USER_END, USER_START};
use kabi::{Error, Syscall};
use okernel::sched::{DEFAULT_SLICE_NS, Params, RunQueue, SchedContext};
use okernel::sync::{LockClass, SpinLock};
use okernel::sys::{self, Values};
use okernel::thread::{RunState, Thread};

use crate::arch::x86_64::gdt::{USER_CODE, USER_DATA};
use crate::arch::x86_64::idt::TrapFrame;
use crate::arch::x86_64::syscall::{self, switch_context, thread_trampoline};
use crate::arch::x86_64::{cpu, fpu, percpu, probe};
use crate::{kcap, kipc, kmem, ksmp, ktest, ktime};

pub mod tests;
pub use tests::TESTS;

/// Registradores iniciais de uma thread de usuário.
#[derive(Clone, Copy, Debug)]
pub struct UserEntry {
    /// Primeira instrução.
    pub rip: u64,
    /// Pilha de usuário.
    pub rsp: u64,
    /// `rdi`, `rsi` e `rdx`.
    pub args: [u64; 3],
}

/// Um evento do registro do escalonador (para os testes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A thread (pelo endereço do objeto) rodou em `[start, end)`.
    Ran {
        /// Endereço do objeto `Thread`.
        thread: usize,
        /// Início, no relógio.
        start: u64,
        /// Fim.
        end: u64,
    },
    /// A thread ficou sem orçamento em `at` e espera até `until`.
    Throttled {
        /// Endereço do objeto `Thread`.
        thread: usize,
        /// Quando.
        at: u64,
        /// Reabastecimento.
        until: u64,
    },
}

struct Sched {
    /// Id da CPU dona.
    id: u32,
    /// Thread na CPU; `None` é o ocioso (o contexto de boot).
    current: Option<Arc<Thread>>,
    /// Quando a atual foi cobrada pela última vez.
    charged_at: u64,
    /// O `SchedContext` em que a atual roda desde então (o dela ou o
    /// doado numa chamada, seção 6.6): o tempo vai para ele mesmo que a
    /// doação acabe antes da cobrança.
    charging: Option<Arc<SchedContext>>,
    /// Quando a atual começou a rodar e quando acaba a fatia dela.
    started_at: u64,
    slice_end: u64,
    ready: RunQueue<Arc<Thread>>,
    /// Sem orçamento, esperando o reabastecimento.
    throttled: Vec<Arc<Thread>>,
    /// Bloqueadas por IPC com prazo (T-208): prazo e thread.
    timeouts: Vec<(u64, Arc<Thread>)>,
    /// A que acabou de sair da CPU, ainda com `on_cpu` (a pilha dela está
    /// em uso até a troca terminar); a próxima a rodar a libera em
    /// [`finish_switch`] e solta a referência (a última, se ela terminou).
    switch_prev: Option<Arc<Thread>>,
    /// Registro de eventos dos testes (capacidade reservada antes; nunca
    /// aloca aqui).
    trace: Vec<Event>,
}

impl Sched {
    const fn new(id: u32) -> Self {
        Self {
            id,
            current: None,
            charged_at: 0,
            charging: None,
            started_at: 0,
            slice_end: 0,
            ready: RunQueue::new(),
            throttled: Vec::new(),
            timeouts: Vec::new(),
            switch_prev: None,
            trace: Vec::new(),
        }
    }
}

/// Escalonador do BSP (estático: existe antes do heap).
static BSP_SCHED: SpinLock<Sched> = SpinLock::with_key(LockClass::RunQueue, 0, Sched::new(0));
/// Escalonador de cada AP, criado por [`init_cpu`] antes de ele ligar.
static SCHEDS: [AtomicPtr<SpinLock<Sched>>; MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];

/// O escalonador da CPU `cpu` (`None` se ela não tem um).
fn sched_of(cpu: u32) -> Option<&'static SpinLock<Sched>> {
    if cpu == 0 {
        return Some(&BSP_SCHED);
    }
    let p = SCHEDS.get(cpu as usize)?.load(Ordering::Acquire);
    // SAFETY: só `init_cpu` grava, com escalonadores que nunca são soltos.
    unsafe { p.as_ref() }
}

/// O escalonador desta CPU.
fn this_sched() -> &'static SpinLock<Sched> {
    sched_of(percpu::cpu_id()).unwrap_or(&BSP_SCHED)
}

/// Endereço do escalonador da CPU `cpu` e quantas prontas ele tem (para
/// os testes).
pub fn sched_info(cpu: u32) -> Option<(usize, usize)> {
    let s = sched_of(cpu)?;
    let ready = s.lock().ready.len();
    Some((core::ptr::from_ref(s).addr(), ready))
}

/// Cria o escalonador da CPU `cpu` (na partida dela, antes de ligá-la);
/// a chave da trava é o id, para duas filas só se tomarem em ordem
/// crescente (ADR 0031, item 3).
pub fn init_cpu(cpu: u32) {
    if cpu == 0 || sched_of(cpu).is_some() {
        return;
    }
    let sched = Box::leak(Box::new(SpinLock::with_key(
        LockClass::RunQueue,
        cpu,
        Sched::new(cpu),
    )));
    if let Some(slot) = SCHEDS.get(cpu as usize) {
        slot.store(sched, Ordering::Release);
    }
}

/// Resumo de cada CPU, lido sem trava para escolher onde acordar (ADR
/// 0032, item 1): prioridade da atual mais um (zero no ocioso) e prontas
/// na fila. Gravado com a trava da fila; valor velho só piora a escolha.
static CUR_PRIO: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static NR_READY: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// Prioridade de `t` mais um, a escala de [`CUR_PRIO`] (zero sem
/// `SchedContext`).
fn rank(t: &Thread) -> u32 {
    sc_of(t).map_or(0, |(_, p)| u32::from(p.priority) + 1)
}

/// Atualiza o resumo da CPU de `s` (com a trava dela): as prontas e, com
/// `cur`, o [`rank`] da atual (quem chama já o tem, sem tomar de novo as
/// travas do `SchedContext`).
fn publish(s: &Sched, cur: Option<u32>) {
    let i = s.id as usize;
    let ready = u32::try_from(s.ready.len()).unwrap_or(u32::MAX);
    if let Some(r) = NR_READY.get(i) {
        r.store(ready, Ordering::Relaxed);
    }
    if let (Some(cur), Some(c)) = (cur, CUR_PRIO.get(i)) {
        c.store(cur, Ordering::Relaxed);
    }
}

/// A CPU `cpu` pode receber threads: ligada e com escalonador.
fn usable(cpu: usize) -> bool {
    cpu == 0
        || (ksmp::start::is_online(cpu) && u32::try_from(cpu).is_ok_and(|c| sched_of(c).is_some()))
}

/// Onde acordar `t` (ADR 0032, item 5; sem máscara de afinidade até o
/// T-325), com `p` o [`rank`] de `t`: a CPU dela, se ociosa ou rodando algo menos prioritário (cache
/// quente); senão uma ociosa sem prontas, procurada a partir dela; senão a
/// que roda a atual menos prioritária, se menos que `t`; senão a dela.
fn choose_cpu(t: &Thread, p: u32) -> u32 {
    let n = ksmp::count().clamp(1, MAX_CPUS);
    let cur = |c: usize| CUR_PRIO[c].load(Ordering::Relaxed);
    let home = t.cpu() as usize;
    let home = if home < n && usable(home) { home } else { 0 };
    let idle = |c: usize| cur(c) == 0 && NR_READY[c].load(Ordering::Relaxed) == 0;
    let chosen = if cur(home) < p {
        home
    } else if let Some(c) = (1..n)
        .map(|i| (home + i) % n)
        .find(|&c| usable(c) && idle(c))
    {
        c
    } else {
        (0..n)
            .filter(|&c| usable(c) && cur(c) < p)
            .min_by_key(|&c| cur(c))
            .unwrap_or(home)
    };
    u32::try_from(chosen).unwrap_or(0)
}

/// Trocas diretas do caminho rápido de IPC.
static FAST_SWITCHES: AtomicU64 = AtomicU64::new(0);
static DEBUG_LOG: SpinLock<([u8; 256], usize)> =
    SpinLock::with_class(LockClass::Diagnostic, ([0; 256], 0));

/// A thread na CPU (`None` no ocioso).
pub fn current() -> Option<Arc<Thread>> {
    this_sched().lock().current.clone()
}

fn user_addr(addr: u64) -> bool {
    (USER_START..USER_END).contains(&addr)
}

/// `thread_start`: monta o quadro de usuário na pilha de kernel e põe a
/// thread na fila de prontas.
///
/// # Errors
///
/// [`Error::Busy`] se já iniciada; [`Error::InvalidArgument`] sem
/// `thread_configure` ou com `rip`/`rsp` fora da metade de usuário;
/// [`Error::QuotaExceeded`] sem memória para a fila.
pub fn start(thread: &Arc<Thread>, entry: &UserEntry) -> Result<(), Error> {
    start_on(thread, entry, percpu::cpu_id())
}

/// Como [`start`], na fila da CPU `cpu` (os testes põem threads em CPUs
/// escolhidas; sem afinidade, uma thread fica onde começou até bloquear).
///
/// # Errors
///
/// Os de [`start`]; [`Error::InvalidArgument`] também se `cpu` não pode
/// receber threads.
pub fn start_on(thread: &Arc<Thread>, entry: &UserEntry, cpu: u32) -> Result<(), Error> {
    if thread.state() != RunState::Inactive {
        return Err(Error::Busy);
    }
    let configured = thread
        .sched_context()
        .is_some_and(|sc| sc.params().is_some());
    if thread.root().is_none() || !configured || !user_addr(entry.rip) || !user_addr(entry.rsp) {
        return Err(Error::InvalidArgument);
    }
    let [rdi, rsi, rdx] = entry.args;
    let frame = TrapFrame {
        rdi,
        rsi,
        rdx,
        rip: entry.rip,
        cs: u64::from(USER_CODE),
        rflags: syscall::user_rflags(0),
        rsp: entry.rsp,
        ss: u64::from(USER_DATA),
        ..TrapFrame::default()
    };
    let frame_at = thread.stack().top - size_of::<TrapFrame>() as u64;
    // Abaixo do quadro: rbp, rbx, r12-r15 zerados e o retorno de
    // `switch_context` para o trampolim.
    let switch_at = frame_at - 7 * 8;
    let target = sched_of(cpu)
        .filter(|_| usable(cpu as usize))
        .ok_or(Error::InvalidArgument)?;
    thread.set_cpu(cpu);
    let mut sched = target.lock();
    // Toda thread iniciada tem lugar reservado na espera: o escalonador
    // nunca aloca.
    sched
        .throttled
        .try_reserve(1)
        .map_err(|_| Error::QuotaExceeded)?;
    sched
        .timeouts
        .try_reserve(1)
        .map_err(|_| Error::QuotaExceeded)?;
    // SAFETY: a pilha de kernel da thread está mapeada (RW) e é só dela;
    // a thread nunca rodou, então nada mais a usa.
    unsafe {
        (frame_at as *mut TrapFrame).write(frame);
        let switch = switch_at as *mut u64;
        for i in 0..6 {
            switch.add(i).write(0);
        }
        switch
            .add(6)
            .write((thread_trampoline as *const ()).addr() as u64);
    }
    thread.saved_rsp().store(switch_at, Ordering::Release);
    enqueue(&mut sched, Arc::clone(thread), ktime::now_ns());
    publish(&sched, None);
    drop(sched);
    if cpu != percpu::cpu_id() {
        ksmp::ipi::resched(cpu as usize);
    }
    Ok(())
}

/// `SchedContext` e parâmetros de uma thread iniciada (`start` exige).
fn sc_of(t: &Thread) -> Option<(Arc<SchedContext>, Params)> {
    let sc = t.sched_context()?;
    let params = sc.params()?;
    Some((sc, params))
}

/// Põe `t` na fila do nível dela ou, sem orçamento, na espera (devolve
/// `false` nesse caso).
fn enqueue(s: &mut Sched, t: Arc<Thread>, now: u64) -> bool {
    let Some((sc, p)) = sc_of(&t) else {
        return false;
    };
    let mut b = sc.budget();
    b.refill(&p, now);
    sc.set_budget(b);
    if b.exhausted(&p) {
        if s.trace.len() < s.trace.capacity() {
            let thread = Arc::as_ptr(&t).addr();
            let until = b.replenish_at;
            s.trace.push(Event::Throttled {
                thread,
                at: now,
                until,
            });
        }
        t.set_state(RunState::Throttled);
        if s.throttled.try_reserve(1).is_ok() {
            s.throttled.push(t);
        }
        false
    } else {
        t.set_state(RunState::Ready);
        let _ = s.ready.push(p.priority, t);
        true
    }
}

/// Desconta do `SchedContext` da atual o tempo desde a última cobrança e
/// passa a cobrar o que ela usa agora.
fn charge_current(s: &mut Sched, now: u64) {
    if let Some(sc) = s.charging.take()
        && let Some(p) = sc.params()
    {
        let mut b = sc.budget();
        b.consume(&p, now.saturating_sub(s.charged_at));
        sc.set_budget(b);
    }
    s.charging = s.current.as_deref().and_then(Thread::sched_context);
    s.charged_at = now;
}

/// Devolve à fila as threads em espera cuja janela acabou.
fn release_throttled(s: &mut Sched, now: u64) {
    let mut i = 0;
    while i < s.throttled.len() {
        let due = sc_of(&s.throttled[i]).is_some_and(|(sc, _)| now >= sc.budget().replenish_at);
        if due {
            let t = s.throttled.swap_remove(i);
            enqueue(s, t, now);
        } else {
            i += 1;
        }
    }
}

/// Arma o timer para o próximo evento: fim da fatia ou do orçamento da
/// atual, ou o primeiro reabastecimento.
fn program_timer(s: &Sched, now: u64) {
    let mut at = u64::MAX;
    if let Some((sc, p)) = s.current.as_deref().and_then(sc_of) {
        at = at.min(s.slice_end);
        if let Some(d) = sc.budget().deadline(&p, now) {
            at = at.min(d);
        }
    }
    for t in &s.throttled {
        if let Some((sc, _)) = sc_of(t) {
            at = at.min(sc.budget().replenish_at);
        }
    }
    for &(deadline, _) in &s.timeouts {
        at = at.min(deadline);
    }
    if at != u64::MAX {
        ktime::arm_by(at);
    }
}

/// Por que o escalonador foi chamado.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Why {
    /// A atual cede a vez e volta para o fim do nível.
    Yield,
    /// A atual terminou.
    Exit,
    /// A atual bloqueou (notificação ou futex) e sai da CPU sem voltar à
    /// fila; quem a acordar a devolve.
    Block,
    /// Timer ou ponto de preempção: a atual segue, a menos que o orçamento
    /// ou a fatia tenha acabado ou haja alguém mais prioritário.
    Preempt,
}

/// A atual pode seguir na CPU (só para [`Why::Preempt`]).
fn keeps_running(s: &Sched, t: &Thread, now: u64) -> bool {
    let Some((sc, p)) = sc_of(t) else {
        return false;
    };
    let mut b = sc.budget();
    b.refill(&p, now);
    sc.set_budget(b);
    let top = s.ready.highest();
    let higher = top.is_some_and(|h| h > p.priority);
    let turn_over = now >= s.slice_end && top == Some(p.priority);
    !b.exhausted(&p) && !higher && !turn_over
}

/// Escolhe a próxima thread e troca para ela. Volta quando a que chamou
/// for escolhida de novo (nunca, se ela saiu).
fn schedule(why: Why) {
    schedule_to(why, None);
}

/// `direct` (bloqueada, já atendida por IPC) pode rodar já, sem passar
/// pela fila: tem orçamento e ninguém pronto tem prioridade maior.
fn runs_directly(s: &Sched, t: &Thread, now: u64) -> bool {
    let Some((sc, p)) = sc_of(t) else {
        return false;
    };
    let mut b = sc.budget();
    b.refill(&p, now);
    sc.set_budget(b);
    !b.exhausted(&p) && s.ready.highest().is_none_or(|h| h <= p.priority)
}

/// Tira `t` da lista de prazos, se estiver nela.
fn drop_timeout(s: &mut Sched, t: &Thread) {
    if let Some(i) = s
        .timeouts
        .iter()
        .position(|(_, w)| core::ptr::eq(Arc::as_ptr(w), t))
    {
        s.timeouts.swap_remove(i);
    }
}

/// Acorda com `TimedOut` as threads cujo prazo de IPC venceu.
fn expire_timeouts() {
    loop {
        let now = ktime::now_ns();
        let expired = {
            let mut s = this_sched().lock();
            let i = s.timeouts.iter().position(|(d, _)| *d <= now);
            i.map(|i| s.timeouts.swap_remove(i).1)
        };
        let Some(t) = expired else { return };
        // A fila do objeto vem antes da do escalonador (seção 6.9): o
        // cancelamento roda sem a trava dela.
        if okernel::ipc::cancel(&t, Error::TimedOut) {
            wake(t, 0);
        }
    }
}

/// A próxima a rodar: `direct`, se puder rodar já, ou a primeira da fila.
fn pick_next(s: &mut Sched, direct: Option<Arc<Thread>>, now: u64) -> Option<Arc<Thread>> {
    if let Some(t) = direct {
        drop_timeout(s, &t);
        if runs_directly(s, &t, now) {
            FAST_SWITCHES.fetch_add(1, Ordering::Relaxed);
            return Some(t);
        }
        enqueue(s, t, now);
    }
    s.ready.pop().map(|(_, t)| t)
}

/// `n` passa a ser a atual desta CPU (`me`): estado, CPU dona, `on_cpu`
/// se acabou de chegar (`arriving`) e início da janela de orçamento.
/// Devolve o [`rank`] dela.
fn run_here(n: &Thread, me: u32, arriving: bool, now: u64) -> u32 {
    n.set_state(RunState::Running);
    n.set_cpu(me);
    if arriving {
        // I3: só a anterior desta CPU (que não chega, segue) poderia estar
        // com a pilha em uso; toda outra saiu de vez.
        debug_assert!(!n.on_cpu(), "thread na fila ainda em outra CPU");
        n.set_on_cpu(true);
    }
    let Some((sc, p)) = sc_of(n) else {
        return 0;
    };
    let mut b = sc.budget();
    b.activate(&p, now);
    sc.set_budget(b);
    u32::from(p.priority) + 1
}

/// Como [`schedule`], mas com `direct` como próxima (caminho rápido de
/// IPC) se ela puder rodar já; senão, ela vai para a fila.
fn schedule_to(why: Why, direct: Option<Arc<Thread>>) {
    expire_timeouts();
    let now = ktime::now_ns();
    let me = percpu::cpu_id();
    let mut s = this_sched().lock();
    charge_current(&mut s, now);
    release_throttled(&mut s, now);
    if why == Why::Preempt
        && let Some(cur) = s.current.clone()
        && keeps_running(&s, &cur, now)
    {
        publish(&s, None);
        program_timer(&s, now);
        return;
    }
    let prev = s.current.take();
    if let Some(p) = &prev {
        match why {
            Why::Exit => p.set_state(RunState::Exited),
            Why::Block => {}
            Why::Yield | Why::Preempt => {
                enqueue(&mut s, Arc::clone(p), now);
            }
        }
    }
    let next = pick_next(&mut s, direct, now);
    let same = match (&prev, &next) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    };
    let cur_rank = next.as_deref().map_or(0, |n| run_here(n, me, !same, now));
    if !same {
        if let Some(p) = &prev
            && s.trace.len() < s.trace.capacity()
        {
            let thread = Arc::as_ptr(p).addr();
            let start = s.started_at;
            s.trace.push(Event::Ran {
                thread,
                start,
                end: now,
            });
        }
        s.started_at = now;
    }
    if !same || why == Why::Yield {
        s.slice_end = now.saturating_add(DEFAULT_SLICE_NS);
    }
    s.current.clone_from(&next);
    s.charging = next.as_deref().and_then(Thread::sched_context);
    publish(&s, Some(cur_rank));
    program_timer(&s, now);
    if same {
        return;
    }
    let idle_slot = percpu::with(|p| p.idle_rsp().as_ptr());
    let prev_slot = prev.as_ref().map_or(idle_slot, |p| p.saved_rsp().as_ptr());
    let prev_fpu = prev
        .as_ref()
        .filter(|p| p.state() != RunState::Exited)
        .map(|p| p.fpu_area());
    // A pilha da que saiu segue em uso até a troca: `switch_prev` a mantém
    // viva (e com `on_cpu`) enquanto o asm grava em `prev_slot`, até a
    // próxima a liberar em `finish_switch`.
    debug_assert!(s.switch_prev.is_none(), "troca anterior não terminada");
    s.switch_prev = prev;
    drop(s);
    // SAFETY: as áreas são das threads (alinhadas a 64, do tamanho que
    // `fpu::area_bytes` pede), só a troca de contexto as acessa, e a pilha
    // de `next` está mapeada.
    unsafe {
        if let Some(area) = prev_fpu {
            fpu::save(core::ptr::with_exposed_provenance_mut(area));
        }
        if let Some(t) = &next {
            fpu::restore(core::ptr::with_exposed_provenance(t.fpu_area()));
            syscall::set_kernel_stack(t.stack().top);
        }
    }
    let (next_rsp, root) = next.as_ref().map_or((idle_rsp(), None), |t| {
        (t.saved_rsp().load(Ordering::Acquire), t.root())
    });
    let root = root.or_else(|| kmem::kernel_root().map(|r| r.0));
    // Para o dump do pânico (ADR 0031, item 8): quem roda nesta CPU.
    let thread = next.as_ref().map_or(0, |t| Arc::as_ptr(t).addr() as u64);
    percpu::with(|p| p.thread().store(thread, Ordering::Relaxed));
    if let Some(root) = root
        && cpu::read_cr3() & 0x000f_ffff_ffff_f000 != root
    {
        // SAFETY: o espaço da thread que vai rodar (vivo enquanto ela
        // estiver em `current`) ou o do kernel; ambos mapeiam o kernel.
        unsafe { cpu::write_cr3(root) };
    }
    drop(next);
    // SAFETY: `prev_slot` é o rsp salvo da anterior, viva (em
    // `switch_prev`) ou o ocioso; `next_rsp` foi salvo por esta mesma função ou
    // montado por `start`.
    crate::ksync::assert_none_held("switch_context");
    percpu::assert_no_borrows();
    unsafe { switch_context(prev_slot, next_rsp) };
    finish_switch();
}

/// rsp salvo do ocioso desta CPU.
fn idle_rsp() -> u64 {
    percpu::with(|p| p.idle_rsp().load(Ordering::Acquire))
}

/// Já na próxima: libera a pilha da anterior (`on_cpu` falso, ADR 0032,
/// item 3, passo 8), que outra CPU pode passar a rodar, e solta a
/// referência a ela (a última, se ela terminou).
fn finish_switch() {
    let prev = this_sched().lock().switch_prev.take();
    if let Some(p) = prev {
        p.set_on_cpu(false);
        drop(p);
    }
}

/// Primeira execução de uma thread, chamada por `thread_trampoline`.
#[unsafe(no_mangle)]
extern "sysv64" fn thread_first_run() {
    finish_switch();
}

/// Cede a CPU para a próxima pronta (do ocioso: roda as prontas).
pub fn yield_now() {
    schedule(Why::Yield);
}

/// Acorda uma thread bloqueada com `value` como resultado da espera e a
/// põe na fila; não troca de thread (quem chama decide se preempta).
///
/// Pode ser chamada de qualquer CPU, com trava de objeto na mão, e nunca
/// espera (ADR 0032, item 5): só quem passa a thread de `Blocked` a
/// `Ready` a enfileira. Ainda saindo da CPU dela (`on_cpu`), volta à fila
/// dessa CPU, a única que pode pegá-la; senão, vai para a CPU de
/// [`choose_cpu`]. Destino em outra CPU ociosa ou rodando algo menos
/// prioritário recebe o IPI de reescalonar.
pub fn wake(thread: Arc<Thread>, value: u64) {
    if !thread.claim_wake() {
        return;
    }
    thread.set_wake_value(value);
    let home = thread.cpu();
    let p = rank(&thread);
    let dest = if thread.on_cpu() {
        home
    } else {
        choose_cpu(&thread, p)
    };
    // O prazo dela está na lista da CPU dona (I7): sai de lá antes de ela
    // mudar de CPU, sem as duas filas na mão ao mesmo tempo.
    if dest != home
        && let Some(old) = sched_of(home)
    {
        drop_timeout(&mut old.lock(), &thread);
    }
    let sched = sched_of(dest).unwrap_or(&BSP_SCHED);
    let mut s = sched.lock();
    drop_timeout(&mut s, &thread);
    let id = s.id;
    thread.set_cpu(id);
    let ready = enqueue(&mut s, thread, ktime::now_ns());
    publish(&s, None);
    // O resumo da atual do destino é exato com a trava dele na mão. Sem
    // orçamento, o destino precisa rearmar o timer para o reabastecimento:
    // também é motivo de aviso.
    let kick =
        id != percpu::cpu_id() && (CUR_PRIO[id as usize].load(Ordering::Relaxed) < p || !ready);
    drop(s);
    if kick {
        ksmp::ipi::resched(id as usize);
    }
}

/// Bloqueia a atual (já marcada) até alguém a acordar ou, com `deadline`
/// não zero, até o prazo vencer (o IPC a acorda com `TimedOut`).
pub fn block_until(deadline: u64) {
    push_timeout(deadline);
    schedule(Why::Block);
}

/// Põe o prazo da atual na lista desta CPU, se ela ainda está bloqueada:
/// quem a acordou antes (de outra CPU, com a trava desta fila) já tirou o
/// prazo que haveria, e um prazo velho na lista seria vencido à toa.
fn push_timeout(deadline: u64) {
    if deadline == 0 {
        return;
    }
    let mut s = this_sched().lock();
    if let Some(t) = s.current.clone()
        && t.state() == RunState::Blocked
        && s.timeouts.try_reserve(1).is_ok()
    {
        s.timeouts.push((deadline, t));
    }
}

/// Caminho rápido de IPC: a atual (já bloqueada, com prazo `deadline`)
/// cede a CPU direto a `to` se `to` puder rodar já; senão, `to` vai para a
/// fila e o escalonador escolhe.
///
/// Só com `to` nesta CPU (ADR 0032, item 6: o caminho rápido é o da mesma
/// CPU) e ganha pelo `compare_exchange` do despertar; senão `to` acorda
/// pelo caminho comum ([`wake`]), que escolhe a CPU e avisa.
pub fn handoff(to: Arc<Thread>, deadline: u64) {
    push_timeout(deadline);
    if to.cpu() != percpu::cpu_id() {
        wake(to, 0);
        schedule(Why::Block);
    } else if to.claim_wake() {
        schedule_to(Why::Block, Some(to));
    } else {
        // Alguém já a acordou (e a pôs numa fila).
        schedule(Why::Block);
    }
}

/// Trocas diretas do caminho rápido de IPC desde o boot.
pub fn fast_switches() -> u64 {
    FAST_SWITCHES.load(Ordering::Relaxed)
}

/// Ponto de preempção: a atual segue, a menos que haja alguém mais
/// prioritário ou a fatia dela tenha acabado.
pub fn preempt() {
    schedule(Why::Preempt);
}

/// O que o despacho portável pede ao kernel (`okernel::sys::Env`).
pub struct KernelEnv;

impl sys::Env for KernelEnv {
    fn preempt(&mut self) {
        preempt();
    }

    fn wake(&mut self, thread: Arc<Thread>, value: u64) {
        wake(thread, value);
    }

    fn current(&self) -> Option<Arc<Thread>> {
        current()
    }

    fn block(&mut self) {
        schedule(Why::Block);
    }

    fn read_u32(&mut self, addr: u64) -> Option<u32> {
        let mut word = [0u8; 4];
        probe::copy_from_user(&mut word, addr).then_some(u32::from_le_bytes(word))
    }

    fn now(&self) -> u64 {
        ktime::now_ns()
    }

    fn block_until(&mut self, deadline: u64) {
        block_until(deadline);
    }

    fn handoff(&mut self, to: Arc<Thread>, deadline: u64) {
        handoff(to, deadline);
    }

    fn read_buffer(&mut self, thread: &Thread, at: usize, out: &mut [u64]) -> bool {
        kipc::read_buffer(thread, at, out)
    }

    fn write_buffer(&mut self, thread: &Thread, at: usize, data: &[u64]) -> bool {
        kipc::write_buffer(thread, at, data)
    }
}

/// Disparo do timer do APIC (com o EOI já feito), vindo do anel 3 ou do
/// ocioso: reavalia quem roda.
pub fn on_timer() {
    ktime::timer_fired();
    preempt();
}

/// Liga o registro de eventos do escalonador com espaço para `capacity`
/// eventos (testes); `false` sem memória.
pub fn trace_start(capacity: usize) -> bool {
    let mut s = this_sched().lock();
    s.trace = Vec::new();
    s.trace.try_reserve_exact(capacity).is_ok()
}

/// Desliga o registro e devolve os eventos.
pub fn trace_take() -> Vec<Event> {
    core::mem::take(&mut this_sched().lock().trace)
}

/// `thread_exit`: a thread atual termina. Quem chama solta antes as
/// referências que tiver na pilha: esta função nunca volta.
pub fn exit_current() -> ! {
    schedule(Why::Exit);
    unreachable!("thread terminada voltou a rodar");
}

/// Chamado por `syscall_entry` com o quadro do usuário. Devolve 1 se a
/// volta pode usar SYSRET.
#[unsafe(no_mangle)]
extern "sysv64" fn syscall_handler(frame: &mut TrapFrame) -> u64 {
    if let Ok(
        call @ (Syscall::IpcSend | Syscall::IpcRecv | Syscall::IpcCall | Syscall::IpcReplyRecv),
    ) = Syscall::try_from(frame.rax)
    {
        kipc::syscall(frame, call);
        frame.rflags = syscall::user_rflags(frame.rflags);
        crate::ksync::assert_none_held("volta ao usuário");
        return u64::from(syscall::sysret_ok(frame.rip, frame.cs, frame.ss));
    }
    let args = [
        frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9,
    ];
    match dispatch(frame.rax, args) {
        Ok([a, b, c]) => {
            frame.rax = kabi::STATUS_OK;
            frame.rdx = a;
            frame.r10 = b;
            frame.r8 = c;
        }
        Err(e) => frame.rax = e.to_raw(),
    }
    frame.rflags = syscall::user_rflags(frame.rflags);
    crate::ksync::assert_none_held("volta ao usuário");
    u64::from(syscall::sysret_ok(frame.rip, frame.cs, frame.ss))
}

fn dispatch(nr: u64, a: [u64; 6]) -> Result<Values, Error> {
    if nr == kabi::DEBUG_PRINT {
        return debug_print(a[0], a[1]);
    }
    let call = Syscall::try_from(nr).map_err(|_| Error::NotSupported)?;
    match call {
        Syscall::Yield => {
            yield_now();
            Ok([0; 3])
        }
        Syscall::ThreadExit => exit_current(),
        Syscall::ClockGet => Ok([ktime::now_ns(), 0, 0]),
        Syscall::ThreadStart => thread_start(a).map(|()| [0; 3]),
        _ => {
            let space = current()
                .and_then(|t| t.cspace())
                .ok_or(Error::NotSupported)?;
            sys::invoke(&space, call, a, kcap::REVOKE_SLICE_BUDGET, &mut KernelEnv)
        }
    }
}

/// `thread_start(thread, rip, rsp, a0, a1, a2)` (ADR 0029): exige `START`
/// na thread.
fn thread_start(a: [u64; 6]) -> Result<(), Error> {
    let space = current()
        .and_then(|t| t.cspace())
        .ok_or(Error::NotSupported)?;
    let h = kabi::Handle::try_from(a[0]).map_err(|_| Error::InvalidHandle)?;
    let cap = space.lock().get(h)?.clone();
    let thread = cap.object.as_thread()?;
    if !cap.rights.contains(kabi::Rights::START) {
        return Err(Error::AccessDenied);
    }
    let entry = UserEntry {
        rip: a[1],
        rsp: a[2],
        args: [a[3], a[4], a[5]],
    };
    start(thread, &entry)
}

/// `kabi::DEBUG_PRINT` (provisória): nos testes de kernel o texto vai ao
/// registro que eles leem; fora deles, ao registro do kernel, uma linha por
/// chamada. Qualquer thread pode chamá-la até `debug_write` ganhar a
/// capability de depuração.
fn debug_print(ptr: u64, len: u64) -> Result<Values, Error> {
    let mut buf = [0u8; kabi::DEBUG_PRINT_MAX];
    let len = usize::try_from(len)
        .ok()
        .filter(|&n| n <= buf.len())
        .ok_or(Error::InvalidArgument)?;
    if !probe::copy_from_user(&mut buf[..len], ptr) {
        return Err(Error::InvalidArgument);
    }
    if !ktest::active() {
        let text = core::str::from_utf8(&buf[..len]).map_err(|_| Error::InvalidArgument)?;
        info!("{}", text.trim_end());
        return Ok([len as u64, 0, 0]);
    }
    let mut log = DEBUG_LOG.lock();
    let (bytes, used) = &mut *log;
    let n = len.min(bytes.len() - *used);
    bytes[*used..*used + n].copy_from_slice(&buf[..n]);
    *used += n;
    Ok([len as u64, 0, 0])
}

/// Esvazia o registro de `debug_print` e devolve o que ele tinha.
pub fn take_debug_log() -> ([u8; 256], usize) {
    core::mem::replace(&mut *DEBUG_LOG.lock(), ([0; 256], 0))
}
