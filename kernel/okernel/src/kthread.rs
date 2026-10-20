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
//! outra thread nesta CPU: na chamada, o servidor que esperava noutra CPU
//! segue quem chama e vem para cá ([`follow`], T-327); na resposta, quem
//! chamou e está noutra CPU acorda pelo despertar comum.
//!
//! Afinidade e balanceamento (ADR 0032, itens 4 e 7; T-325): uma thread só
//! começa a rodar numa CPU da máscara do `SchedContext` em que roda (o
//! doado, se houver). O despertar escolhe entre as CPUs da máscara; a
//! decisão que acha a atual ou uma pronta fora dela a põe em `outbox`, de
//! onde ela vai para uma CPU permitida depois da troca. O ocioso rouba uma
//! pronta da CPU de maior carga ([`idle_steal`]) e, no timer, a CPU puxa
//! uma da que tem duas a mais que ela, no máximo a cada [`BALANCE_NS`].
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
use kabi::sched::CpuMask;

use kabi::vm::{USER_END, USER_START};
use kabi::{Error, Syscall};
use okernel::sched::{Budget, DEFAULT_SLICE_NS, Params, RunQueue, SchedContext};
use okernel::sync::{LockClass, SpinGuard, SpinLock};
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
    /// Prontas que esta CPU não pode rodar (a máscara do `SchedContext`
    /// delas mudou ou elas o receberam por doação): saem da fila e vão
    /// para uma CPU permitida em [`drain_outbox`], sem esta trava na mão e
    /// depois da troca (ADR 0032, item 3, passos 4, 5 e 8).
    outbox: Vec<Arc<Thread>>,
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
            outbox: Vec::new(),
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
    with_sc(t, |_, p| u32::from(p.priority) + 1).unwrap_or(0)
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

/// CPUs em que `t` pode começar a rodar: a máscara do `SchedContext` em
/// que ela roda (o doado, se houver; todas, sem nenhum).
fn mask_of(t: &Thread) -> CpuMask {
    t.with_sched_context(|sc| sc.mask()).unwrap_or(CpuMask::ALL)
}

/// `t` pode começar a rodar na CPU `cpu` (ADR 0032, I4).
fn allowed(t: &Thread, cpu: u32) -> bool {
    t.with_sched_context(|sc| sc.allows(cpu as usize))
        .unwrap_or(true)
}

/// Onde acordar `t` (ADR 0032, item 5), com `p` o [`rank`] de `t` e só
/// entre as CPUs da máscara dela: a CPU dela, se ociosa ou rodando algo
/// menos prioritário (cache quente); senão uma ociosa sem prontas,
/// procurada a partir dela; senão a que roda a atual menos prioritária, se
/// menos que `t`; senão a dela, ou a primeira permitida depois dela.
fn choose_cpu(t: &Thread, p: u32) -> u32 {
    let n = ksmp::count().clamp(1, MAX_CPUS);
    let mask = mask_of(t);
    let ok = |c: usize| usable(c) && mask.contains(c);
    let cur = |c: usize| CUR_PRIO[c].load(Ordering::Relaxed);
    let idle = |c: usize| cur(c) == 0 && NR_READY[c].load(Ordering::Relaxed) == 0;
    let from = t.cpu() as usize % n;
    let home = Some(from).filter(|&h| ok(h));
    let around = || (0..n).map(|i| (from + i) % n);
    let chosen = if let Some(h) = home.filter(|&h| cur(h) < p) {
        h
    } else if let Some(c) = around().find(|&c| ok(c) && idle(c)) {
        c
    } else if let Some(c) = (0..n)
        .filter(|&c| ok(c) && cur(c) < p)
        .min_by_key(|&c| cur(c))
    {
        c
    } else {
        // Máscara sem CPU usável (só antes de as CPUs dela ligarem): a 0.
        home.or_else(|| around().find(|&c| ok(c))).unwrap_or(0)
    };
    u32::try_from(chosen).unwrap_or(0)
}

/// Põe `thread` (pronta, fora de toda fila, sem `on_cpu`) na fila da CPU
/// `dest`, com a trava só dela, e avisa o destino se ele está ocioso ou
/// roda algo menos prioritário que `p` (o [`rank`] de `thread`).
fn push_to(dest: u32, thread: Arc<Thread>, p: u32) {
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

/// Manda para outra CPU, pela escolha de [`choose_cpu`], as prontas que
/// esta não pode rodar (`Sched::outbox`). Sem trava na mão; a anterior
/// já saiu da CPU (`on_cpu` falso).
fn drain_outbox() {
    loop {
        let t = this_sched().lock().outbox.pop();
        let Some(t) = t else { return };
        let p = rank(&t);
        push_to(choose_cpu(&t, p), t, p);
    }
}

/// Tira `t` (pronta) da CPU: vai para `outbox`. Sem memória para isso,
/// devolve `t` para quem chama rodá-la aqui mesmo (só nesse caso uma CPU
/// fora da máscara começa a rodar uma thread).
fn to_outbox(s: &mut Sched, t: Arc<Thread>) -> Option<Arc<Thread>> {
    if s.outbox.try_reserve(1).is_err() {
        AFFINITY_MISSES.fetch_add(1, Ordering::Relaxed);
        return Some(t);
    }
    t.set_state(RunState::Ready);
    s.outbox.push(t);
    None
}

/// Intervalo mínimo entre dois balanços periódicos de uma CPU (ADR 0032,
/// item 7).
const BALANCE_NS: u64 = 10_000_000;
/// Último balanço periódico de cada CPU.
static LAST_BALANCE: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Threads puxadas de outra CPU pelo balanceamento desde o boot.
static PULLS: AtomicU64 = AtomicU64::new(0);

/// Threads puxadas de outra CPU (roubo do ocioso e balanço periódico)
/// desde o boot.
pub fn pulls() -> u64 {
    PULLS.load(Ordering::Relaxed)
}

/// Puxa da fila da CPU `victim` para a desta a pronta mais prioritária que
/// pode rodar aqui e não tem `on_cpu` (ADR 0032, I3 e I4); com `local`, só
/// uma de prioridade não menor que a da melhor pronta daqui. Toma as duas
/// filas em ordem de id (ADR 0031, item 3). `true` se trouxe alguém.
fn pull_from(victim: u32, local: bool) -> bool {
    let me = percpu::cpu_id();
    let Some(theirs) = sched_of(victim).filter(|_| victim != me) else {
        return false;
    };
    let mine = this_sched();
    let (mut v, mut m) = if victim < me {
        let v = theirs.lock();
        (v, mine.lock())
    } else {
        let m = mine.lock();
        (theirs.lock(), m)
    };
    let min = if local {
        m.ready.highest().unwrap_or(0)
    } else {
        0
    };
    let Some((_, t)) = v
        .ready
        .take_where(min, |_, t| !t.on_cpu() && allowed(t, me))
    else {
        return false;
    };
    publish(&v, None);
    drop(v);
    t.set_cpu(me);
    enqueue(&mut m, t, ktime::now_ns());
    publish(&m, None);
    PULLS.fetch_add(1, Ordering::Relaxed);
    true
}

/// Carga da CPU `c` pelo resumo atômico: as prontas e a atual. Uma CPU
/// ociosa com uma pronta tem carga 1: já foi avisada e vai rodá-la.
fn load(c: usize) -> u32 {
    NR_READY[c]
        .load(Ordering::Relaxed)
        .saturating_add(u32::from(CUR_PRIO[c].load(Ordering::Relaxed) != 0))
}

/// A CPU, fora esta, de maior [`load`], se for pelo menos `at_least`.
fn busiest(at_least: u32) -> Option<u32> {
    let me = percpu::cpu_id() as usize;
    let n = ksmp::count().clamp(1, MAX_CPUS);
    (0..n)
        .filter(|&c| c != me && usable(c))
        .max_by_key(|&c| load(c))
        .filter(|&c| load(c) >= at_least)
        .and_then(|c| u32::try_from(c).ok())
}

/// Roubo do ocioso (ADR 0032, item 7): sem prontas aqui, puxa uma da CPU
/// de maior carga que tenha alguma pronta além da que roda (carga 2 ou
/// mais). `true` se trouxe alguém: quem chama cede a vez de novo antes de
/// dormir.
pub fn idle_steal() -> bool {
    let me = percpu::cpu_id() as usize;
    if NR_READY[me].load(Ordering::Relaxed) != 0 {
        return false;
    }
    busiest(2).is_some_and(|c| pull_from(c, false))
}

/// Balanço periódico, de carona no timer (ADR 0032, item 7): a cada
/// [`BALANCE_NS`] no máximo, puxa uma thread da CPU de maior carga se ela
/// tem pelo menos duas a mais que esta.
fn periodic_balance(now: u64) {
    let me = percpu::cpu_id() as usize;
    let last = &LAST_BALANCE[me];
    if now.saturating_sub(last.load(Ordering::Relaxed)) < BALANCE_NS {
        return;
    }
    last.store(now, Ordering::Relaxed);
    if let Some(c) = busiest(load(me).saturating_add(2)) {
        pull_from(c, true);
    }
}

/// `sc` passa a permitir só `mask`, como `sched_configure` com `r8` (para
/// os testes): as CPUs fora dela reavaliam quem roda.
pub fn set_affinity(sc: &SchedContext, mask: CpuMask) {
    sc.set_mask(mask);
    sys::Env::affinity_changed(&mut KernelEnv, mask);
}

/// CPUs ligadas.
fn online_mask() -> CpuMask {
    (0..ksmp::count().min(MAX_CPUS))
        .filter(|&c| usable(c))
        .fold(CpuMask::NONE, CpuMask::with)
}

/// Vezes em que uma CPU rodou uma thread fora da máscara por falta de
/// memória para `outbox` ([`to_outbox`]).
static AFFINITY_MISSES: AtomicU64 = AtomicU64::new(0);

/// Threads rodadas fora da máscara desde o boot (zero, salvo sem memória).
pub fn affinity_misses() -> u64 {
    AFFINITY_MISSES.load(Ordering::Relaxed)
}

/// Trocas diretas do caminho rápido de IPC, por CPU: só a própria CPU
/// grava a dela, sem RMW atômico (T-331).
static FAST_SWITCHES: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// Servidores trazidos de outra CPU por quem os chamou ([`follow`]).
static FOLLOWS: AtomicU64 = AtomicU64::new(0);
static DEBUG_LOG: SpinLock<([u8; 256], usize)> =
    SpinLock::with_class(LockClass::Diagnostic, ([0; 256], 0));

/// A thread na CPU (`None` no ocioso).
///
/// Lida da área por CPU, sem a trava da fila (T-331): `schedule_to` grava
/// lá a próxima antes de trocar para ela, e só esta CPU lê e grava.
pub fn current() -> Option<Arc<Thread>> {
    let addr = percpu::with(|p| p.thread().load(Ordering::Relaxed));
    let thread = core::ptr::with_exposed_provenance::<Thread>(usize::try_from(addr).ok()?);
    if thread.is_null() {
        return None;
    }
    // SAFETY: `addr` veio de `Arc::as_ptr` da thread que roda nesta CPU, e
    // `Sched::current` desta CPU guarda uma referência a ela enquanto ela
    // roda aqui; quem chama roda nesta CPU, com interrupções desligadas,
    // então ela não sai da CPU até a referência nova existir.
    unsafe {
        Arc::increment_strong_count(thread);
        Some(Arc::from_raw(thread))
    }
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
    let me = percpu::cpu_id();
    let cpu = if allowed(thread, me) {
        me
    } else {
        choose_cpu(thread, rank(thread))
    };
    start_on(thread, entry, cpu)
}

/// Como [`start`], na fila da CPU `cpu` (os testes põem threads em CPUs
/// escolhidas; o balanceamento pode levá-las para outra da máscara).
///
/// # Errors
///
/// Os de [`start`]; [`Error::InvalidArgument`] também se `cpu` não pode
/// receber threads ou está fora da máscara do `SchedContext`.
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
        .filter(|_| usable(cpu as usize) && allowed(thread, cpu))
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

/// `f` sobre o `SchedContext` em que `t` roda e os parâmetros dele (os
/// de uma thread iniciada; `start` os exige), sem tomar referência: roda
/// com a trava folha da thread na mão (T-331).
fn with_sc<R>(t: &Thread, f: impl FnOnce(&SchedContext, Params) -> R) -> Option<R> {
    t.with_sched_context(|sc| sc.params().map(|p| f(sc, p)))
        .flatten()
}

/// Reabastece o orçamento de `sc` em `now` e o devolve.
fn refill(sc: &SchedContext, p: &Params, now: u64) -> Budget {
    let mut b = sc.budget();
    b.refill(p, now);
    sc.set_budget(b);
    b
}

/// Põe `t` na fila do nível dela ou, sem orçamento, na espera (devolve
/// `false` nesse caso).
fn enqueue(s: &mut Sched, t: Arc<Thread>, now: u64) -> bool {
    let Some((b, exhausted, priority)) = with_sc(&t, |sc, p| {
        let b = refill(sc, &p, now);
        (b, b.exhausted(&p), p.priority)
    }) else {
        return false;
    };
    if exhausted {
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
        let _ = s.ready.push(priority, t);
        true
    }
}

/// Desconta do `SchedContext` cobrado o tempo desde a última cobrança;
/// quem chama passa a cobrar o da atual (ou da próxima) com [`charge_to`]
/// ou pelo que [`run_here`] leu.
fn charge_current(s: &mut Sched, now: u64) {
    if let Some(sc) = &s.charging
        && let Some(p) = sc.params()
    {
        let mut b = sc.budget();
        b.consume(&p, now.saturating_sub(s.charged_at));
        sc.set_budget(b);
    }
    s.charged_at = now;
}

/// Passa a cobrar em `charging` o `SchedContext` em que `t` roda agora.
/// Sem trocar a referência se é o mesmo: no ping-pong de IPC com doação,
/// os dois lados rodam no de quem chama (T-331).
fn charge_to(charging: &mut Option<Arc<SchedContext>>, t: Option<&Thread>) {
    let same = match (t, &*charging) {
        (Some(t), Some(c)) => t.with_sched_context(|sc| Arc::ptr_eq(sc, c)) == Some(true),
        (None, None) => true,
        _ => false,
    };
    if !same {
        *charging = t.and_then(Thread::sched_context);
    }
}

/// Devolve à fila as threads em espera cuja janela acabou.
fn release_throttled(s: &mut Sched, now: u64) {
    let mut i = 0;
    while i < s.throttled.len() {
        let due = with_sc(&s.throttled[i], |sc, _| now >= sc.budget().replenish_at) == Some(true);
        if due {
            let t = s.throttled.swap_remove(i);
            enqueue(s, t, now);
        } else {
            i += 1;
        }
    }
}

/// O que limita a vez da atual, para [`program_timer`].
#[derive(Clone, Copy)]
enum Until {
    /// Nada: sem atual com `SchedContext`.
    Nothing,
    /// O fim da fatia (orçamento sem limite).
    Slice,
    /// O fim da fatia ou o do orçamento, no instante dado.
    Budget(u64),
}

impl Until {
    fn of(b: &Budget, p: &Params, now: u64) -> Self {
        b.deadline(p, now).map_or(Self::Slice, Self::Budget)
    }
}

/// Arma o timer para o próximo evento: fim da fatia ou do orçamento da
/// atual (`cur`, como quem chama já o leu), ou o primeiro
/// reabastecimento.
fn program_timer(s: &Sched, cur: Until) {
    let mut at = match cur {
        Until::Nothing => u64::MAX,
        Until::Slice => s.slice_end,
        Until::Budget(d) => s.slice_end.min(d),
    };
    for t in &s.throttled {
        if let Some(r) = with_sc(t, |sc, _| sc.budget().replenish_at) {
            at = at.min(r);
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

/// A atual pode seguir na CPU `me` (só para [`Why::Preempt`]): devolve
/// então o que limita a vez dela.
fn keeps_running(s: &Sched, t: &Thread, me: u32, now: u64) -> Option<Until> {
    let (b, p) = with_sc(t, |sc, p| {
        sc.allows(me as usize).then(|| (refill(sc, &p, now), p))
    })??;
    let top = s.ready.highest();
    let higher = top.is_some_and(|h| h > p.priority);
    let turn_over = now >= s.slice_end && top == Some(p.priority);
    (!b.exhausted(&p) && !higher && !turn_over).then(|| Until::of(&b, &p, now))
}

/// Escolhe a próxima thread e troca para ela. Volta quando a que chamou
/// for escolhida de novo (nunca, se ela saiu).
fn schedule(why: Why) {
    schedule_to(why, None);
}

/// Destino de `direct` (bloqueada, já atendida por IPC) em [`pick_next`].
enum Direct {
    /// Roda já, sem passar pela fila: a CPU está na máscara, tem orçamento
    /// e ninguém pronto tem prioridade maior.
    Run,
    /// Vai para a fila desta CPU.
    Queue,
    /// Fora da máscara: vai para outra CPU ([`to_outbox`]).
    Elsewhere,
}

/// Para onde vai `direct` na CPU `me`, numa leitura só do `SchedContext`
/// dela (T-331).
fn direct_verdict(s: &Sched, t: &Thread, me: u32, now: u64) -> Direct {
    let verdict = with_sc(t, |sc, p| {
        if !sc.allows(me as usize) {
            return Direct::Elsewhere;
        }
        let b = refill(sc, &p, now);
        if !b.exhausted(&p) && s.ready.highest().is_none_or(|h| h <= p.priority) {
            Direct::Run
        } else {
            Direct::Queue
        }
    });
    verdict.unwrap_or_else(|| {
        if allowed(t, me) {
            Direct::Queue
        } else {
            Direct::Elsewhere
        }
    })
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

/// A próxima a rodar na CPU `me`: `direct`, se puder rodar já, ou a
/// primeira da fila. As que `me` não pode rodar (I4) vão para `outbox`.
fn pick_next(s: &mut Sched, direct: Option<Arc<Thread>>, me: u32, now: u64) -> Option<Arc<Thread>> {
    if let Some(t) = direct {
        drop_timeout(s, &t);
        match direct_verdict(s, &t, me, now) {
            Direct::Run => {
                if let Some(c) = FAST_SWITCHES.get(me as usize) {
                    c.store(c.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
                }
                return Some(t);
            }
            Direct::Queue => {
                enqueue(s, t, now);
            }
            Direct::Elsewhere => {
                if let Some(t) = to_outbox(s, t) {
                    return Some(t);
                }
            }
        }
    }
    while let Some((_, t)) = s.ready.pop() {
        if allowed(&t, me) {
            return Some(t);
        }
        if let Some(t) = to_outbox(s, t) {
            return Some(t);
        }
    }
    None
}

/// O que [`run_here`] leu do `SchedContext` da nova atual.
struct Started {
    /// O [`rank`] dela.
    rank: u32,
    /// O que limita a vez dela, para [`program_timer`].
    until: Until,
    /// Ela roda no `SchedContext` que já é cobrado.
    same_charge: bool,
}

/// `n` passa a ser a atual desta CPU (`me`): estado, CPU dona, `on_cpu`
/// se acabou de chegar (`arriving`) e início da janela de orçamento, numa
/// leitura só do `SchedContext` dela (T-331). `charging` é o cobrado até
/// aqui.
fn run_here(
    n: &Thread,
    me: u32,
    arriving: bool,
    now: u64,
    charging: Option<&Arc<SchedContext>>,
) -> Started {
    n.set_state(RunState::Running);
    n.set_cpu(me);
    if arriving {
        // I3: só a anterior desta CPU (que não chega, segue) poderia estar
        // com a pilha em uso; toda outra saiu de vez.
        debug_assert!(!n.on_cpu(), "thread na fila ainda em outra CPU");
        n.set_on_cpu(true);
    }
    let charged = |sc: &SchedContext| charging.is_some_and(|c| core::ptr::eq(sc, Arc::as_ptr(c)));
    n.with_sched_context(|sc| {
        let same_charge = charged(sc);
        let Some(p) = sc.params() else {
            return Started {
                rank: 0,
                until: Until::Nothing,
                same_charge,
            };
        };
        let mut b = sc.budget();
        b.activate(&p, now);
        sc.set_budget(b);
        Started {
            rank: u32::from(p.priority) + 1,
            until: Until::of(&b, &p, now),
            same_charge,
        }
    })
    .unwrap_or(Started {
        rank: 0,
        until: Until::Nothing,
        same_charge: charging.is_none(),
    })
}

/// Destino da atual `p`, que sai da CPU `me` por `why`.
fn put_back(s: &mut Sched, p: &Arc<Thread>, why: Why, me: u32, now: u64) {
    match why {
        Why::Exit => p.set_state(RunState::Exited),
        Why::Block => {}
        // Fora da máscara (mudou ou veio com uma doação): sai para uma CPU
        // permitida depois da troca, quando já não tiver `on_cpu`.
        Why::Yield | Why::Preempt if !allowed(p, me) => {
            if let Some(p) = to_outbox(s, Arc::clone(p)) {
                enqueue(s, p, now);
            }
        }
        Why::Yield | Why::Preempt => {
            enqueue(s, Arc::clone(p), now);
        }
    }
}

/// Registra nos testes que `p` rodou até `now`.
fn trace_ran(s: &mut Sched, p: &Thread, now: u64) {
    if s.trace.len() < s.trace.capacity() {
        let thread = core::ptr::from_ref(p).addr();
        let start = s.started_at;
        s.trace.push(Event::Ran {
            thread,
            start,
            end: now,
        });
    }
}

/// Como [`schedule`], mas com `direct` como próxima (caminho rápido de
/// IPC) se ela puder rodar já; senão, ela vai para a fila.
fn schedule_to(why: Why, direct: Option<Arc<Thread>>) {
    let mut now = ktime::now_ns();
    let me = percpu::cpu_id();
    let mut s = this_sched().lock();
    // Prazos vencidos: só então solta a fila para os cancelar (a do objeto
    // vem antes). O caso comum, sem prazo, fica numa trava só (T-331).
    if s.timeouts.iter().any(|(d, _)| *d <= now) {
        drop(s);
        expire_timeouts();
        now = ktime::now_ns();
        s = this_sched().lock();
    }
    charge_current(&mut s, now);
    release_throttled(&mut s, now);
    if why == Why::Preempt
        && let Some(cur) = s.current.clone()
        && let Some(until) = keeps_running(&s, &cur, me, now)
    {
        // Sem par no nível, a vez segue numa fatia nova: com a vencida, o
        // timer seria armado no passado e dispararia sem parar.
        if now >= s.slice_end {
            s.slice_end = now.saturating_add(DEFAULT_SLICE_NS);
        }
        charge_to(&mut s.charging, Some(&cur));
        publish(&s, None);
        program_timer(&s, until);
        return;
    }
    let prev = s.current.take();
    if let Some(p) = &prev {
        put_back(&mut s, p, why, me, now);
    }
    let next = pick_next(&mut s, direct, me, now);
    let same = match (&prev, &next) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    };
    let started = next
        .as_deref()
        .map(|n| run_here(n, me, !same, now, s.charging.as_ref()));
    if !same {
        if let Some(p) = &prev {
            trace_ran(&mut s, p, now);
        }
        s.started_at = now;
    }
    if !same || why == Why::Yield {
        s.slice_end = now.saturating_add(DEFAULT_SLICE_NS);
    }
    if !started.as_ref().is_some_and(|st| st.same_charge) {
        s.charging = next.as_deref().and_then(Thread::sched_context);
    }
    publish(&s, Some(started.as_ref().map_or(0, |st| st.rank)));
    program_timer(&s, started.map_or(Until::Nothing, |st| st.until));
    if same {
        s.current = next;
        let outbox = !s.outbox.is_empty();
        drop(s);
        drop(prev);
        if outbox {
            drain_outbox();
        }
        return;
    }
    switch_away(s, prev, next);
}

/// O que a troca usa da próxima: lido com a trava da fila na mão, para a
/// referência ir para `current` sem clonar (T-331).
struct Incoming {
    /// rsp salvo dela (ou o do ocioso).
    rsp: u64,
    /// Área de FPU dela.
    fpu: Option<usize>,
    /// Topo da pilha de kernel dela, para a entrada de syscall.
    stack_top: Option<u64>,
    /// Raiz do espaço dela, se tiver um.
    root: Option<u64>,
    /// Ponteiro dela, para `current` e o dump do pânico (0 é o ocioso).
    thread: u64,
}

impl Incoming {
    fn of(next: Option<&Arc<Thread>>) -> Self {
        next.map_or_else(
            || Self {
                rsp: idle_rsp(),
                fpu: None,
                stack_top: None,
                root: None,
                thread: 0,
            },
            |t| Self {
                rsp: t.saved_rsp().load(Ordering::Acquire),
                fpu: Some(t.fpu_area()),
                stack_top: Some(t.stack().top),
                root: t.root(),
                thread: Arc::as_ptr(t).expose_provenance() as u64,
            },
        )
    }
}

/// Fim de uma troca que muda de thread: `next` (já escolhida, com o
/// estado de quem roda) passa a ser a atual de `s` e a CPU troca para ela.
/// Volta quando `prev` (a que sai) rodar de novo.
fn switch_away(mut s: SpinGuard<'_, Sched>, prev: Option<Arc<Thread>>, next: Option<Arc<Thread>>) {
    let incoming = Incoming::of(next.as_ref());
    s.current = next;
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
    // da próxima está mapeada. A próxima segue viva em `current`, que só
    // esta CPU muda.
    unsafe {
        if let Some(area) = prev_fpu {
            fpu::save(core::ptr::with_exposed_provenance_mut(area));
        }
        if let Some(area) = incoming.fpu {
            fpu::restore(core::ptr::with_exposed_provenance(area));
        }
        if let Some(top) = incoming.stack_top {
            syscall::set_kernel_stack(top);
        }
    }
    let root = incoming.root.or_else(|| kmem::kernel_root().map(|r| r.0));
    // Para o dump do pânico (ADR 0031, item 8) e para `current`: quem roda
    // nesta CPU.
    percpu::with(|p| p.thread().store(incoming.thread, Ordering::Relaxed));
    if let Some(root) = root
        && cpu::read_cr3() & 0x000f_ffff_ffff_f000 != root
    {
        // SAFETY: o espaço da thread que vai rodar (vivo enquanto ela
        // estiver em `current`) ou o do kernel; ambos mapeiam o kernel.
        unsafe { crate::kvm::load_root(root) };
    }
    // SAFETY: `prev_slot` é o rsp salvo da anterior, viva (em
    // `switch_prev`) ou o ocioso; `incoming.rsp` foi salvo por esta mesma
    // função ou montado por `start`.
    crate::ksync::assert_none_held("switch_context");
    percpu::assert_no_borrows();
    unsafe { switch_context(prev_slot, incoming.rsp) };
    finish_switch();
}

/// rsp salvo do ocioso desta CPU.
fn idle_rsp() -> u64 {
    percpu::with(|p| p.idle_rsp().load(Ordering::Acquire))
}

/// Já na próxima: libera a pilha da anterior (`on_cpu` falso, ADR 0032,
/// item 3, passo 8), que outra CPU pode passar a rodar, solta a
/// referência a ela (a última, se ela terminou) e manda as prontas que
/// esta CPU não pode rodar para outra.
fn finish_switch() {
    let (prev, outbox) = {
        let mut s = this_sched().lock();
        (s.switch_prev.take(), !s.outbox.is_empty())
    };
    if let Some(p) = prev {
        p.set_on_cpu(false);
        drop(p);
    }
    if outbox {
        drain_outbox();
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
/// dessa CPU, a única que pode pegá-la, mesmo fora da máscara (quem a
/// tirar da fila a manda para uma permitida); senão, vai para a CPU de
/// [`choose_cpu`], entre as da máscara. Destino em outra CPU ociosa ou
/// rodando algo menos prioritário recebe o IPI de reescalonar.
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
    push_to(dest, thread, p);
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

/// Troca direta do caminho rápido de IPC (`okernel::ipc::fast`, T-331):
/// como [`handoff`] sem prazo, sem as conferências que ele já fez. `to` é
/// desta CPU, com a pilha livre, e foi atendida pelo IPC; segue bloqueada
/// até aqui, e ninguém mais a pode acordar (saiu da fila e do `Reply`).
pub fn switch_direct(to: Arc<Thread>) {
    debug_assert_eq!(to.cpu(), percpu::cpu_id(), "troca direta de outra CPU");
    if !to.claim_wake() {
        schedule(Why::Block);
    } else if let Err(to) = direct_switch(to) {
        schedule_to(Why::Block, Some(to));
    }
}

/// A troca de [`switch_direct`] sem a escolha geral de [`schedule_to`]: a
/// atual sai bloqueada e `to` roda já, com o que [`pick_next`] e
/// [`run_here`] fariam com ela, numa leitura só do `SchedContext` dela.
///
/// Devolve `to` se ela não pode rodar já (máscara, orçamento ou alguém
/// pronto mais prioritário) ou se há prazo vencido a tratar; então
/// [`schedule_to`] decide. Até aí só cobrou a atual e reabasteceu os
/// orçamentos que já podiam voltar, o que ele refaz igual.
fn direct_switch(to: Arc<Thread>) -> Result<(), Arc<Thread>> {
    let now = ktime::now_ns();
    let me = percpu::cpu_id();
    let mut s = this_sched().lock();
    if s.current.is_none() || s.timeouts.iter().any(|(d, _)| *d <= now) {
        return Err(to);
    }
    charge_current(&mut s, now);
    release_throttled(&mut s, now);
    let highest = s.ready.highest();
    let charging = s.charging.as_ref().map(Arc::as_ptr);
    let started = to
        .with_sched_context(|sc| {
            let p = sc.params()?;
            if !sc.allows(me as usize) {
                return None;
            }
            let mut b = refill(sc, &p, now);
            if b.exhausted(&p) || highest.is_some_and(|h| h > p.priority) {
                return None;
            }
            b.activate(&p, now);
            sc.set_budget(b);
            Some(Started {
                rank: u32::from(p.priority) + 1,
                until: Until::of(&b, &p, now),
                same_charge: charging.is_some_and(|c| core::ptr::eq(Arc::as_ptr(sc), c)),
            })
        })
        .flatten();
    let Some(started) = started else {
        return Err(to);
    };
    drop_timeout(&mut s, &to);
    to.set_state(RunState::Running);
    to.set_cpu(me);
    debug_assert!(!to.on_cpu(), "troca direta para thread ainda em outra CPU");
    to.set_on_cpu(true);
    let prev = s.current.take();
    if let Some(p) = &prev {
        trace_ran(&mut s, p, now);
    }
    s.started_at = now;
    s.slice_end = now.saturating_add(DEFAULT_SLICE_NS);
    if !started.same_charge {
        s.charging = to.sched_context();
    }
    if let Some(c) = FAST_SWITCHES.get(me as usize) {
        c.store(c.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    }
    publish(&s, Some(started.rank));
    program_timer(&s, started.until);
    switch_away(s, prev, Some(to));
    Ok(())
}

/// Caminho rápido de `ipc_call` que achou o servidor `to` esperando (ADR
/// 0032, item 6): ele segue quem chama e roda nesta CPU. A atual já está
/// bloqueada esperando a resposta, com prazo `deadline`.
///
/// Com `to` noutra CPU, a atual ganha o despertar dele e, sem trava
/// nenhuma na mão (ADR 0031, regra 4), espera a pilha dele sair de uso
/// (`on_cpu`), atendendo os IPIs; então tira o prazo dele da lista da CPU
/// antiga (I7), grava esta CPU como a dele e faz a troca direta. A espera
/// termina: entre entrar na fila do endpoint e trocar de contexto, o
/// servidor só toma travas, que quem espera não segura, e acorda threads,
/// o que nunca espera.
pub fn follow(to: Arc<Thread>, deadline: u64) {
    let me = percpu::cpu_id();
    if to.cpu() == me {
        handoff(to, deadline);
        return;
    }
    push_timeout(deadline);
    if !to.claim_wake() {
        // Alguém já o acordou (e o pôs numa fila).
        schedule(Why::Block);
        return;
    }
    crate::ksync::assert_none_held("follow");
    while to.on_cpu() {
        ksmp::ipi::poll();
        core::hint::spin_loop();
    }
    if let Some(old) = sched_of(to.cpu()) {
        drop_timeout(&mut old.lock(), &to);
    }
    to.set_cpu(me);
    FOLLOWS.fetch_add(1, Ordering::Relaxed);
    schedule_to(Why::Block, Some(to));
}

/// Trocas diretas do caminho rápido de IPC desde o boot.
pub fn fast_switches() -> u64 {
    FAST_SWITCHES
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .sum()
}

/// Servidores que seguiram quem os chamou para outra CPU desde o boot.
pub fn follows() -> u64 {
    FOLLOWS.load(Ordering::Relaxed)
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

    fn follow(&mut self, to: Arc<Thread>, deadline: u64) {
        follow(to, deadline);
    }

    fn read_buffer(&mut self, thread: &Thread, at: usize, out: &mut [u64]) -> bool {
        kipc::read_buffer(thread, at, out)
    }

    fn write_buffer(&mut self, thread: &Thread, at: usize, data: &[u64]) -> bool {
        kipc::write_buffer(thread, at, data)
    }

    fn read_bytes(&mut self, addr: u64, out: &mut [u8]) -> bool {
        probe::copy_from_user(out, addr)
    }

    fn online_cpus(&self) -> CpuMask {
        online_mask()
    }

    fn affinity_changed(&mut self, mask: CpuMask) {
        let me = percpu::cpu_id() as usize;
        for c in 0..ksmp::count().min(MAX_CPUS) {
            if c != me && !mask.contains(c) && usable(c) {
                ksmp::ipi::resched(c);
            }
        }
    }
}

/// Disparo do timer do APIC (com o EOI já feito), vindo do anel 3 ou do
/// ocioso: reavalia quem roda.
pub fn on_timer() {
    ktime::timer_fired();
    periodic_balance(ktime::now_ns());
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
        Syscall::SysInfo => sys_info(a[0]),
        Syscall::ThreadStart => thread_start(a).map(|()| [0; 3]),
        _ => {
            let space = current()
                .and_then(|t| t.cspace())
                .ok_or(Error::NotSupported)?;
            sys::invoke(&space, call, a, kcap::REVOKE_SLICE_BUDGET, &mut KernelEnv)
        }
    }
}

/// `sys_info(seletor)` (ADR 0032, item 4): com [`kabi::sched::SYS_INFO_CPUS`],
/// as CPUs ligadas e o total de ids lógicos da topologia.
fn sys_info(selector: u64) -> Result<Values, Error> {
    match selector {
        kabi::sched::SYS_INFO_CPUS => Ok([
            ksmp::start::online_count().max(1) as u64,
            ksmp::count().max(1) as u64,
            0,
        ]),
        _ => Err(Error::NotSupported),
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
