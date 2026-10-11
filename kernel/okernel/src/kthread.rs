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
use core::sync::atomic::{AtomicU64, Ordering};

use kabi::vm::{USER_END, USER_START};
use kabi::{Error, Syscall};
use okernel::sched::{DEFAULT_SLICE_NS, Params, RunQueue, SchedContext};
use okernel::sync::SpinLock;
use okernel::sys::{self, Values};
use okernel::thread::{RunState, Thread};

use crate::arch::x86_64::gdt::{USER_CODE, USER_DATA};
use crate::arch::x86_64::idt::TrapFrame;
use crate::arch::x86_64::syscall::{self, switch_context, thread_trampoline};
use crate::arch::x86_64::{cpu, fpu, probe};
use crate::{kcap, kipc, kmem, ktest, ktime};

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
    /// Thread na CPU; `None` é o ocioso (o contexto de boot).
    current: Option<Arc<Thread>>,
    /// Quando a atual foi cobrada pela última vez.
    charged_at: u64,
    /// Quando a atual começou a rodar e quando acaba a fatia dela.
    started_at: u64,
    slice_end: u64,
    ready: RunQueue<Arc<Thread>>,
    /// Sem orçamento, esperando o reabastecimento.
    throttled: Vec<Arc<Thread>>,
    /// Bloqueadas por IPC com prazo (T-208): prazo e thread.
    timeouts: Vec<(u64, Arc<Thread>)>,
    /// Thread que terminou e cuja pilha ainda estava em uso na troca; a
    /// próxima a rodar a solta.
    dead: Option<Arc<Thread>>,
    /// Registro de eventos dos testes (capacidade reservada antes; nunca
    /// aloca aqui).
    trace: Vec<Event>,
}

static SCHED: SpinLock<Sched> = SpinLock::new(Sched {
    current: None,
    charged_at: 0,
    started_at: 0,
    slice_end: 0,
    ready: RunQueue::new(),
    throttled: Vec::new(),
    timeouts: Vec::new(),
    dead: None,
    trace: Vec::new(),
});
/// rsp salvo do ocioso.
static IDLE_RSP: AtomicU64 = AtomicU64::new(0);
/// Trocas diretas do caminho rápido de IPC.
static FAST_SWITCHES: AtomicU64 = AtomicU64::new(0);
static DEBUG_LOG: SpinLock<([u8; 256], usize)> = SpinLock::new(([0; 256], 0));

/// A thread na CPU (`None` no ocioso).
pub fn current() -> Option<Arc<Thread>> {
    SCHED.lock().current.clone()
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
    let mut sched = SCHED.lock();
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
    Ok(())
}

/// `SchedContext` e parâmetros de uma thread iniciada (`start` exige).
fn sc_of(t: &Thread) -> Option<(Arc<SchedContext>, Params)> {
    let sc = t.sched_context()?;
    let params = sc.params()?;
    Some((sc, params))
}

/// Põe `t` na fila do nível dela ou, sem orçamento, na espera.
fn enqueue(s: &mut Sched, t: Arc<Thread>, now: u64) {
    let Some((sc, p)) = sc_of(&t) else { return };
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
    } else {
        t.set_state(RunState::Ready);
        let _ = s.ready.push(p.priority, t);
    }
}

/// Desconta da atual o tempo desde a última cobrança.
fn charge_current(s: &mut Sched, now: u64) {
    if let Some((sc, p)) = s.current.as_deref().and_then(sc_of) {
        let mut b = sc.budget();
        b.consume(&p, now.saturating_sub(s.charged_at));
        sc.set_budget(b);
    }
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
        ktime::set_timer_at(at);
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
            let mut s = SCHED.lock();
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

/// Como [`schedule`], mas com `direct` como próxima (caminho rápido de
/// IPC) se ela puder rodar já; senão, ela vai para a fila.
fn schedule_to(why: Why, direct: Option<Arc<Thread>>) {
    expire_timeouts();
    let now = ktime::now_ns();
    let mut s = SCHED.lock();
    charge_current(&mut s, now);
    release_throttled(&mut s, now);
    if why == Why::Preempt
        && let Some(cur) = s.current.clone()
        && keeps_running(&s, &cur, now)
    {
        program_timer(&s, now);
        return;
    }
    let prev = s.current.take();
    if let Some(p) = &prev {
        match why {
            Why::Exit => p.set_state(RunState::Exited),
            Why::Block => {}
            Why::Yield | Why::Preempt => enqueue(&mut s, Arc::clone(p), now),
        }
    }
    let next = pick_next(&mut s, direct, now);
    let same = match (&prev, &next) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    };
    if let Some(n) = &next {
        n.set_state(RunState::Running);
        if let Some((sc, p)) = sc_of(n) {
            let mut b = sc.budget();
            b.activate(&p, now);
            sc.set_budget(b);
        }
    }
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
    program_timer(&s, now);
    if same {
        return;
    }
    let prev_slot = prev
        .as_ref()
        .map_or(IDLE_RSP.as_ptr(), |p| p.saved_rsp().as_ptr());
    let prev_fpu = prev
        .as_ref()
        .filter(|p| p.state() != RunState::Exited)
        .map(|p| p.fpu_area());
    // A pilha da que saiu segue em uso até a troca; a fila (ou `dead`)
    // mantém viva a anterior enquanto o asm grava em `prev_slot`.
    let buried = if why == Why::Exit {
        core::mem::replace(&mut s.dead, prev)
    } else {
        None
    };
    drop(s);
    drop(buried);
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
    let (next_rsp, root) = next
        .as_ref()
        .map_or((IDLE_RSP.load(Ordering::Acquire), None), |t| {
            (t.saved_rsp().load(Ordering::Acquire), t.root())
        });
    let root = root.or_else(|| kmem::kernel_root().map(|r| r.0));
    if let Some(root) = root
        && cpu::read_cr3() & 0x000f_ffff_ffff_f000 != root
    {
        // SAFETY: o espaço da thread que vai rodar (vivo enquanto ela
        // estiver em `current`) ou o do kernel; ambos mapeiam o kernel.
        unsafe { cpu::write_cr3(root) };
    }
    drop(next);
    // SAFETY: `prev_slot` é o rsp salvo da anterior, viva (na fila, em
    // `dead` ou o ocioso); `next_rsp` foi salvo por esta mesma função ou
    // montado por `start`.
    unsafe { switch_context(prev_slot, next_rsp) };
    finish_switch();
}

/// Solta a thread que terminou, já fora da pilha dela.
fn finish_switch() {
    let dead = SCHED.lock().dead.take();
    drop(dead);
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
pub fn wake(thread: Arc<Thread>, value: u64) {
    thread.set_wake_value(value);
    let mut s = SCHED.lock();
    drop_timeout(&mut s, &thread);
    if thread.state() == RunState::Blocked {
        enqueue(&mut s, thread, ktime::now_ns());
    }
}

/// Bloqueia a atual (já marcada) até alguém a acordar ou, com `deadline`
/// não zero, até o prazo vencer (o IPC a acorda com `TimedOut`).
pub fn block_until(deadline: u64) {
    if deadline != 0 {
        let mut s = SCHED.lock();
        if let Some(t) = s.current.clone()
            && s.timeouts.len() < s.timeouts.capacity()
        {
            s.timeouts.push((deadline, t));
        }
    }
    schedule(Why::Block);
}

/// Caminho rápido de IPC: a atual (já bloqueada, com prazo `deadline`)
/// cede a CPU direto a `to` se `to` puder rodar já; senão, `to` vai para a
/// fila e o escalonador escolhe.
pub fn handoff(to: Arc<Thread>, deadline: u64) {
    if deadline != 0 {
        let mut s = SCHED.lock();
        if let Some(t) = s.current.clone()
            && s.timeouts.len() < s.timeouts.capacity()
        {
            s.timeouts.push((deadline, t));
        }
    }
    schedule_to(Why::Block, Some(to));
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
    preempt();
}

/// Liga o registro de eventos do escalonador com espaço para `capacity`
/// eventos (testes); `false` sem memória.
pub fn trace_start(capacity: usize) -> bool {
    let mut s = SCHED.lock();
    s.trace = Vec::new();
    s.trace.try_reserve_exact(capacity).is_ok()
}

/// Desliga o registro e devolve os eventos.
pub fn trace_take() -> Vec<Event> {
    core::mem::take(&mut SCHED.lock().trace)
}

/// `thread_exit`: a thread atual termina.
fn exit_current() -> ! {
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
        _ => {
            let space = current()
                .and_then(|t| t.cspace())
                .ok_or(Error::NotSupported)?;
            sys::invoke(&space, call, a, kcap::REVOKE_SLICE_BUDGET, &mut KernelEnv)
        }
    }
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
