//! Threads e escalonamento (SDD v1.0, seções 6.1, 6.6 e 14.2; ADR 0029).
//!
//! Além das syscalls cruas, [`spawn`] e [`JoinHandle::join`] (T-335; ADR 0039,
//! itens 2, 3 e 6). Cada thread nova ganha:
//!
//! - **uma região** de um `MemoryObject` só, mapeada num "espaço" de 1 MiB
//!   próprio: `[página de guarda | pilha | bloco da thread (com o buffer de
//!   IPC)]`. A página de guarda fica **sem mapeamento**; estourar a pilha dá
//!   falta de página no endereço dela (e, havendo endpoint de exceções, a
//!   mensagem chega a ele);
//! - **um bloco** ([`crate::tls`]) em `FS_BASE`, com o heap `oalloc` da
//!   thread, os `thread_local!`, o buffer de IPC e o endpoint de exceções
//!   (opcional, de [`Builder::exception_endpoint`]);
//! - **um `SchedContext`** (orçamento = período, prioridade de [`Builder`]) e
//!   um objeto `Thread`, ligado ao `CapSpace` e ao `AddressSpace` de quem criou
//!   com `CONFIGURE_BIND_SELF` (nenhum serviço guarda capability de si).
//!
//! `join` espera o evento de morte do objeto `Thread` (ADR 0035, T-348):
//! liga-o a uma notificação própria (`obj_bind_notify`) e espera nela. O
//! kernel só sinaliza depois de a thread deixar de executar código de
//! usuário, saia ela por `thread_exit`, por falta fatal ou encerrada por
//! outra; só então `join` desmapeia a região e devolve o espaço, e lê o
//! registro de morte (`sys_info`, classe 2). A saída normal roda antes os
//! destrutores dos `thread_local!` e devolve o heap. Os objetos do kernel
//! (`Thread`, `SchedContext`) voltam à cota quando a thread termina de fato
//! e a capability dela, guardada no [`JoinHandle`], é apagada.
//!
//! Um [`JoinHandle`] largado sem `join` não espera: se a thread já morreu,
//! a região volta já; senão vai para uma lista de órfãs, recolhida (as que
//! já morreram) a cada [`spawn`], `join` ou `JoinHandle` largado.
//!
//! Limite: a thread que morre por falta ou encerrada não devolve o heap
//! dela (o estado dele pode estar no meio de uma operação); os segmentos
//! com blocos dela ficam presos até o fim do processo.

#![allow(clippy::cast_possible_truncation, reason = "x86-64: 64 bits")]

use alloc_crate::boxed::Box;
use alloc_crate::sync::Arc;
use alloc_crate::vec::Vec;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use kabi::sched::{CpuMask, SYS_INFO_CPUS};
use kabi::thread::{CONFIGURE_BIND_SELF, CONFIGURE_EXCEPTION, CONFIGURE_IPC_BUFFER, CONFIGURE_TLS};
use kabi::vm::{PAGE_SIZE, WRITE};
use kabi::{Error, Handle, ObjectType, Syscall};

use crate::cap::{self, raw};
use crate::sys::syscall;
use crate::tls::{self, Handoff, ThreadBlock};
use crate::vm::{self, Mapping};

/// `thread = SELF` em `thread_configure`: a própria thread, sem capability
/// (ADR 0039, item 3; o `kabi::thread::SELF`, zero). Vale para [`set_ipc_buffer`],
/// [`set_exception_handler`] e [`set_tls`]; [`bind`] exige a capability.
pub const SELF: Handle = Handle::from_raw(0);
const _: () = assert!(kabi::thread::SELF == 0);

/// Termina a thread atual (`thread_exit`) com o código 0.
pub fn exit() -> ! {
    exit_with(0)
}

/// Termina a thread atual com `code`, que vai ao registro de morte dela
/// (ADR 0035, item 2). Numa thread de [`spawn`], roda antes os destrutores
/// dos `thread_local!` e devolve o heap, e `join` devolve `Err(code)`.
pub fn exit_with(code: u64) -> ! {
    let block = tls::current();
    if block.joinable() {
        block.run_destructors();
        block.retire_heap();
    }
    exit_raw(code)
}

/// Como [`exit_with`], mas sem rodar destrutores nem devolver o heap: para
/// quando o estado da thread não é confiável. O fim chega a quem espera no
/// `join` pelo evento de morte do kernel, como qualquer outro.
pub fn exit_raw(code: u64) -> ! {
    let _ = syscall(Syscall::ThreadExit, [code, 0, 0, 0, 0, 0]);
    // O kernel nunca volta de `thread_exit` sem flags.
    loop {
        core::hint::spin_loop();
    }
}

/// `thread_exit` com `EXIT_GROUP`: encerra o processo inteiro com `code`
/// (ADR 0039, item 5; ADR 0035, item 4): as outras threads morrem como
/// `Killed` e a causa do processo fica `Exited` com `code`. Não roda
/// destrutores. Só volta com o erro do kernel, numa thread sem processo
/// (sem `CapSpace` ligado) nunca: aí só a thread termina.
#[must_use]
pub fn exit_group(code: u64) -> Error {
    match syscall(Syscall::ThreadExit, [code, kabi::exit::GROUP, 0, 0, 0, 0]) {
        Err(e) => e,
        Ok(_) => Error::NotSupported,
    }
}

/// `thread_configure` do TLS: o `FS_BASE` de `thread` ([`SELF`] para a
/// própria) passa a ser `va`, zero ou um endereço da metade de usuário
/// (ADR 0039, item 3). Na própria thread vale já; noutra que roda, na
/// próxima vez que ela entrar numa CPU.
///
/// # Errors
///
/// Os do kernel (`InvalidArgument` fora da metade de usuário).
pub fn set_tls(thread: Handle, va: u64) -> Result<(), Error> {
    let args = [raw(thread), 0, 0, va, 0, CONFIGURE_TLS];
    syscall(Syscall::ThreadConfigure, args).map(drop)
}

/// `thread_configure` com `CONFIGURE_BIND_SELF`: a thread `thread` (ainda
/// não iniciada) passa a rodar no `CapSpace` e no `AddressSpace` de quem
/// chama, sem as capabilities deles (T-335).
///
/// # Errors
///
/// Os do kernel (`Busy` se a thread já começou).
pub fn bind_self(thread: Handle) -> Result<(), Error> {
    let args = [raw(thread), 0, 0, 0, 0, CONFIGURE_BIND_SELF];
    syscall(Syscall::ThreadConfigure, args).map(drop)
}

/// Cede a CPU (`yield`).
pub fn yield_now() {
    let _ = syscall(Syscall::Yield, [0; 6]);
}

/// `thread_configure` só da ligação: a thread passa a rodar com o
/// `CapSpace` `cspace` e o `AddressSpace` `aspace` (antes de
/// [`start`]).
///
/// # Errors
///
/// Os do kernel (`Busy` se a thread já começou).
pub fn bind(thread: Handle, cspace: Handle, aspace: Handle) -> Result<(), Error> {
    let args = [raw(thread), raw(cspace), raw(aspace), 0, 0, 0];
    syscall(Syscall::ThreadConfigure, args).map(drop)
}

/// `thread_configure` do buffer de IPC: `va` (uma página alinhada
/// mapeada no espaço da thread) ou `None` para tirar.
///
/// # Errors
///
/// Os do kernel.
pub fn set_ipc_buffer(thread: Handle, va: Option<u64>) -> Result<(), Error> {
    let args = [raw(thread), 0, 0, va.unwrap_or(0), 0, CONFIGURE_IPC_BUFFER];
    syscall(Syscall::ThreadConfigure, args).map(drop)
}

/// `thread_configure` do endpoint de exceções: `ep` é um handle no
/// `CapSpace` da thread (T-210), ou `None` para tirar.
///
/// # Errors
///
/// Os do kernel.
pub fn set_exception_handler(thread: Handle, ep: Option<Handle>) -> Result<(), Error> {
    let ep = ep.map_or(0, raw);
    let args = [raw(thread), 0, 0, 0, ep, CONFIGURE_EXCEPTION];
    syscall(Syscall::ThreadConfigure, args).map(drop)
}

/// `thread_start`: a thread começa em `rip` com a pilha em `rsp` e `args`
/// em `rdi`, `rsi` e `rdx`.
///
/// # Errors
///
/// Os do kernel (`InvalidArgument` sem ligação ou `SchedContext`).
pub fn start(thread: Handle, rip: u64, rsp: u64, args: [u64; 3]) -> Result<(), Error> {
    let [a0, a1, a2] = args;
    syscall(Syscall::ThreadStart, [raw(thread), rip, rsp, a0, a1, a2]).map(drop)
}

/// `sched_configure`: `budget_ns` a cada `period_ns`, com `priority`
/// (0 a 255; seção 6.6).
///
/// # Errors
///
/// Os do kernel.
pub fn sched_configure(
    sc: Handle,
    budget_ns: u64,
    period_ns: u64,
    priority: u8,
) -> Result<(), Error> {
    let args = [raw(sc), budget_ns, period_ns, u64::from(priority), 0, 0];
    syscall(Syscall::SchedConfigure, args).map(drop)
}

/// Como [`sched_configure`], e o `SchedContext` passa a permitir só as CPUs
/// de `mask` (ADR 0032, item 4): as threads que rodam sobre ele, inclusive
/// por doação, só começam a rodar nelas.
///
/// # Errors
///
/// Os do kernel (`InvalidArgument` se `mask` não tem CPU ligada).
pub fn sched_configure_on(
    sc: Handle,
    budget_ns: u64,
    period_ns: u64,
    priority: u8,
    mask: &CpuMask,
) -> Result<(), Error> {
    let addr = core::ptr::from_ref(mask).addr() as u64;
    let args = [raw(sc), budget_ns, period_ns, u64::from(priority), addr, 0];
    syscall(Syscall::SchedConfigure, args).map(drop)
}

/// CPUs ligadas e total de ids lógicos da topologia (`sys_info` com
/// `SYS_INFO_CPUS`).
///
/// # Errors
///
/// Os do kernel.
pub fn cpus() -> Result<(u64, u64), Error> {
    syscall(Syscall::SysInfo, [SYS_INFO_CPUS, 0, 0, 0, 0, 0])
        .map(|[online, total, _]| (online, total))
}

/// `sched_bind`: a thread passa a rodar sobre o `SchedContext` `sc`.
///
/// # Errors
///
/// Os do kernel.
pub fn sched_bind(sc: Handle, thread: Handle) -> Result<(), Error> {
    syscall(Syscall::SchedBind, [raw(sc), raw(thread), 0, 0, 0, 0]).map(drop)
}

/// Prioridade padrão das threads novas (a do `root` e dos serviços).
pub const DEFAULT_PRIORITY: u8 = 150;
/// Pilha padrão: 64 KiB (ADR 0039, item 6).
pub const DEFAULT_STACK: usize = 64 * 1024;

/// Espaço virtual de cada thread: guarda + pilha + bloco.
const SLOT_BYTES: u64 = 1 << 20;
/// Início da faixa dos espaços (logo acima da janela do alocador).
const SLOTS_BASE: u64 = 0x0000_2000_0000_0000;
/// Quantos espaços existem (4096 threads vivas por processo).
const SLOTS: usize = 4096;
const PERIOD_NS: u64 = 1_000_000;

static SLOT_MAP: [AtomicU64; SLOTS / 64] = [const { AtomicU64::new(0) }; SLOTS / 64];
static SLOT_HINT: AtomicUsize = AtomicUsize::new(0);

/// Reserva um espaço; devolve o índice.
fn slot_take() -> Option<usize> {
    let start = SLOT_HINT.fetch_add(1, Ordering::Relaxed);
    for k in 0..SLOT_MAP.len() {
        let w = (start + k) % SLOT_MAP.len();
        let word = &SLOT_MAP[w];
        let mut cur = word.load(Ordering::Relaxed);
        while cur != u64::MAX {
            let bit = (!cur).trailing_zeros();
            match word.compare_exchange_weak(
                cur,
                cur | (1 << bit),
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(w * 64 + bit as usize),
                Err(now) => cur = now,
            }
        }
    }
    None
}

fn slot_give(index: usize) {
    SLOT_MAP[index / 64].fetch_and(!(1 << (index % 64)), Ordering::Release);
}

/// A região da thread: o mapeamento (pilha e bloco) e o espaço que ocupa.
/// O `Drop` desmapeia e devolve o espaço.
struct Region {
    map: Option<Mapping>,
    slot: usize,
}

impl Drop for Region {
    fn drop(&mut self) {
        drop(self.map.take());
        slot_give(self.slot);
    }
}

/// Opções de [`spawn`].
#[derive(Clone, Copy, Debug)]
pub struct Builder {
    stack: usize,
    priority: u8,
    quota: Option<Handle>,
    exception: Option<Handle>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// Pilha de [`DEFAULT_STACK`], prioridade [`DEFAULT_PRIORITY`], cota do
    /// processo, sem endpoint de exceções.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stack: DEFAULT_STACK,
            priority: DEFAULT_PRIORITY,
            quota: None,
            exception: None,
        }
    }

    /// Tamanho da pilha, arredondado para páginas (entre 1 página e quase
    /// 1 MiB).
    #[must_use]
    pub const fn stack_size(mut self, bytes: usize) -> Self {
        self.stack = bytes;
        self
    }

    /// Prioridade do `SchedContext` da thread.
    #[must_use]
    pub const fn priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Cota de onde saem a região (pilha e bloco), o `Thread` e o
    /// `SchedContext` (a do processo, por omissão). Os segmentos do heap da
    /// thread saem sempre da cota de `rt::init`.
    #[must_use]
    pub const fn quota(mut self, quota: Handle) -> Self {
        self.quota = Some(quota);
        self
    }

    /// Endpoint de exceções da thread: um handle no `CapSpace` do processo
    /// (`thread_configure`, `CONFIGURE_EXCEPTION`).
    #[must_use]
    pub const fn exception_endpoint(mut self, ep: Handle) -> Self {
        self.exception = Some(ep);
        self
    }

    /// Cria e inicia uma thread que roda `f`.
    ///
    /// # Errors
    ///
    /// `NotSupported` antes de `rt::init`; `InvalidArgument` para pilha
    /// grande demais; `QuotaExceeded` sem cota ou sem espaço para threads; os
    /// do kernel. Em erro nada fica: região, objetos e função são devolvidos.
    pub fn spawn<F, T>(self, f: F) -> Result<JoinHandle<T>, Error>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let env = crate::rt::env().ok_or(Error::NotSupported)?;
        let quota = self.quota.unwrap_or(env.quota);
        let stack = self.stack.max(1).next_multiple_of(PAGE_SIZE as usize);
        let block_len = size_of::<ThreadBlock>();
        let total = stack + block_len;
        // Guarda (1 página) + região cabem no espaço.
        if (total as u64) + PAGE_SIZE > SLOT_BYTES {
            return Err(Error::InvalidArgument);
        }
        // Antes de a nova thread pedir segmentos, devolve os que ficaram
        // ociosos aqui (ver `alloc::collect`).
        crate::alloc::collect();
        reap_orphans();
        let slot = slot_take().ok_or(Error::QuotaExceeded)?;
        let base = SLOTS_BASE + slot as u64 * SLOT_BYTES;
        // O mapeamento começa depois da guarda, que nunca é mapeada.
        let object = cap::create(quota, ObjectType::MemoryObject, total as u64)
            .inspect_err(|_| slot_give(slot))?;
        let map = Mapping::new(vm::SELF, object, base + PAGE_SIZE, total as u64, WRITE);
        // A região guarda o objeto; sem ela o `vm_unmap` o destrói.
        let _ = cap::delete(object);
        let region = Region {
            map: Some(map.inspect_err(|_| slot_give(slot))?),
            slot,
        };
        let map = region.map.as_ref().ok_or(Error::InvalidArgument)?;
        let block = tls::init_block(map, stack, self.exception);
        let packet = Arc::new(Handoff::<T>::new());
        let theirs = Arc::clone(&packet);
        block.set_main(Box::new(move || theirs.set(f())));
        let top = base + PAGE_SIZE + stack as u64;
        let thread = match self.launch(quota, block, top) {
            Ok(thread) => thread,
            Err(e) => {
                // A função nunca rodou: solta-a (e o `Arc` dela) já.
                drop(block.take_main());
                return Err(e);
            }
        };
        Ok(JoinHandle {
            thread,
            region: Some(region),
            guard: base,
            stack,
            packet,
            _owns: PhantomData,
        })
    }

    /// Cria o `Thread` e o `SchedContext`, configura e inicia; devolve a
    /// capability da thread (para o `join` esperar a morte dela).
    fn launch(&self, quota: Handle, block: &ThreadBlock, top: u64) -> Result<Handle, Error> {
        let thread = cap::create(quota, ObjectType::Thread, 0)?;
        let result = (|| {
            let sc = cap::create(quota, ObjectType::SchedContext, 0)?;
            let bound = sched_configure(sc, PERIOD_NS, PERIOD_NS, self.priority)
                .and_then(|()| sched_bind(sc, thread));
            // A thread guarda o `SchedContext`; a capability não faz falta.
            let _ = cap::delete(sc);
            bound?;
            bind_self(thread)?;
            set_tls(thread, block_va(block))?;
            set_ipc_buffer(thread, Some(block.ipc_va()))?;
            if let Some(ep) = block.exception() {
                set_exception_handler(thread, Some(ep))?;
            }
            // Na entrada o ABI espera `rsp + 8` alinhado a 16 (como depois
            // de um `call`).
            start(thread, entry_point(), top - 8, [0; 3])
        })();
        if result.is_err() {
            let _ = cap::delete(thread);
        }
        result.map(|()| thread)
    }
}

fn block_va(block: &ThreadBlock) -> u64 {
    core::ptr::from_ref(block).addr() as u64
}

fn entry_point() -> u64 {
    let f: extern "sysv64" fn(u64) -> ! = thread_entry;
    f as usize as u64
}

/// Primeira função de uma thread de [`spawn`].
extern "sysv64" fn thread_entry(_: u64) -> ! {
    if let Some(main) = tls::current().take_main() {
        main();
    }
    exit_with(0)
}

/// Cria uma thread que roda `f` (com o [`Builder`] padrão).
///
/// # Panics
///
/// Se a thread não pôde ser criada (ver [`Builder::spawn`]).
pub fn spawn<F, T>(f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    Builder::new().spawn(f).expect("thread::spawn")
}

/// Identificador único da thread que chama (a principal é 1).
#[must_use]
pub fn id() -> u64 {
    tls::current().id()
}

/// Espera para juntar uma thread criada por [`spawn`].
///
/// Largar o `JoinHandle` sem `join` solta a thread (ela segue); a região
/// dela volta quando ela morrer (ver o módulo).
pub struct JoinHandle<T> {
    /// Capability do objeto `Thread` (`BIND` e `READ_STATE`).
    thread: Handle,
    region: Option<Region>,
    guard: u64,
    stack: usize,
    packet: Arc<Handoff<T>>,
    _owns: PhantomData<T>,
}

impl<T> JoinHandle<T> {
    fn block(&self) -> Option<&ThreadBlock> {
        let map = self.region.as_ref()?.map.as_ref()?;
        Some(tls::block_in(map, self.stack))
    }

    /// Endereço da página de guarda (sem mapeamento) logo abaixo da pilha.
    #[must_use]
    pub const fn guard_page(&self) -> u64 {
        self.guard
    }

    /// Identificador da thread.
    #[must_use]
    pub fn thread_id(&self) -> u64 {
        self.block().map_or(0, ThreadBlock::id)
    }

    /// A capability do objeto `Thread` (vale até o `join` ou o `Drop`), para
    /// ligar o evento de morte a outra notificação ([`cap::bind_notify`]) ou
    /// ler o registro de morte. Não a apague nem a destrua: `join` espera por
    /// ela (para encerrar, [`kill`](Self::kill)).
    #[must_use]
    pub const fn handle(&self) -> Handle {
        self.thread
    }

    /// Encerra a thread (ADR 0035, item 4): ela morre como `Killed` sem
    /// voltar ao código dela (nem rodar destrutores), inclusive se espera
    /// numa fila ou roda noutra CPU. Encerra uma cópia da capability; o
    /// `join` segue valendo.
    ///
    /// # Errors
    ///
    /// Os do kernel (`QuotaExceeded` sem espaço na tabela para a cópia).
    pub fn kill(&self) -> Result<(), Error> {
        let copy = cap::mint(self.thread, kabi::Rights::DESTROY, 0, None)?;
        cap::destroy(copy).inspect_err(|_| {
            let _ = cap::delete(copy);
        })
    }

    /// Espera a thread terminar, libera a pilha e o bloco dela e devolve o
    /// resultado de `f`, ou `Err(código)` se ela não voltou de `f`: o código
    /// de `exit_with`, o vetor da falta fatal ou 0 se outra a encerrou (ver
    /// [`join_status`](Self::join_status) para a causa).
    ///
    /// # Errors
    ///
    /// O código de saída, se `f` não voltou.
    pub fn join(self) -> Result<T, u64> {
        self.join_status().map_err(|d| d.code)
    }

    /// Como [`join`](Self::join), com o registro de morte inteiro (causa,
    /// código e auxiliar; ADR 0035, item 2) se `f` não voltou.
    ///
    /// # Errors
    ///
    /// O registro de morte, se `f` não voltou.
    pub fn join_status(mut self) -> Result<T, cap::Death> {
        let death = wait_death(self.thread);
        if let Some(region) = self.region.take() {
            if death.is_some() {
                reclaim(self.thread, region, self.stack);
            } else {
                // Capability perdida: a thread pode estar viva na região.
                core::mem::forget(region);
            }
        }
        let death = death.unwrap_or(cap::Death {
            cause: 0,
            code: 0,
            aux: 0,
        });
        // A thread pode ter liberado blocos nossos: recolhe-os agora, para os
        // segmentos voltarem à fonte (ver `alloc::collect`).
        crate::alloc::collect();
        reap_orphans();
        self.packet.take().ok_or(death)
    }
}

impl<T> Drop for JoinHandle<T> {
    fn drop(&mut self) {
        let Some(region) = self.region.take() else {
            return;
        };
        let orphan = Orphan {
            thread: self.thread,
            region,
            stack: self.stack,
        };
        if orphan.dead() {
            orphan.reclaim();
        } else {
            let mut list = ORPHANS.lock();
            if list.try_reserve(1).is_ok() {
                list.push(orphan);
            } else {
                // Sem memória para guardar: a região vaza (a thread pode
                // estar rodando nela).
                core::mem::forget(orphan);
            }
        }
        reap_orphans();
    }
}

/// O registro de morte de `thread`, esperando por ele: pela notificação
/// ligada ao evento de morte ou, sem cota para ela, cedendo a vez até a
/// thread morrer. `None` se a capability não lê mais o registro (apagada
/// por quem a recebeu de [`JoinHandle::handle`]).
fn wait_death(thread: Handle) -> Option<cap::Death> {
    let read = || cap::death(thread);
    match read() {
        Ok(Some(d)) => return Some(d),
        Ok(None) => {}
        Err(_) => return None,
    }
    if let Some(env) = crate::rt::env()
        && let Ok(ntfy) = cap::create(env.quota, ObjectType::Notification, 0)
    {
        if cap::bind_notify(thread, ntfy, 1).is_ok() {
            while syscall(Syscall::NtfyWait, [raw(ntfy), 0, 0, 0, 0, 0])
                .is_ok_and(|[bits, ..]| bits & 1 == 0)
            {}
        }
        // O kernel solta a notificação com a ligação, na morte da thread.
        let _ = cap::delete(ntfy);
    }
    loop {
        match read() {
            Ok(Some(d)) => return Some(d),
            Ok(None) => yield_now(),
            Err(_) => return None,
        }
    }
}

/// Devolve o que era de uma thread morta: a função inicial (se ela morreu
/// antes de rodá-la), a capability e a região.
fn reclaim(thread: Handle, region: Region, stack: usize) {
    if let Some(map) = region.map.as_ref() {
        // Morta, a thread não toca mais no bloco: quem a junta é o dono.
        drop(tls::block_in(map, stack).take_main());
    }
    let _ = cap::delete(thread);
    drop(region);
}

/// Thread de um `JoinHandle` largado, ainda viva da última vez que se viu.
struct Orphan {
    thread: Handle,
    region: Region,
    stack: usize,
}

impl Orphan {
    fn dead(&self) -> bool {
        // Sem como ler (capability sumiu), fica guardada: liberar a região
        // de uma thread que pode estar viva seria pior que vazá-la.
        cap::death(self.thread).is_ok_and(|d| d.is_some())
    }

    fn reclaim(self) {
        reclaim(self.thread, self.region, self.stack);
    }
}

/// As órfãs (ver o módulo).
static ORPHANS: crate::sync::Mutex<Vec<Orphan>> = crate::sync::Mutex::new(Vec::new());

/// Devolve a região das órfãs que já morreram (fora da trava).
fn reap_orphans() {
    let dead: Vec<Orphan> = {
        let Some(mut list) = ORPHANS.try_lock() else {
            return;
        };
        if list.is_empty() {
            return;
        }
        let mut dead = Vec::new();
        let mut i = 0;
        while i < list.len() {
            if list[i].dead() && dead.try_reserve(1).is_ok() {
                dead.push(list.swap_remove(i));
            } else {
                i += 1;
            }
        }
        dead
    };
    for orphan in dead {
        orphan.reclaim();
    }
}
