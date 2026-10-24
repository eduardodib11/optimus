//! Objeto `Thread` (T-206; SDD v1.0, seções 6.1 e 6.3).
//!
//! Uma thread tem pilha de kernel própria (16 KiB com página de guarda),
//! área de estado de FPU/SIMD do tamanho que a CPU pede (XSAVE ou FXSAVE),
//! o `CapSpace` e o `AddressSpace` em que roda. Tudo é cobrado da cota na
//! criação. Os registradores de usuário ficam num quadro no topo da pilha de
//! kernel, montado e lido pelo código de arquitetura.
//!
//! O que o escalonador lê a cada troca (estado, rsp salvo, CR3, área de FPU,
//! `FS_BASE`) fica em atômicas e endereços fixos, para ele não tomar a trava da thread
//! com a da fila na mão (ordem da seção 6.9: objeto antes da fila).

#![forbid(unsafe_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{
    AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering, fence,
};

use kabi::vm::{PAGE_SIZE, USER_END, USER_START};
use kabi::{Error, Handle};

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota, SharedCapSpace};
use crate::ipc::IpcSlot;
use crate::notify::Notification;
use crate::platform::{KERNEL_STACK_BYTES, KernelStack, Platform};
use crate::sched::SchedContext;
use crate::sync::{LockClass, SpinLock};
use crate::vm::SharedAddressSpace;

/// Estado de execução.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RunState {
    /// Criada, ainda sem `thread_start`.
    Inactive = 0,
    /// Na fila, pronta para rodar.
    Ready = 1,
    /// Na CPU.
    Running = 2,
    /// Esperando o próximo período do `SchedContext` (T-207).
    Throttled = 3,
    /// Terminou com `thread_exit`; não roda mais.
    Exited = 4,
    /// Esperando numa `Notification` ou num futex (T-209), fora da fila.
    Blocked = 5,
}

impl RunState {
    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Ready,
            2 => Self::Running,
            3 => Self::Throttled,
            4 => Self::Exited,
            5 => Self::Blocked,
            _ => Self::Inactive,
        }
    }
}

/// Bloco de 64 bytes alinhado como XSAVE exige.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct Block([u8; 64]);

/// Palavra de controle x87 inicial (FNINIT).
const FCW_INIT: u16 = 0x037f;
/// MXCSR inicial: todas as exceções SIMD mascaradas.
const MXCSR_INIT: u32 = 0x1f80;

/// A ligação de um evento de ciclo de vida (ADR 0035, item 3): a
/// notificação e os bits que ela recebe.
pub type Event = (Arc<Notification>, u64);

/// Onde a thread roda (tabelas de capabilities e de páginas) e o estado da
/// morte dela (ADR 0035, itens 3 e 4), sob a trava `Thread.binding`.
#[derive(Default)]
pub struct Binding {
    /// `CapSpace` usado nas syscalls da thread.
    pub cspace: Option<Arc<SharedCapSpace>>,
    /// `AddressSpace` da thread.
    pub aspace: Option<Arc<SharedAddressSpace>>,
    /// Ligação do evento de morte (`obj_bind_notify`).
    event: Option<Event>,
    /// A thread já morreu: o evento é nível, e ligar depois sinaliza já.
    dead: bool,
    /// Alguém pediu o encerramento ([`Thread::request_kill`]).
    kill: bool,
}

/// Threads com encerramento pedido e ainda vivas, em todo o kernel: zero é
/// o caso comum, e o caminho de volta ao usuário só olha a própria thread
/// quando há alguma.
static KILLS: AtomicUsize = AtomicUsize::new(0);

/// Há thread com encerramento pedido que ainda não morreu.
#[must_use]
#[inline]
pub fn kills_pending() -> bool {
    KILLS.load(Ordering::SeqCst) != 0
}

/// O que a morte de uma thread entrega a quem a registra
/// ([`Thread::mark_dead`]).
pub struct Death {
    /// O evento a sinalizar, se ligado.
    pub event: Option<Event>,
    /// O `CapSpace` (processo) da thread, se ligada.
    pub cspace: Option<Arc<SharedCapSpace>>,
}

/// `SchedContext`s de uma thread, sob uma trava só: o escalonador lê o
/// ativo várias vezes por troca (T-331).
#[derive(Default)]
struct SchedSlots {
    /// O dela, ligado por `sched_bind`.
    own: Option<Arc<SchedContext>>,
    /// O doado por quem chamou, enquanto ela atende a chamada (seção
    /// 6.6); vale no lugar de `own`.
    donated: Option<Arc<SchedContext>>,
}

impl SchedSlots {
    fn active(&self) -> Option<&Arc<SchedContext>> {
        self.donated.as_ref().or(self.own.as_ref())
    }
}

/// Contexto de execução.
pub struct Thread {
    charge: Charge,
    platform: &'static dyn Platform,
    stack: KernelStack,
    /// rsp do kernel salvo na última troca de contexto (escrito pelo asm).
    saved_rsp: AtomicU64,
    /// PML4 do espaço da thread (zero sem espaço).
    root: AtomicU64,
    state: AtomicU8,
    /// CPU dona da thread: a da fila em que está ou a última em que rodou
    /// (ADR 0032, item 1).
    cpu: AtomicU32,
    /// A pilha de kernel da thread está em uso por uma CPU: ela é a atual
    /// dessa CPU ou acabou de sair e a troca ainda não terminou (ADR 0032,
    /// I1). Nenhuma outra CPU a roda enquanto isso (I3).
    on_cpu: AtomicBool,
    /// Valor entregue a quem acorda a thread bloqueada (os bits da
    /// notificação, T-209).
    wake_value: AtomicU64,
    /// Erro do despertar (cru; zero sem erro): o objeto em que a thread
    /// esperava morreu (`PeerClosed` da notificação, ADR 0032, item 6).
    wake_error: AtomicU64,
    /// Área de FPU; só o código de troca de contexto a acessa, pelo
    /// endereço exposto em `fpu_addr`.
    fpu: Vec<Block>,
    fpu_addr: usize,
    binding: SpinLock<Binding>,
    /// `SchedContext` dela e o doado; trava folha (nada é tomado com ela
    /// na mão), lida pelo escalonador.
    sched: SpinLock<SchedSlots>,
    /// Estado de IPC (T-208); trava folha, depois da fila do objeto.
    ipc: SpinLock<IpcSlot>,
    /// Endereço de usuário do buffer de IPC (zero: sem buffer).
    ipc_buffer: AtomicU64,
    /// Handle cru, no `CapSpace` da thread, do endpoint de exceções (T-210;
    /// zero: sem endpoint).
    exception: AtomicU32,
    /// `FS_BASE` do usuário (T-333; ADR 0039, item 3): a troca de contexto
    /// o põe na CPU ao entrar a thread.
    fs_base: AtomicU64,
    /// Registro de morte (ADR 0035, item 2): causa (`kabi::exit::CAUSE_*`;
    /// zero: viva), código e auxiliar. A causa é gravada por último.
    death_cause: AtomicU8,
    death: [AtomicU64; 2],
    /// Cópia de `Binding::kill` lida sem trava (volta ao usuário e espera).
    kill: AtomicBool,
    /// A thread conta nas vivas do processo (`process::on_start`); muda só
    /// com a trava do `CapSpace` dela.
    counted: AtomicBool,
}

impl fmt::Debug for Thread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Thread(pilha {:#x}, {:?})", self.stack.top, self.state())
    }
}

impl Thread {
    /// Thread inativa, com pilha e área de FPU, cobrada de `quota`.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota ou sem memória para a pilha.
    pub fn new(quota: &Arc<MemoryQuota>, platform: &'static dyn Platform) -> Result<Self, Error> {
        let fpu_bytes = platform.fpu_area_bytes();
        let blocks = fpu_bytes.div_ceil(size_of::<Block>());
        let cost = object_bytes::<Self>() + KERNEL_STACK_BYTES + (blocks * 64) as u64;
        let charge = quota.charge(cost)?;
        let mut fpu = Vec::new();
        fpu.try_reserve_exact(blocks)
            .map_err(|_| Error::QuotaExceeded)?;
        fpu.resize(blocks, Block([0; 64]));
        if let Some(first) = fpu.first_mut() {
            first.0[..2].copy_from_slice(&FCW_INIT.to_le_bytes());
            first.0[24..28].copy_from_slice(&MXCSR_INIT.to_le_bytes());
        }
        let fpu_addr = fpu.as_mut_ptr().expose_provenance();
        let stack = platform.alloc_kernel_stack().ok_or(Error::QuotaExceeded)?;
        Ok(Self {
            charge,
            platform,
            stack,
            saved_rsp: AtomicU64::new(0),
            root: AtomicU64::new(0),
            state: AtomicU8::new(RunState::Inactive as u8),
            cpu: AtomicU32::new(0),
            on_cpu: AtomicBool::new(false),
            wake_value: AtomicU64::new(0),
            wake_error: AtomicU64::new(0),
            fpu,
            fpu_addr,
            binding: SpinLock::with_class(LockClass::Object, Binding::default()),
            sched: SpinLock::with_class(LockClass::SchedLeaf, SchedSlots::default()),
            ipc: SpinLock::with_class(LockClass::IpcSlot, IpcSlot::default()),
            ipc_buffer: AtomicU64::new(0),
            exception: AtomicU32::new(0),
            fs_base: AtomicU64::new(0),
            death_cause: AtomicU8::new(0),
            death: [const { AtomicU64::new(0) }; 2],
            kill: AtomicBool::new(false),
            counted: AtomicBool::new(false),
        })
    }

    /// A plataforma da thread (quem a põe de volta na fila).
    #[must_use]
    pub fn platform(&self) -> &'static dyn Platform {
        self.platform
    }

    /// Pilha de kernel.
    #[must_use]
    pub const fn stack(&self) -> KernelStack {
        self.stack
    }

    /// Endereço (com proveniência exposta) da área de FPU, alinhado a 64.
    #[must_use]
    pub const fn fpu_area(&self) -> usize {
        self.fpu_addr
    }

    /// Bytes da área de FPU.
    #[must_use]
    pub fn fpu_bytes(&self) -> usize {
        self.fpu.len() * size_of::<Block>()
    }

    /// Onde o asm de troca guarda o rsp do kernel.
    #[must_use]
    pub const fn saved_rsp(&self) -> &AtomicU64 {
        &self.saved_rsp
    }

    /// PML4 do espaço (para o CR3), se configurada.
    #[must_use]
    #[inline]
    pub fn root(&self) -> Option<u64> {
        let root = self.root.load(Ordering::Acquire);
        (root != 0).then_some(root)
    }

    /// Estado de execução.
    #[must_use]
    #[inline]
    pub fn state(&self) -> RunState {
        RunState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Muda o estado (pelo escalonador).
    #[inline]
    pub fn set_state(&self, state: RunState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// Passa de `Blocked` a `Ready` se ainda estiver bloqueada; só quem
    /// vence põe a thread numa fila (ADR 0032, item 5): dois despertares
    /// ao mesmo tempo, de CPUs diferentes, nunca a enfileiram duas vezes.
    #[inline]
    pub fn claim_wake(&self) -> bool {
        self.state
            .compare_exchange(
                RunState::Blocked as u8,
                RunState::Ready as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Bytes cobrados da cota.
    #[must_use]
    pub const fn charged(&self) -> u64 {
        self.charge.bytes()
    }

    /// Muda a CPU dona da thread (pelo escalonador, com a thread fora de
    /// qualquer CPU).
    #[inline]
    pub fn set_cpu(&self, cpu: u32) {
        self.cpu.store(cpu, Ordering::Release);
    }

    /// CPU dona da thread (a da fila em que está ou a última em que rodou).
    #[inline]
    pub fn cpu(&self) -> u32 {
        self.cpu.load(Ordering::Acquire)
    }

    /// Marca a pilha de kernel em uso (ao virar a atual de uma CPU) ou
    /// livre (pela CPU, depois de terminar a troca para outra).
    #[inline]
    pub fn set_on_cpu(&self, on: bool) {
        self.on_cpu.store(on, Ordering::Release);
    }

    /// A pilha de kernel da thread está em uso por uma CPU.
    #[must_use]
    #[inline]
    pub fn on_cpu(&self) -> bool {
        self.on_cpu.load(Ordering::Acquire)
    }

    /// Guarda o valor que a thread recebe ao acordar.
    #[inline]
    pub fn set_wake_value(&self, value: u64) {
        self.wake_value.store(value, Ordering::Release);
    }

    /// O valor entregue no último despertar.
    #[must_use]
    pub fn wake_value(&self) -> u64 {
        self.wake_value.load(Ordering::Acquire)
    }

    /// O próximo despertar devolve `e` em vez do valor (antes de acordar
    /// a thread, por quem tirou a thread da fila do objeto).
    pub fn set_wake_error(&self, e: Error) {
        self.wake_error.store(e.to_raw(), Ordering::Release);
    }

    /// Tira o erro do último despertar, se houver.
    pub fn take_wake_error(&self) -> Option<Error> {
        Error::try_from(self.wake_error.swap(0, Ordering::AcqRel)).ok()
    }

    /// `thread_configure`: liga a thread a um `CapSpace` e a um
    /// `AddressSpace`. Só antes de `thread_start`.
    ///
    /// # Errors
    ///
    /// [`Error::Busy`] se a thread já foi iniciada.
    pub fn configure(
        &self,
        cspace: Arc<SharedCapSpace>,
        aspace: Arc<SharedAddressSpace>,
    ) -> Result<(), Error> {
        let mut binding = self.binding.lock();
        if self.state() != RunState::Inactive {
            return Err(Error::Busy);
        }
        self.root.store(aspace.lock().root().0, Ordering::Release);
        binding.cspace = Some(cspace);
        binding.aspace = Some(aspace);
        Ok(())
    }

    /// `sched_bind`: a thread passa a rodar sobre `sc`. Só antes de
    /// `thread_start`, uma vez por thread e por `SchedContext`.
    ///
    /// # Errors
    ///
    /// [`Error::Busy`] se a thread já iniciou ou já tem um `SchedContext`,
    /// ou se `sc` já está ligado a outra.
    pub fn bind_sched(&self, sc: Arc<SchedContext>) -> Result<(), Error> {
        let mut slots = self.sched.lock();
        if self.state() != RunState::Inactive || slots.own.is_some() || !sc.try_bind() {
            return Err(Error::Busy);
        }
        slots.own = Some(sc);
        Ok(())
    }

    /// O `SchedContext` em que a thread roda: o doado, se ela atende uma
    /// chamada, ou o dela, se ligado.
    #[must_use]
    pub fn sched_context(&self) -> Option<Arc<SchedContext>> {
        self.sched.lock().active().cloned()
    }

    /// `f` sobre o [`sched_context`](Self::sched_context), sem tomar uma
    /// referência a ele; `f` roda com a trava folha na mão e não pode
    /// tomar outra.
    pub fn with_sched_context<R>(&self, f: impl FnOnce(&Arc<SchedContext>) -> R) -> Option<R> {
        self.sched.lock().active().map(f)
    }

    /// Doação em `ipc_call` (seção 6.6): a thread passa a rodar com `sc`,
    /// o tempo e a prioridade de quem chamou, até [`undonate`](Self::undonate).
    pub fn donate(&self, sc: Arc<SchedContext>) {
        let old = self.sched.lock().donated.replace(sc);
        // A última referência pode ir aqui: solta sem a trava na mão.
        drop(old);
    }

    /// Devolve a doação `sc`, se for a que a thread usa agora.
    pub fn undonate(&self, sc: &Arc<SchedContext>) {
        let mut slots = self.sched.lock();
        if slots.donated.as_ref().is_some_and(|d| Arc::ptr_eq(d, sc)) {
            let old = slots.donated.take();
            drop(slots);
            drop(old);
        }
    }

    /// O `AddressSpace` da thread, se configurada.
    #[must_use]
    pub fn aspace(&self) -> Option<Arc<SharedAddressSpace>> {
        self.binding.lock().aspace.clone()
    }

    /// Estado de IPC da thread.
    #[must_use]
    pub const fn ipc(&self) -> &SpinLock<IpcSlot> {
        &self.ipc
    }

    /// Endereço de usuário do buffer de IPC, se houver.
    #[must_use]
    #[inline]
    pub fn ipc_buffer(&self) -> Option<u64> {
        let va = self.ipc_buffer.load(Ordering::Acquire);
        (va != 0).then_some(va)
    }

    /// `va` serve de buffer de IPC: zero ou uma página alinhada na metade
    /// de usuário.
    #[must_use]
    pub fn valid_ipc_buffer(va: u64) -> bool {
        va == 0 || (va.is_multiple_of(PAGE_SIZE) && (USER_START..USER_END).contains(&va))
    }

    /// Fixa o buffer de IPC (parte de `thread_configure`): uma página
    /// alinhada na metade de usuário; zero tira o buffer.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] para endereço desalinhado ou fora da
    /// metade de usuário.
    pub fn set_ipc_buffer(&self, va: u64) -> Result<(), Error> {
        if !Self::valid_ipc_buffer(va) {
            return Err(Error::InvalidArgument);
        }
        self.ipc_buffer.store(va, Ordering::Release);
        Ok(())
    }

    /// Fixa o endpoint de exceções (parte de `thread_configure`, T-210): o
    /// handle, no `CapSpace` da thread, procurado a cada falta; o handle
    /// nulo tira o endpoint. Como só o handle fica guardado, apagar ou
    /// revogar a capability também o tira.
    pub fn set_exception_handler(&self, h: Handle) {
        self.exception.store(h.raw(), Ordering::Release);
    }

    /// O handle do endpoint de exceções, se houver.
    #[must_use]
    pub fn exception_handler(&self) -> Option<Handle> {
        let raw = self.exception.load(Ordering::Acquire);
        (raw != 0).then(|| Handle::from_raw(raw))
    }

    /// O `CapSpace` da thread, se configurada.
    #[must_use]
    pub fn cspace(&self) -> Option<Arc<SharedCapSpace>> {
        self.binding.lock().cspace.clone()
    }

    /// `va` serve de `FS_BASE` (ADR 0039, item 3): zero ou um endereço
    /// canônico da metade de usuário (abaixo de `USER_END`). Um valor não
    /// canônico daria #GP no `WRMSR` do kernel; um da metade alta
    /// apontaria o TLS para o kernel.
    #[must_use]
    pub const fn valid_tls(va: u64) -> bool {
        va < USER_END
    }

    /// Fixa o `FS_BASE` (parte de `thread_configure`, `CONFIGURE_TLS`). A
    /// CPU o recebe na próxima vez que a thread entrar nela (ou já, se
    /// quem chama for a própria thread e gravar o MSR).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] fora da metade de usuário.
    pub fn set_tls(&self, va: u64) -> Result<(), Error> {
        if !Self::valid_tls(va) {
            return Err(Error::InvalidArgument);
        }
        self.fs_base.store(va, Ordering::Release);
        Ok(())
    }

    /// O `FS_BASE` da thread (zero: nenhum).
    #[must_use]
    #[inline]
    pub fn tls(&self) -> u64 {
        self.fs_base.load(Ordering::Acquire)
    }

    /// Grava o registro de morte (ADR 0035, item 2): `cause` é uma de
    /// `kabi::exit::CAUSE_*`. Só a primeira gravação vale; chamada pela
    /// própria thread no caminho de saída.
    pub fn record_death(&self, cause: u8, code: u64, aux: u64) {
        if cause == 0 || self.death_cause.load(Ordering::Acquire) != 0 {
            return;
        }
        self.death[0].store(code, Ordering::Relaxed);
        self.death[1].store(aux, Ordering::Relaxed);
        self.death_cause.store(cause, Ordering::Release);
    }

    /// `thread_start` toma a thread: de `Inactive` a `Ready`, uma vez só
    /// (contra outra partida e contra o encerramento de uma inativa).
    #[must_use]
    pub fn claim_start(&self) -> bool {
        self.state
            .compare_exchange(
                RunState::Inactive as u8,
                RunState::Ready as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Desfaz [`claim_start`](Self::claim_start): a partida falhou antes de
    /// a thread entrar numa fila.
    pub fn unclaim_start(&self) {
        self.set_state(RunState::Inactive);
    }

    /// Pede o encerramento da thread (ADR 0035, item 4): ela morre como
    /// `Killed` na próxima volta ao usuário, ao tentar bloquear ou, inativa,
    /// já (quem pede chama [`kill_inactive`](Self::kill_inactive)). Falso se
    /// ela já morreu ou o pedido já existia.
    pub fn request_kill(&self) -> bool {
        let mut b = self.binding.lock();
        if b.dead || b.kill {
            return false;
        }
        b.kill = true;
        KILLS.fetch_add(1, Ordering::SeqCst);
        self.kill.store(true, Ordering::SeqCst);
        drop(b);
        // Par com a espera (`ipc::cancel_any` e a conferência antes de
        // bloquear): ou quem pede vê a espera publicada no slot, ou a thread
        // vê o pedido depois de publicá-la.
        fence(Ordering::SeqCst);
        true
    }

    /// O encerramento foi pedido.
    #[must_use]
    #[inline]
    pub fn kill_requested(&self) -> bool {
        self.kill.load(Ordering::SeqCst)
    }

    /// Thread nunca iniciada e com encerramento pedido: passa a `Exited`,
    /// para nenhuma partida a rodar. Falso se ela já foi iniciada.
    #[must_use]
    pub fn kill_inactive(&self) -> bool {
        self.state
            .compare_exchange(
                RunState::Inactive as u8,
                RunState::Exited as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Marca a morte, uma vez só (o registro já gravado), e devolve o
    /// evento a sinalizar e o `CapSpace` da thread; `None` se ela já estava
    /// morta.
    pub fn mark_dead(&self) -> Option<Death> {
        let mut b = self.binding.lock();
        if b.dead {
            return None;
        }
        b.dead = true;
        if b.kill {
            KILLS.fetch_sub(1, Ordering::SeqCst);
        }
        Some(Death {
            event: b.event.take(),
            cspace: b.cspace.clone(),
        })
    }

    /// `obj_bind_notify` sobre a thread (ADR 0035, item 3): `event` passa a
    /// ser a ligação (`None` desliga). Devolve o que sinalizar já (a thread
    /// já morreu: o evento é nível e não fica guardado) e a ligação antiga,
    /// para quem chama soltar sem a trava.
    pub fn bind_death(&self, event: Option<Event>) -> (Option<Event>, Option<Event>) {
        let mut b = self.binding.lock();
        if b.dead {
            return (event, b.event.take());
        }
        (None, core::mem::replace(&mut b.event, event))
    }

    /// A thread conta nas vivas do processo (com a trava do `CapSpace`).
    #[must_use]
    pub fn counted(&self) -> bool {
        self.counted.load(Ordering::Relaxed)
    }

    /// Marca se a thread conta nas vivas do processo (com a trava do
    /// `CapSpace`).
    pub fn set_counted(&self, counted: bool) {
        self.counted.store(counted, Ordering::Relaxed);
    }

    /// O registro de morte, `(causa, código, auxiliar)`, se a thread já
    /// morreu.
    #[must_use]
    pub fn death(&self) -> Option<(u8, u64, u64)> {
        let cause = self.death_cause.load(Ordering::Acquire);
        (cause != 0).then(|| {
            (
                cause,
                self.death[0].load(Ordering::Relaxed),
                self.death[1].load(Ordering::Relaxed),
            )
        })
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        // Quem solta a última referência nunca é a própria thread: o
        // escalonador só a solta depois de trocar para outra.
        self.platform.free_kernel_stack(self.stack);
    }
}

#[cfg(test)]
mod tests;
