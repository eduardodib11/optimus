//! Objeto `Thread` (T-206; SDD v1.0, seções 6.1 e 6.3).
//!
//! Uma thread tem pilha de kernel própria (16 KiB com página de guarda),
//! área de estado de FPU/SIMD do tamanho que a CPU pede (XSAVE ou FXSAVE),
//! o `CapSpace` e o `AddressSpace` em que roda. Tudo é cobrado da cota na
//! criação. Os registradores de usuário ficam num quadro no topo da pilha de
//! kernel, montado e lido pelo código de arquitetura.
//!
//! O que o escalonador lê a cada troca (estado, rsp salvo, CR3, área de FPU)
//! fica em atômicas e endereços fixos, para ele não tomar a trava da thread
//! com a da fila na mão (ordem da seção 6.9: objeto antes da fila).

#![forbid(unsafe_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use kabi::vm::{PAGE_SIZE, USER_END, USER_START};
use kabi::{Error, Handle};

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota, SharedCapSpace};
use crate::ipc::IpcSlot;
use crate::platform::{KERNEL_STACK_BYTES, KernelStack, Platform};
use crate::sched::SchedContext;
use crate::sync::SpinLock;
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

/// Onde a thread roda: tabelas de capabilities e de páginas.
#[derive(Default)]
pub struct Binding {
    /// `CapSpace` usado nas syscalls da thread.
    pub cspace: Option<Arc<SharedCapSpace>>,
    /// `AddressSpace` da thread.
    pub aspace: Option<Arc<SharedAddressSpace>>,
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
    /// Valor entregue a quem acorda a thread bloqueada (os bits da
    /// notificação, T-209).
    wake_value: AtomicU64,
    /// Área de FPU; só o código de troca de contexto a acessa, pelo
    /// endereço exposto em `fpu_addr`.
    fpu: Vec<Block>,
    fpu_addr: usize,
    binding: SpinLock<Binding>,
    /// `SchedContext` em que a thread roda; trava folha (nada é tomado
    /// com ela na mão), lida pelo escalonador.
    sched: SpinLock<Option<Arc<SchedContext>>>,
    /// Estado de IPC (T-208); trava folha, depois da fila do objeto.
    ipc: SpinLock<IpcSlot>,
    /// Endereço de usuário do buffer de IPC (zero: sem buffer).
    ipc_buffer: AtomicU64,
    /// Handle cru, no `CapSpace` da thread, do endpoint de exceções (T-210;
    /// zero: sem endpoint).
    exception: AtomicU32,
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
            wake_value: AtomicU64::new(0),
            fpu,
            fpu_addr,
            binding: SpinLock::new(Binding::default()),
            sched: SpinLock::new(None),
            ipc: SpinLock::new(IpcSlot::default()),
            ipc_buffer: AtomicU64::new(0),
            exception: AtomicU32::new(0),
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
    pub fn root(&self) -> Option<u64> {
        let root = self.root.load(Ordering::Acquire);
        (root != 0).then_some(root)
    }

    /// Estado de execução.
    #[must_use]
    pub fn state(&self) -> RunState {
        RunState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Muda o estado (pelo escalonador).
    pub fn set_state(&self, state: RunState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// Bytes cobrados da cota.
    #[must_use]
    pub const fn charged(&self) -> u64 {
        self.charge.bytes()
    }

    /// Guarda o valor que a thread recebe ao acordar.
    pub fn set_wake_value(&self, value: u64) {
        self.wake_value.store(value, Ordering::Release);
    }

    /// O valor entregue no último despertar.
    #[must_use]
    pub fn wake_value(&self) -> u64 {
        self.wake_value.load(Ordering::Acquire)
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
        *binding = Binding {
            cspace: Some(cspace),
            aspace: Some(aspace),
        };
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
        let mut slot = self.sched.lock();
        if self.state() != RunState::Inactive || slot.is_some() || !sc.try_bind() {
            return Err(Error::Busy);
        }
        *slot = Some(sc);
        Ok(())
    }

    /// O `SchedContext` da thread, se ligado.
    #[must_use]
    pub fn sched_context(&self) -> Option<Arc<SchedContext>> {
        self.sched.lock().clone()
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
