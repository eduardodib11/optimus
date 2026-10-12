//! O que os objetos portáveis pedem à máquina (T-205 em diante).
//!
//! Objetos como `AddressSpace` e `MemoryObject` vivem na biblioteca
//! portável, mas precisam de frames físicos, de acesso às tabelas de página
//! e de invalidar a TLB. O kernel instala uma implementação de [`Platform`]
//! no boot ([`install`]); `obj_create` a usa para criar esses objetos. Os
//! testes no host passam uma implementação falsa direto aos construtores.

#![forbid(unsafe_code)]

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::mm::PhysAddr;
use crate::mm::paging::TableMemory;
use crate::sync::{LockClass, SpinLock};
use crate::thread::Thread;

/// Serviços da máquina para os objetos do kernel.
pub trait Platform: Sync {
    /// Acesso às tabelas de página de um espaço de endereçamento novo; as
    /// tabelas que ele aloca saem do mesmo lugar que [`alloc_frame`](Self::alloc_frame).
    fn tables(&self) -> Box<dyn TableMemory + Send>;
    /// PML4 do kernel, de onde um espaço novo copia a metade alta.
    fn kernel_root(&self) -> PhysAddr;
    /// Um frame de 4 KiB zerado.
    fn alloc_frame(&self) -> Option<PhysAddr>;
    /// Devolve um frame de [`alloc_frame`](Self::alloc_frame).
    fn free_frame(&self, frame: PhysAddr);
    /// Invalida a tradução de `virt` no espaço com PML4 `root`, onde ela
    /// estiver em cache.
    fn flush(&self, root: PhysAddr, virt: u64);
    /// Pilha de kernel de uma thread nova ([`KERNEL_STACK_BYTES`]), com
    /// página de guarda.
    fn alloc_kernel_stack(&self) -> Option<KernelStack>;
    /// Devolve uma pilha de [`alloc_kernel_stack`](Self::alloc_kernel_stack),
    /// que ninguém mais usa.
    fn free_kernel_stack(&self, stack: KernelStack);
    /// Bytes da área de estado de FPU/SIMD de uma thread (XSAVE ou FXSAVE).
    fn fpu_area_bytes(&self) -> usize;
    /// Põe de volta na fila `thread`, bloqueada num objeto de IPC que foi
    /// destruído (o resultado da espera já está gravado nela); não troca de
    /// thread. Pode ser chamada com a trava de um `CapSpace` na mão.
    fn wake(&self, thread: Arc<Thread>);
}

/// Bytes da pilha de kernel de cada thread (seção 6.3).
pub const KERNEL_STACK_BYTES: u64 = 16 << 10;

/// Pilha de kernel de uma thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelStack {
    /// Topo (exclusivo), alinhado a 16 bytes.
    pub top: u64,
    /// Identificador da pilha para quem a alocou.
    pub slot: u32,
}

static PLATFORM: SpinLock<Option<&'static dyn Platform>> =
    SpinLock::with_class(LockClass::Diagnostic, None);

/// Instala a plataforma do kernel (uma vez, no boot).
pub fn install(platform: &'static dyn Platform) {
    *PLATFORM.lock() = Some(platform);
}

/// A plataforma instalada, se houver.
pub fn get() -> Option<&'static dyn Platform> {
    *PLATFORM.lock()
}
