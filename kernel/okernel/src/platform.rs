//! O que os objetos portáveis pedem à máquina (T-205 em diante).
//!
//! Objetos como `AddressSpace` e `MemoryObject` vivem na biblioteca
//! portável, mas precisam de frames físicos, de acesso às tabelas de página
//! e de invalidar a TLB. O kernel instala uma implementação de [`Platform`]
//! no boot ([`install`]); `obj_create` a usa para criar esses objetos. Os
//! testes no host passam uma implementação falsa direto aos construtores.

#![forbid(unsafe_code)]

use alloc::boxed::Box;

use crate::mm::PhysAddr;
use crate::mm::paging::TableMemory;
use crate::sync::SpinLock;

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
}

static PLATFORM: SpinLock<Option<&'static dyn Platform>> = SpinLock::new(None);

/// Instala a plataforma do kernel (uma vez, no boot).
pub fn install(platform: &'static dyn Platform) {
    *PLATFORM.lock() = Some(platform);
}

/// A plataforma instalada, se houver.
pub fn get() -> Option<&'static dyn Platform> {
    *PLATFORM.lock()
}
