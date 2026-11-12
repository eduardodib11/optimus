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

use kabi::Error;

use crate::cap::MemoryQuota;
use crate::mm::PhysAddr;
use crate::mm::paging::TableMemory;
use crate::notify::Interrupt;
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
    /// Zera um frame de [`alloc_frame`](Self::alloc_frame) que ainda é de
    /// quem chama (`mem_op(ZERO)`, ADR 0038).
    fn zero_frame(&self, frame: PhysAddr);
    /// Invalida as traduções de `pages` páginas a partir de `start` no
    /// espaço com PML4 `root`, em toda CPU que as possa ter em cache (TLB
    /// shootdown, T-326), e só volta depois. Quem chama libera o que saiu
    /// do mapeamento só depois disso.
    fn flush(&self, root: PhysAddr, start: u64, pages: u64);
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
    /// Verdadeiro se `[base, base + len)` pode virar `MemoryObject` de MMIO
    /// (T-402): fora da RAM e das faixas do kernel, do bootfs e do ACPI, e
    /// fora da MMIO que o próprio kernel usa (APIC, HPET, IOMMU, janela de
    /// MSI).
    fn device_range_ok(&self, base: u64, len: u64) -> bool;
    /// `Interrupt` de MSI ou MSI-X (T-404): um vetor livre, cobrado de
    /// `quota`, e o endereço e o dado que o dispositivo escreve para
    /// dispará-lo.
    ///
    /// # Errors
    ///
    /// [`Error::Busy`] sem vetor livre; [`Error::QuotaExceeded`] sem cota;
    /// [`Error::NotSupported`] onde não há MSI.
    fn msi(&self, quota: &Arc<MemoryQuota>) -> Result<(Arc<Interrupt>, u64, u64), Error> {
        let _ = quota;
        Err(Error::NotSupported)
    }
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
