//! Memória virtual de usuário e pilhas de kernel sobre o hardware (T-205,
//! T-206).
//!
//! A [`Platform`] do kernel entrega aos objetos portáveis de `okernel::vm`
//! frames zerados do buddy, tabelas pelo mapa direto e invalidação da TLB
//! em toda CPU com o espaço no CR3 (shootdown, `ksmp::tlb`, T-326; as
//! outras não têm traduções em cache, porque a troca de CR3 sem PCID
//! descarta a TLB).
//!
//! As pilhas de kernel das threads (16 KiB) ficam na faixa de pilhas da
//! seção 6.4, uma por fatia de 32 KiB: os 16 KiB de baixo nunca são
//! mapeados e servem de guarda contra estouro.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use okernel::mm::PhysAddr;
use okernel::mm::paging::{Flags, PageSize, TableMemory};
use okernel::platform::{self, KERNEL_STACK_BYTES, KernelStack, Platform};
use okernel::sync::{LockClass, SpinLock};
use okernel::thread::Thread;

use crate::arch::x86_64::{cpu, fpu};
use crate::kmem::{self, DirectMap};
use crate::ksmp::tlb;
use okernel::tlb::Flush;

/// Início das pilhas de kernel das threads, na faixa de pilhas da seção 6.4
/// (`0xFFFF_E000_0000_0000`); o primeiro MiB dela fica com a pilha
/// provisória que o optboot deixou mapeada.
const STACKS_BASE: u64 = 0xffff_e000_0010_0000;
/// Fatia de cada pilha: guarda embaixo, pilha em cima.
const STACK_SLOT: u64 = 2 * KERNEL_STACK_BYTES;
const PAGE: u64 = 4096;

/// Fatias de pilha: a próxima nunca usada e as devolvidas.
static STACK_SLOTS: SpinLock<(u32, Vec<u32>)> =
    SpinLock::with_class(LockClass::KernelStacks, (0, Vec::new()));

mod tests;
pub use tests::TESTS;

/// Bits do endereço físico do PML4 no CR3.
const CR3_ADDR: u64 = 0x000f_ffff_ffff_f000;

struct KernelPlatform;

static PLATFORM: KernelPlatform = KernelPlatform;

impl Platform for KernelPlatform {
    fn tables(&self) -> Box<dyn TableMemory + Send> {
        // `DirectMap` não tem tamanho: a caixa não aloca.
        Box::new(DirectMap)
    }

    fn kernel_root(&self) -> PhysAddr {
        kmem::kernel_root().unwrap_or(PhysAddr(cpu::read_cr3() & CR3_ADDR))
    }

    fn alloc_frame(&self) -> Option<PhysAddr> {
        let frame = kmem::alloc_frames(0)?;
        zero_frame(frame);
        Some(frame)
    }

    fn free_frame(&self, frame: PhysAddr) {
        kmem::free_frames(frame, 0);
    }

    fn zero_frame(&self, frame: PhysAddr) {
        zero_frame(frame);
    }

    fn flush(&self, root: PhysAddr, start: u64, pages: u64) {
        tlb::flush(root.0, Flush::range(start, pages));
    }

    fn alloc_kernel_stack(&self) -> Option<KernelStack> {
        let slot = {
            let mut slots = STACK_SLOTS.lock();
            if let Some(slot) = slots.1.pop() {
                slot
            } else {
                slots.0 = slots.0.checked_add(1)?;
                slots.0 - 1
            }
        };
        let top = STACKS_BASE + (u64::from(slot) + 1) * STACK_SLOT;
        let stack = KernelStack { top, slot };
        let bottom = top - KERNEL_STACK_BYTES;
        for page in (0..KERNEL_STACK_BYTES / PAGE).map(|i| bottom + i * PAGE) {
            let mapped = kmem::alloc_frames(0).is_some_and(|frame| {
                zero_frame(frame);
                let ok = kmem::map(page, frame, PageSize::Size4K, Flags::RW).is_ok();
                if !ok {
                    kmem::free_frames(frame, 0);
                }
                ok
            });
            if !mapped {
                self.free_kernel_stack(stack);
                return None;
            }
        }
        Some(stack)
    }

    fn free_kernel_stack(&self, stack: KernelStack) {
        // Um shootdown para a pilha toda (a thread pode ter rodado noutra
        // CPU), e só depois os frames voltam ao buddy.
        let bottom = stack.top - KERNEL_STACK_BYTES;
        kmem::unmap_pages(bottom, KERNEL_STACK_BYTES / PAGE, &mut |frame| {
            kmem::free_frames(frame, 0);
        });
        let mut slots = STACK_SLOTS.lock();
        // Sem memória para a lista, a fatia só deixa de ser reutilizada.
        if slots.1.try_reserve(1).is_ok() {
            slots.1.push(stack.slot);
        }
    }

    fn fpu_area_bytes(&self) -> usize {
        fpu::area_bytes()
    }

    fn wake(&self, thread: Arc<Thread>) {
        crate::kthread::wake(thread, 0);
    }

    fn device_range_ok(&self, base: u64, len: u64) -> bool {
        device_range_ok(base, len)
    }

    fn msi(
        &self,
        quota: &Arc<okernel::cap::MemoryQuota>,
        source: Option<u16>,
    ) -> Result<(Arc<okernel::notify::Interrupt>, u64, u64), kabi::Error> {
        crate::kirq::create_msi(quota, source)
    }

    fn isa_irq(
        &self,
        quota: &Arc<okernel::cap::MemoryQuota>,
        irq: u8,
    ) -> Result<Arc<okernel::notify::Interrupt>, kabi::Error> {
        crate::kirq::create_isa(quota, irq)
    }
}

/// Janela de mensagens MSI do APIC local: escrever nela é interromper.
const MSI_WINDOW: (u64, u64) = (0xFEE0_0000, 0xFEF0_0000);
/// Fim dos endereços físicos que um objeto de dispositivo pode cobrir.
const PHYS_LIMIT: u64 = 1 << 52;

/// Faixa aceita como MMIO de dispositivo (T-402): dentro de 52 bits, fora
/// da janela de MSI, da MMIO do próprio kernel e de toda faixa do mapa de
/// memória que não seja `Mmio` ou `Reserved` (RAM, kernel, bootfs, ACPI).
fn device_range_ok(base: u64, len: u64) -> bool {
    use kabi::boot::MemKind;
    let Some(end) = base.checked_add(len) else {
        return false;
    };
    let Some(map) = crate::bootinfo::get().and_then(crate::bootinfo::memory_map) else {
        return false;
    };
    let overlaps = |a: u64, b: u64| a < end && base < b;
    len != 0
        && end <= PHYS_LIMIT
        && !overlaps(MSI_WINDOW.0, MSI_WINDOW.1)
        && !kmem::touches_kernel_mmio(base, end)
        && !map.iter().any(|r| {
            !matches!(r.kind(), MemKind::Mmio | MemKind::Reserved) && overlaps(r.base, r.end())
        })
}

/// Liga a FPU para o usuário e instala a plataforma; chamar depois de
/// `kmem::init`.
pub fn init() {
    fpu::init();
    platform::install(&PLATFORM);
}

/// Troca o espaço de endereçamento ativo; devolve o CR3 anterior.
///
/// # Safety
///
/// `root` precisa ser o PML4 de um `AddressSpace` vivo (que tem a metade
/// alta do kernel) ou o do kernel, e continuar vivo enquanto estiver no CR3.
pub unsafe fn activate(root: PhysAddr) -> u64 {
    let old = cpu::read_cr3();
    // SAFETY: contrato acima.
    unsafe { load_root(root.0) };
    old
}

/// Zera um frame recém-saído do buddy. As pilhas de kernel também saem
/// zeradas: nada de dado velho na pilha e, no TCG, nenhuma tradução velha
/// na página (do firmware ou de código de usuário que morou nela), que
/// deixaria lenta toda escrita nela enquanto durasse.
fn zero_frame(frame: PhysAddr) {
    // SAFETY: frame do buddy que é de quem chama (recém-alocado ou de um
    // `MemoryObject`, sem referência Rust a ele), no mapa direto (RW),
    // alinhado a 4 KiB.
    unsafe { core::ptr::write_bytes(kmem::direct(frame) as *mut u8, 0, 4096) };
}

/// Carrega `root` no CR3, anotando-o antes para o shootdown (ADR 0031,
/// item 7: a anotação vem antes do `mov cr3`).
///
/// # Safety
///
/// Como em [`activate`].
pub unsafe fn load_root(root: u64) {
    tlb::note_root(root);
    if cpu::read_cr4() & crate::ketapas::CR4_PCIDE != 0 {
        unsafe { cpu::write_cr3(root | ((root >> 12) % 4095 + 1) | (1 << 63)) };
        return;
    }
    // SAFETY: contrato acima: o PML4 mapeia o kernel em execução.
    unsafe { cpu::write_cr3(root) };
}
