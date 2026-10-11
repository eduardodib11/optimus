//! Memória virtual de usuário sobre o hardware (T-205).
//!
//! A [`Platform`] do kernel entrega aos objetos portáveis de `okernel::vm`
//! frames zerados do buddy, tabelas pelo mapa direto e invalidação da TLB
//! (`invlpg` quando o espaço é o do CR3; os outros espaços não têm
//! traduções em cache, porque a troca de CR3 sem PCID descarta a TLB).

use alloc::boxed::Box;

use okernel::mm::PhysAddr;
use okernel::mm::paging::TableMemory;
use okernel::platform::{self, Platform};

use crate::arch::x86_64::cpu;
use crate::kmem::{self, DirectMap};

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
        // SAFETY: frame recém-saído do buddy, só nosso, no mapa direto
        // (RW), alinhado a 4 KiB.
        unsafe { core::ptr::write_bytes(kmem::direct(frame) as *mut u8, 0, 4096) };
        Some(frame)
    }

    fn free_frame(&self, frame: PhysAddr) {
        kmem::free_frames(frame, 0);
    }

    fn flush(&self, root: PhysAddr, virt: u64) {
        if cpu::read_cr3() & CR3_ADDR == root.0 {
            cpu::invlpg(virt);
        }
    }
}

/// Instala a plataforma; chamar depois de `kmem::init`.
pub fn init() {
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
    // SAFETY: contrato acima: o PML4 mapeia o kernel em execução.
    unsafe { cpu::write_cr3(root.0) };
    old
}
