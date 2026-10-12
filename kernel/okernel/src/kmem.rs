//! Memória do kernel sobre o hardware (T-107; SDD v1.0, seções 6.3 a 6.5).
//!
//! Liga a lógica portável de `okernel::mm` à máquina: o buddy recebe a RAM
//! usável do mapa da `BootInfo`, e as tabelas de página deixadas pelo optboot
//! passam a ser geridas pelo kernel através do mapa direto. Na partida, o
//! kernel remove a identidade temporária da metade baixa, deixa só de leitura
//! o apelido do texto e dos dados só de leitura no mapa direto (W^X vale em
//! todos os apelidos) e liga SMEP, SMAP e UMIP quando a CPU os tem.
//!
//! Ordem das travas: tabelas de página antes de frames.
//!
//! Frames de 4 KiB passam pelo cache da CPU (T-328, `okernel::mm::cache`):
//! sem trava, só a própria CPU o usa, e a trava do buddy só é tomada para
//! trazer ou devolver um lote. [`frame_stats`] conta os frames parados nos
//! caches como livres. Uma liberação dupla só é pega no cache da mesma CPU
//! (o buddy pega as que chegam a ele).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kabi::boot::{DIRECT_MAP_START, MemRegion};
use okernel::mm::buddy::{FrameAllocator, FrameMeta};
use okernel::mm::cache::FRAME_BATCH;
use okernel::mm::paging::{Flags, MapError, Mapping, PageSize, PageTables, Table, TableMemory};
use okernel::mm::{FRAME_SIZE, PhysAddr, frames};
use okernel::sync::{LockClass, SpinLock};
use okernel::tlb::{Flush, KERNEL_ROOT};

use crate::arch::x86_64::{cpu, percpu};
use crate::ksmp::{self, tlb};

mod tests;
pub use tests::TESTS;

/// Base do mapa direto, lida da `BootInfo` no boot (ADR 0026).
static DIRECT_BASE: AtomicU64 = AtomicU64::new(DIRECT_MAP_START);
static FRAMES: SpinLock<Option<FrameAllocator<'static>>> =
    SpinLock::with_class(LockClass::Frames, None);
static KERNEL_PT: SpinLock<Option<PageTables<DirectMap>>> =
    SpinLock::with_class(LockClass::KernelPageTables, None);
/// Faixa física gerida pelo buddy (`[início, fim)`), para conferir o que
/// entra no cache sem tomar a trava.
static MANAGED: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// Cache de frames por CPU ligado; desligar serve só para medir o ganho.
static CACHE_ON: AtomicBool = AtomicBool::new(true);

unsafe extern "C" {
    static __kernel_text_start: u8;
    static __kernel_text_end: u8;
    static __kernel_rodata_start: u8;
    static __kernel_rodata_end: u8;
}

/// Faixa virtual `[início, fim)` do texto do kernel.
pub fn kernel_text() -> (u64, u64) {
    (
        (&raw const __kernel_text_start).addr() as u64,
        (&raw const __kernel_text_end).addr() as u64,
    )
}

/// Faixa virtual `[início, fim)` dos dados só de leitura do kernel.
pub fn kernel_rodata() -> (u64, u64) {
    (
        (&raw const __kernel_rodata_start).addr() as u64,
        (&raw const __kernel_rodata_end).addr() as u64,
    )
}

/// Fixa a base do mapa direto (`BootInfo.direct_map_base`, já validada).
/// Chamar uma vez, no boot, antes de qualquer acesso pelo mapa direto.
pub fn set_direct_base(base: u64) {
    DIRECT_BASE.store(base, Ordering::Relaxed);
}

/// Base do mapa direto: o endereço virtual do físico 0.
pub fn direct_base() -> u64 {
    DIRECT_BASE.load(Ordering::Relaxed)
}

/// Endereço virtual de `phys` no mapa direto.
pub fn direct(phys: PhysAddr) -> u64 {
    direct_base() + phys.0
}

/// Tabelas acessadas pelo mapa direto, com frames do buddy.
pub struct DirectMap;

impl TableMemory for DirectMap {
    fn table(&mut self, phys: PhysAddr) -> &mut Table {
        // SAFETY: tabelas de página moram em frames de RAM, todos no mapa
        // direto, alinhados a 4 KiB; quem chama segura `KERNEL_PT`, então só
        // há um acesso por vez.
        unsafe { &mut *(direct(phys) as *mut Table) }
    }

    fn alloc_table(&mut self) -> Option<PhysAddr> {
        let frame = alloc_frames(0)?;
        self.table(frame).fill(0);
        Some(frame)
    }

    fn free_table(&mut self, phys: PhysAddr) {
        free_frames(phys, 0);
    }
}

/// Aloca `2^order` frames contíguos (os de 4 KiB, pelo cache desta CPU).
pub fn alloc_frames(order: usize) -> Option<PhysAddr> {
    if order == 0 && CACHE_ON.load(Ordering::Relaxed) {
        let frame = percpu::with_frame_cache(|c| {
            if let Some(f) = c.pop() {
                return Some(f);
            }
            let mut frames = FRAMES.lock();
            let buddy = frames.as_mut()?;
            c.refill(FRAME_BATCH, &mut || buddy.alloc(0).map(|f| f.0));
            c.pop()
        });
        // Vazio aqui e no buddy: não há o que devolver desta CPU.
        return frame.map(PhysAddr);
    }
    if let Some(frame) = FRAMES.lock().as_mut()?.alloc(order) {
        return Some(frame);
    }
    // Os frames parados no cache desta CPU podem completar um bloco.
    drain_frame_cache();
    FRAMES.lock().as_mut()?.alloc(order)
}

/// Devolve frames obtidos com [`alloc_frames`].
pub fn free_frames(addr: PhysAddr, order: usize) {
    if order == 0 && CACHE_ON.load(Ordering::Relaxed) && managed(addr) {
        percpu::with_frame_cache(|c| {
            if c.contains(addr.0) {
                error!("okernel: free_frames({:#x}, 0): já livre", addr.0);
                return;
            }
            if c.push(addr.0) {
                return;
            }
            if let Some(buddy) = FRAMES.lock().as_mut() {
                c.spill(FRAME_BATCH, &mut |f| buddy_free(buddy, PhysAddr(f), 0));
            }
            if !c.push(addr.0) {
                error!("okernel: cache de frames cheio depois de esvaziar");
            }
        });
        return;
    }
    if let Some(buddy) = FRAMES.lock().as_mut() {
        buddy_free(buddy, addr, order);
    }
}

fn buddy_free(buddy: &mut FrameAllocator<'static>, addr: PhysAddr, order: usize) {
    if let Err(e) = buddy.free(addr, order) {
        error!("okernel: free_frames({:#x}, {order}): {e:?}", addr.0);
    }
}

/// Frame de 4 KiB alinhado dentro da faixa do buddy.
fn managed(addr: PhysAddr) -> bool {
    let [start, end] = [0, 1].map(|i| MANAGED[i].load(Ordering::Relaxed));
    addr.0.is_multiple_of(FRAME_SIZE) && (start..end).contains(&addr.0)
}

/// Devolve ao buddy todos os frames do cache desta CPU.
pub fn drain_frame_cache() {
    percpu::with_frame_cache(|c| {
        if c.is_empty() {
            return;
        }
        if let Some(buddy) = FRAMES.lock().as_mut() {
            c.spill(usize::MAX, &mut |f| buddy_free(buddy, PhysAddr(f), 0));
        }
    });
}

/// Liga ou desliga o cache de frames por CPU (para medir); devolve o
/// estado anterior. Desligado, os frames que já estão nos caches ficam
/// lá até ele voltar.
pub fn set_frame_cache(on: bool) -> bool {
    CACHE_ON.swap(on, Ordering::AcqRel)
}

/// Frames parados nos caches de todas as CPUs (pode estar mudando).
pub fn cached_frames() -> usize {
    let aps = (1..ksmp::count()).filter_map(ksmp::start::percpu_of);
    percpu::bsp().frames_cached() + aps.map(percpu::PerCpu::frames_cached).sum::<usize>()
}

/// PML4 do kernel.
pub fn kernel_root() -> Option<PhysAddr> {
    Some(KERNEL_PT.lock().as_ref()?.root())
}

/// Frames livres (no buddy e nos caches das CPUs) e gerenciados.
pub fn frame_stats() -> (usize, usize) {
    let (free, managed) = FRAMES
        .lock()
        .as_ref()
        .map_or((0, 0), |f| (f.free_frames(), f.managed_frames()));
    (free + cached_frames(), managed)
}

fn with_tables<T>(
    f: impl FnOnce(&mut PageTables<DirectMap>) -> Result<T, MapError>,
) -> Result<T, MapError> {
    f(KERNEL_PT.lock().as_mut().ok_or(MapError::NotMapped)?)
}

/// Mapeia uma página no espaço do kernel.
pub fn map(virt: u64, phys: PhysAddr, size: PageSize, flags: Flags) -> Result<(), MapError> {
    with_tables(|pt| pt.map(virt, phys, size, flags))
}

/// Desmapeia uma página do kernel e invalida a TLB em toda CPU
/// (shootdown, T-326); devolve o frame, que só então pode ser liberado.
pub fn unmap(virt: u64, size: PageSize) -> Result<PhysAddr, MapError> {
    let phys = with_tables(|pt| pt.unmap(virt, size))?;
    tlb::flush(KERNEL_ROOT, Flush::range(virt, size.bytes() / 4096));
    Ok(phys)
}

/// Desmapeia `pages` páginas de 4 KiB do kernel a partir de `start` (até
/// [`okernel::tlb::MAX_PAGES`]) com um só shootdown e só depois entrega a
/// `freed` o frame de cada uma.
pub fn unmap_pages(start: u64, pages: u64, freed: &mut dyn FnMut(PhysAddr)) {
    const _: () = assert!(okernel::tlb::MAX_PAGES == 32);
    let mut frames = [PhysAddr(0); 32];
    let mut n = 0;
    if let Some(pt) = KERNEL_PT.lock().as_mut() {
        for i in 0..pages.min(okernel::tlb::MAX_PAGES) {
            if let Ok(frame) = pt.unmap(start + i * 4096, PageSize::Size4K) {
                frames[n] = frame;
                n += 1;
            }
        }
    }
    tlb::flush(KERNEL_ROOT, Flush::range(start, pages));
    for &frame in &frames[..n] {
        freed(frame);
    }
}

/// Troca as permissões de uma página do kernel e invalida a TLB em toda
/// CPU.
pub fn protect(virt: u64, size: PageSize, flags: Flags) -> Result<(), MapError> {
    with_tables(|pt| pt.protect(virt, size, flags))?;
    tlb::flush(KERNEL_ROOT, Flush::range(virt, size.bytes() / 4096));
    Ok(())
}

/// Deixa sem cache o apelido no mapa direto da página de MMIO em `phys`,
/// para registradores de dispositivo (APIC, HPET); devolve o endereço virtual.
pub fn mmio(phys: u64) -> Result<u64, MapError> {
    let virt = direct(PhysAddr(phys & !0xfff));
    let flags = Flags {
        uncached: true,
        ..Flags::RW
    };
    protect(virt, PageSize::Size4K, flags)?;
    Ok(virt + (phys & 0xfff))
}

/// A folha que mapeia `virt`.
pub fn translate(virt: u64) -> Option<Mapping> {
    KERNEL_PT.lock().as_mut()?.translate(virt)
}

/// Visita todas as folhas do espaço do kernel.
pub fn for_each_leaf(f: &mut dyn FnMut(u64, Mapping)) {
    if let Some(pt) = KERNEL_PT.lock().as_mut() {
        pt.for_each_leaf(f);
    }
}

/// Inicializa o buddy, assume as tabelas de página e endurece o espaço do
/// kernel. Chamar uma vez, no boot.
pub fn init(map: &[MemRegion]) {
    init_frames(map);
    let root = PhysAddr(cpu::read_cr3() & 0x000f_ffff_ffff_f000);
    // SAFETY: o PML4 ativo é uma tabela válida no mapa direto; a metade
    // baixa só tem a identidade temporária do optboot, que nada do kernel usa
    // (código, pilha, BootInfo e tabelas estão na metade alta).
    let pml4 = unsafe { &mut *(direct(root) as *mut Table) };
    pml4[..256].fill(0);
    // Toda entrada da metade alta ganha tabela já no boot: os espaços de
    // usuário (T-205) copiam essas entradas, e um mapeamento posterior do
    // kernel aparece em todos eles.
    let mut tables = DirectMap;
    let missing = pml4[256..].iter().filter(|e| **e & 1 == 0).count();
    for entry in pml4[256..].iter_mut().filter(|e| **e & 1 == 0) {
        match tables.alloc_table() {
            Some(t) => *entry = t.0 | 0b11,
            None => error!("okernel: sem frame para a metade alta do PML4"),
        }
    }
    let mut pt = PageTables::new(root, DirectMap);
    let mut protected = 0;
    for (start, end) in [kernel_text(), kernel_rodata()] {
        for virt in (start..end).step_by(4096) {
            let Some(m) = pt.translate(virt) else {
                continue;
            };
            let alias = direct(m.phys);
            match pt.protect(alias, PageSize::Size4K, Flags::READ) {
                Ok(()) => protected += 1,
                Err(e) => error!("okernel: protegendo {alias:#x}: {e:?}"),
            }
        }
    }
    *KERNEL_PT.lock() = Some(pt);
    cpu::flush_tlb();
    info!(
        "okernel: identidade removida; {protected} páginas do kernel só de leitura no mapa direto; {missing} entradas da metade alta criadas"
    );
    harden_cpu();
}

fn init_frames(map: &[MemRegion]) {
    let Some(plan) = frames::plan(map) else {
        error!("okernel: sem memória usável para o buddy");
        return;
    };
    let meta = direct(plan.meta) as *mut FrameMeta;
    // SAFETY: `plan.meta` é RAM usável (só o kernel a usa agora), no mapa
    // direto, com espaço para `plan.frames` entradas; cada uma é escrita antes
    // de virar referência.
    let meta = unsafe {
        for i in 0..plan.frames {
            meta.add(i).write(FrameMeta::EMPTY);
        }
        core::slice::from_raw_parts_mut(meta, plan.frames)
    };
    let Ok(mut buddy) = FrameAllocator::new(plan.base, meta) else {
        error!("okernel: faixa do buddy inválida");
        return;
    };
    for (base, len) in frames::free_ranges(map, &plan) {
        if let Err(e) = buddy.add_region(PhysAddr(base), len) {
            error!("okernel: faixa {base:#x}+{len:#x} recusada: {e:?}");
        }
    }
    info!(
        "okernel: buddy com {} MiB livres; metadados de {} KiB em {:#x}",
        (buddy.free_frames() as u64 * FRAME_SIZE) >> 20,
        plan.meta_bytes >> 10,
        plan.meta.0
    );
    MANAGED[0].store(plan.base.0, Ordering::Relaxed);
    MANAGED[1].store(
        plan.base.0 + plan.frames as u64 * FRAME_SIZE,
        Ordering::Relaxed,
    );
    *FRAMES.lock() = Some(buddy);
}

/// SMEP, SMAP e UMIP: nome, se a CPU anuncia (CPUID.7.0) e o bit do CR4.
pub fn hardening_features() -> [(&'static str, bool, u64); 3] {
    let (ebx, ecx) = if cpu::max_leaf(false) >= 7 {
        let r = cpu::cpuid(7, 0);
        (r.ebx, r.ecx)
    } else {
        (0, 0)
    };
    [
        ("SMEP", ebx & (1 << 7) != 0, cpu::CR4_SMEP),
        ("SMAP", ebx & (1 << 20) != 0, cpu::CR4_SMAP),
        ("UMIP", ecx & (1 << 2) != 0, cpu::CR4_UMIP),
    ]
}

/// Liga SMEP, SMAP e UMIP conforme CPUID; confere NX e CR0.WP.
fn harden_cpu() {
    let mut cr4 = cpu::read_cr4();
    for (name, present, bit) in hardening_features() {
        if present {
            cr4 |= bit;
        } else {
            warn!("okernel: CPU sem {name}");
        }
    }
    // SAFETY: só liga proteções que a CPU anuncia; o kernel não tem páginas
    // de usuário nem usa as instruções que UMIP restringe no anel 3.
    unsafe { cpu::write_cr4(cr4) };
    cpu::SMAP_ENABLED.store(
        cr4 & cpu::CR4_SMAP != 0,
        core::sync::atomic::Ordering::Relaxed,
    );
    // SAFETY: EFER existe em toda CPU x86-64.
    let efer = unsafe { cpu::rdmsr(cpu::MSR_EFER) };
    let nx = efer & cpu::EFER_NXE != 0;
    let wp = cpu::read_cr0() & cpu::CR0_WP != 0;
    info!("okernel: CR4 {cr4:#x}; NX {nx}, CR0.WP {wp}");
}
