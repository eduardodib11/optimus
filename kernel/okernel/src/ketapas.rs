//! EXPERIMENTO da T-519 (não vai para a main): tempo por etapa do caminho
//! rápido de IPC e custo de instruções isoladas, medidos em KVM.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::{cpu, fpu};

pub static ON: AtomicBool = AtomicBool::new(false);
pub static NOFPU: AtomicBool = AtomicBool::new(false);
pub static NOFS: AtomicBool = AtomicBool::new(false);
pub const CR4_PCIDE: u64 = 1 << 17;

/// Liga ou desliga o PCID nesta CPU (só no experimento).
pub fn pcid(on: bool) -> bool {
    if cpu::cpuid(1, 0).ecx & (1 << 17) == 0 {
        return false;
    }
    let cr4 = cpu::read_cr4();
    unsafe {
        if on {
            cpu::write_cr3(cpu::read_cr3() & 0x000f_ffff_ffff_f000);
            cpu::write_cr4(cr4 | CR4_PCIDE);
        } else {
            cpu::write_cr3(cpu::read_cr3() & 0x000f_ffff_ffff_f000);
            cpu::write_cr4(cr4 & !CR4_PCIDE);
        }
    }
    true
}
const N: usize = 16;
pub static DIR: AtomicU64 = AtomicU64::new(0);
static LAST: AtomicU64 = AtomicU64::new(0);
static SUM: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static CNT: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];
static MINV: [AtomicU64; N] = [const { AtomicU64::new(u64::MAX) }; N];

/// Marca o fim da etapa `k` (o trecho desde a marca anterior).
#[inline(always)]
pub fn mark(k: usize) {
    if !ON.load(Ordering::Relaxed) {
        return;
    }
    let k = k + 8 * DIR.load(Ordering::Relaxed) as usize;
    let now = cpu::rdtsc_ordered();
    let d = now.wrapping_sub(LAST.load(Ordering::Relaxed));
    LAST.store(now, Ordering::Relaxed);
    if d < 50_000 && k < N {
        SUM[k].store(SUM[k].load(Ordering::Relaxed) + d, Ordering::Relaxed);
        CNT[k].store(CNT[k].load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        if d < MINV[k].load(Ordering::Relaxed) {
            MINV[k].store(d, Ordering::Relaxed);
        }
    }
}

pub fn start() {
    for k in 0..N {
        SUM[k].store(0, Ordering::Relaxed);
        CNT[k].store(0, Ordering::Relaxed);
        MINV[k].store(u64::MAX, Ordering::Relaxed);
    }
    LAST.store(cpu::rdtsc_ordered(), Ordering::Relaxed);
    ON.store(true, Ordering::Relaxed);
}

pub fn report() {
    ON.store(false, Ordering::Relaxed);
    for k in 0..N {
        let c = CNT[k].load(Ordering::Relaxed);
        if c > 0 {
            info!(
                "bench: etapa{k} n={c} media_ciclos={} min_ciclos={}",
                SUM[k].load(Ordering::Relaxed) / c,
                MINV[k].load(Ordering::Relaxed)
            );
        }
    }
}

/// Mediana, em ciclos, de 101 lotes de 64 execuções de `f` (por execução).
fn per_op(mut f: impl FnMut(u64)) -> u64 {
    let mut v = [0u64; 101];
    for slot in &mut v {
        let t0 = cpu::rdtsc_ordered();
        for i in 0..64 {
            f(i);
        }
        let t1 = cpu::rdtsc_ordered();
        *slot = (t1 - t0) / 64;
    }
    v.sort_unstable();
    v[50]
}

/// Custo de instruções isoladas; `roots` = dois CR3 que mapeiam o kernel.
pub fn costs(roots: [u64; 2]) {
    let vazio = per_op(|i| {
        core::hint::black_box(i);
    });
    let a = AtomicU64::new(0);
    let lock = per_op(|i| {
        a.fetch_add(core::hint::black_box(i), Ordering::AcqRel);
    });
    let tsc = per_op(|_| {
        core::hint::black_box(cpu::rdtsc_ordered());
    });
    // SAFETY: experimento; FS_BASE existe e o kernel não usa FS.
    let fs0 = unsafe { cpu::rdmsr(cpu::MSR_FS_BASE) };
    let rd = per_op(|_| {
        core::hint::black_box(unsafe { cpu::rdmsr(cpu::MSR_FS_BASE) });
    });
    let wr = per_op(|i| unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, 0x1000 * (i & 1)) });
    unsafe { cpu::wrmsr(cpu::MSR_FS_BASE, fs0) };
    let xgetbv = per_op(|_| {
        let (lo, hi): (u32, u32);
        unsafe { asm!("xgetbv", in("ecx") 1u32, out("eax") lo, out("edx") hi, options(nomem, nostack)) };
        core::hint::black_box((lo, hi));
    });
    // Duas áreas FPU, alternadas como numa troca.
    let bytes = fpu::area_bytes();
    let layout = alloc::alloc::Layout::from_size_align(bytes, 64).unwrap();
    let a1 = unsafe { alloc::alloc::alloc_zeroed(layout) };
    let a2 = unsafe { alloc::alloc::alloc_zeroed(layout) };
    unsafe { fpu::save(a1) };
    unsafe { fpu::save(a2) };
    let fpu_par = per_op(|i| unsafe {
        let (s, r) = if i & 1 == 0 { (a1, a2) } else { (a2, a1) };
        fpu::save(s);
        fpu::restore(r);
    });
    let so_xrstor = per_op(|_| unsafe { fpu::restore(a1) });
    unsafe {
        alloc::alloc::dealloc(a1, layout);
        alloc::alloc::dealloc(a2, layout);
    }
    let cr0 = cpu::read_cr3();
    let cr3 = per_op(|i| unsafe { cpu::write_cr3(roots[(i & 1) as usize]) });
    let cr3_igual = per_op(|_| unsafe { cpu::write_cr3(roots[0]) });
    let ler_cr3 = per_op(|_| {
        core::hint::black_box(cpu::read_cr3());
    });
    unsafe { cpu::write_cr3(cr0) };
    info!(
        "bench: custos vazio={vazio} lock_xadd={lock} lfence_rdtsc={tsc} rdmsr_fs={rd} wrmsr_fs={wr} xgetbv1={xgetbv} xsaveopt_xrstor={fpu_par} xrstor={so_xrstor} mov_cr3_alterna={cr3} mov_cr3_igual={cr3_igual} ler_cr3={ler_cr3} fpu_bytes={bytes} xcr0={:#x}",
        fpu::xcr0()
    );
}
