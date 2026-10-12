//! Testes de kernel do TLB shootdown (T-326): depois de `vm_unmap` ou de
//! trocar um mapeamento, nenhuma outra CPU usa a tradução velha.

use core::sync::atomic::{AtomicU64, Ordering};

use kabi::fault::PAGE_FAULT;
use kabi::vm::{PAGE_SIZE, WRITE};
use kabi::{Handle, ObjectType};
use okernel::cap::Cap;
use okernel::fault::Kill;
use okernel::mm::paging::{Flags, PageSize};
use okernel::vm::{vm_map, vm_unmap};

use super::super::{UserEntry, start_on};
use super::smp::{gone, option, wait_for};
use super::{DATA_VA, Process, cap, delete, process, settled, thread, user_symbol};
use crate::kcap::root_quota;
use crate::ktest::Outcome;
use crate::{kfault, kmem, ksmp, ktime};

unsafe extern "C" {
    static user_tlb_spin: u8;
    static user_tlb_reader: u8;
}

/// Página RW de controle, comum ao kernel (pelo mapa direto) e à leitora.
const SHARED_VA: u64 = 0x60_0000;
/// Página que a leitora lê e o kernel desmapeia ou troca.
const TARGET_VA: u64 = 0x70_0000;
/// Página do kernel trocada no teste da metade alta, na faixa de objetos
/// do kernel, ao lado da de `kmem::tests`.
const KERNEL_VA: u64 = 0xffff_c0ff_ff10_0000;
/// Rodadas sem `smp.shootdown`. O aceite do T-326 pede 10⁵, que `cargo
/// xtask test smp` roda num boot de release à parte.
const DEFAULT_ROUNDS: u64 = 10_000;
/// Rodadas do teste da metade alta, por CPU.
const KERNEL_ROUNDS: u64 = 1_000;
/// Leituras da leitora por rodada (`user_tlb_reader`).
const READS_PER_ROUND: u64 = 64;
/// Marcas das duas páginas que se alternam no mesmo endereço.
const TAGS: [u64; 2] = [0x0a0a_0a0a_0a0a_0a0a, 0x0b0b_0b0b_0b0b_0b0b];
const MS: u64 = 1_000_000;

/// Palavras da página de controle de `user_tlb_reader`.
const GO: usize = 0;
const ACK: usize = 1;
const EXPECT: usize = 2;
const STALE: usize = 3;
const READS: usize = 4;
const STOP: usize = 5;

/// Um `MemoryObject` de uma página de um processo de teste, visto pelo
/// kernel pelo mapa direto.
struct Page {
    handle: Handle,
    cap: Cap,
    base: u64,
}

impl Page {
    /// Cria a página em `p` (zerada).
    fn new(p: &Process) -> Result<Self, &'static str> {
        let handle = p
            .cspace
            .lock()
            .obj_create(p.quota, ObjectType::MemoryObject, PAGE_SIZE)
            .map_err(|_| "obj_create(MemoryObject)")?;
        let cap = cap(&p.cspace, handle)?;
        let frame = cap
            .object
            .as_memory_object()
            .map_err(|_| "tipo")?
            .frame(0)
            .ok_or("frame")?;
        Ok(Self {
            handle,
            cap,
            base: kmem::direct(frame),
        })
    }

    /// A palavra `i` da página.
    fn word(&self, i: usize) -> &AtomicU64 {
        assert!(i < 512);
        // SAFETY: o frame é do MemoryObject que `self.cap` mantém vivo; no
        // mapa direto, alinhado a 4 KiB, e só se acessa como atômicos (o
        // usuário que o mapeia também é parte do teste).
        unsafe { &*(self.base as *const AtomicU64).add(i) }
    }
}

/// Com uma só CPU não há outra para avisar.
fn other_cpus() -> Option<usize> {
    let n = ksmp::start::online_count();
    if n < 2 {
        info!("ktest: · só uma CPU; nada a derrubar");
        None
    } else {
        Some(n)
    }
}

/// Gira (sem `hlt`, atendendo IPIs) até `done()` ou `limit_ns`: a outra
/// ponta é uma leitora que gira numa CPU dela.
fn spin_until(limit_ns: u64, done: impl Fn() -> bool) -> bool {
    let give_up = ktime::now_ns() + limit_ns;
    while !done() {
        if ktime::now_ns() > give_up {
            return false;
        }
        ksmp::ipi::poll();
        core::hint::spin_loop();
    }
    true
}

/// Aceite do T-326: uma thread em cada outra CPU lê sem parar uma página;
/// o BSP faz `vm_unmap` e, na volta, a leitora já não pode ler: falta na
/// próxima leitura (no máximo uma leitura conta depois da volta, a que já
/// tinha passado pela TLB quando o IPI chegou).
pub fn unmap_faz_faltar() -> Outcome {
    let Some(n) = other_cpus() else {
        return Ok(());
    };
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    for cpu in 1..n {
        unmap_em(u32::try_from(cpu).map_err(|_| "id")?)?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Uma rodada de [`unmap_faz_faltar`] com a leitora na CPU `cpu`.
fn unmap_em(cpu: u32) -> Outcome {
    let p = process(1)?;
    let control = Page::new(&p)?;
    let target = Page::new(&p)?;
    target.word(0).store(TAGS[0], Ordering::Relaxed);
    ensure!(vm_map(&p.aspace, &control.cap, SHARED_VA, 0, PAGE_SIZE, WRITE).is_ok());
    ensure!(vm_map(&p.aspace, &target.cap, TARGET_VA, 0, PAGE_SIZE, 0).is_ok());
    let (handle, t) = thread(&p)?;
    let e = UserEntry {
        rip: user_symbol(&raw const user_tlb_spin),
        rsp: DATA_VA + PAGE_SIZE,
        args: [TARGET_VA, SHARED_VA, 0],
    };
    ensure!(start_on(&t, &e, cpu).is_ok());
    let reads = control.word(0);
    ensure!(wait_for(1_000 * MS, || reads.load(Ordering::Relaxed) >= 1_000));
    let before = kfault::killed();
    ensure!(vm_unmap(&p.aspace, TARGET_VA, PAGE_SIZE).is_ok());
    let at_return = reads.load(Ordering::Relaxed);
    ensure!(wait_for(1_000 * MS, || gone(&t)));
    let total = reads.load(Ordering::Relaxed);
    info!(
        "ktest: · cpu{cpu}: {at_return} leituras até a volta do vm_unmap, {} depois",
        total - at_return
    );
    ensure!(total <= at_return + 1);
    ensure!(control.word(1).load(Ordering::Relaxed) == TAGS[0]);
    ensure!(t.cpu() == cpu);
    ensure!(kfault::killed() == before + 1);
    let report = kfault::last().ok_or("sem relatório de falta")?;
    ensure!(report.thread == alloc::sync::Arc::as_ptr(&t).addr());
    ensure!(report.kill == Kill::NoHandler);
    ensure!(report.fault.vector == PAGE_FAULT && report.fault.addr == TARGET_VA);
    // Falta de página ausente (bit P do código de erro desligado).
    ensure!(report.fault.error & 1 == 0);
    drop(t);
    delete(&p, &[handle, control.handle, target.handle])
}

/// Aceite do T-326: a leitora numa outra CPU lê uma página que o BSP, a
/// cada rodada, desmapeia e troca pela outra de duas (marcas distintas) no
/// mesmo endereço; entre rodadas a tradução velha fica na TLB dela, e
/// nenhuma leitura pode dar a marca da página anterior.
pub fn sem_traducao_velha() -> Outcome {
    let Some(n) = other_cpus() else {
        return Ok(());
    };
    let cpu = u32::try_from(n - 1).map_err(|_| "id")?;
    let rounds = option("smp.shootdown", DEFAULT_ROUNDS);
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let p = process(1)?;
        let control = Page::new(&p)?;
        let pages = [Page::new(&p)?, Page::new(&p)?];
        for (page, tag) in pages.iter().zip(TAGS) {
            page.word(0).store(tag, Ordering::Relaxed);
        }
        ensure!(vm_map(&p.aspace, &control.cap, SHARED_VA, 0, PAGE_SIZE, WRITE).is_ok());
        ensure!(vm_map(&p.aspace, &pages[0].cap, TARGET_VA, 0, PAGE_SIZE, 0).is_ok());
        control.word(EXPECT).store(TAGS[0], Ordering::Relaxed);
        control.word(GO).store(1, Ordering::Release);
        let (handle, t) = thread(&p)?;
        let entry = UserEntry {
            rip: user_symbol(&raw const user_tlb_reader),
            rsp: DATA_VA + PAGE_SIZE,
            args: [TARGET_VA, SHARED_VA, 0],
        };
        let t0 = ktime::now_ns();
        ensure!(start_on(&t, &entry, cpu).is_ok());
        for round in 1..=rounds {
            let ack = control.word(ACK);
            ensure!(spin_until(1_000 * MS, || ack.load(Ordering::Acquire) == round));
            let next = usize::from(round % 2 == 1);
            ensure!(vm_unmap(&p.aspace, TARGET_VA, PAGE_SIZE).is_ok());
            ensure!(vm_map(&p.aspace, &pages[next].cap, TARGET_VA, 0, PAGE_SIZE, 0).is_ok());
            control.word(EXPECT).store(TAGS[next], Ordering::Relaxed);
            control.word(GO).store(round + 1, Ordering::Release);
        }
        let ack = control.word(ACK);
        ensure!(spin_until(1_000 * MS, || ack.load(Ordering::Acquire) == rounds + 1));
        let ns = ktime::now_ns() - t0;
        control.word(STOP).store(1, Ordering::Release);
        ensure!(wait_for(1_000 * MS, || gone(&t)));
        let stale = control.word(STALE).load(Ordering::Relaxed);
        let reads = control.word(READS).load(Ordering::Relaxed);
        info!(
            "ktest: · cpu{cpu}: {rounds} trocas em {} ms ({} ns cada), {reads} leituras, \
             {stale} com a tradução velha",
            ns / MS,
            ns / rounds.max(1)
        );
        ensure!(stale == 0);
        ensure!(reads == (rounds + 1) * READS_PER_ROUND);
        ensure!(t.cpu() == cpu);
        drop(t);
        let [first, second] = pages;
        delete(&p, &[handle, control.handle, first.handle, second.handle])?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

/// Última leitura de [`read_kernel_word`], de outra CPU.
static SEEN: AtomicU64 = AtomicU64::new(0);

/// Função remota: lê a palavra do kernel em `va`.
fn read_kernel_word(va: u64) {
    // SAFETY: o teste mantém `va` mapeada (RW, metade alta) enquanto
    // espera a função remota terminar.
    let word = unsafe { core::ptr::read_volatile(va as *const u64) };
    SEEN.store(word, Ordering::Release);
}

/// Metade alta: cada outra CPU lê uma página do kernel (global, então a
/// troca de `CR3` não a tira da TLB) que o BSP troca pela outra de duas a
/// cada rodada; toda leitura tem de ver a página nova.
pub fn kernel_sem_traducao_velha() -> Outcome {
    let Some(n) = other_cpus() else {
        return Ok(());
    };
    let frames = [
        kmem::alloc_frames(0).ok_or("sem frame")?,
        kmem::alloc_frames(0).ok_or("sem frame")?,
    ];
    for (&frame, tag) in frames.iter().zip(TAGS) {
        // SAFETY: frame recém-saído do buddy, só nosso, no mapa direto.
        unsafe { core::ptr::write_volatile(kmem::direct(frame) as *mut u64, tag) };
    }
    let mut result = Ok(());
    let mut current = 0;
    if kmem::map(KERNEL_VA, frames[0], PageSize::Size4K, Flags::RW).is_err() {
        result = Err("map");
    }
    'rounds: for _ in 0..KERNEL_ROUNDS {
        if result.is_err() {
            break;
        }
        for cpu in 1..n {
            if !ksmp::ipi::call_on(cpu, read_kernel_word, KERNEL_VA) {
                result = Err("CPU desligada");
                break 'rounds;
            }
            if SEEN.load(Ordering::Acquire) != TAGS[current] {
                result = Err("outra CPU leu a página do kernel pela tradução velha");
                break 'rounds;
            }
        }
        if !matches!(kmem::unmap(KERNEL_VA, PageSize::Size4K), Ok(f) if f == frames[current]) {
            result = Err("unmap");
            break;
        }
        current ^= 1;
        if kmem::map(KERNEL_VA, frames[current], PageSize::Size4K, Flags::RW).is_err() {
            result = Err("map");
        }
    }
    let _ = kmem::unmap(KERNEL_VA, PageSize::Size4K);
    for frame in frames {
        kmem::free_frames(frame, 0);
    }
    if result.is_ok() {
        info!(
            "ktest: · {KERNEL_ROUNDS} trocas de página do kernel lidas por {} CPU(s)",
            n - 1
        );
    }
    result
}
