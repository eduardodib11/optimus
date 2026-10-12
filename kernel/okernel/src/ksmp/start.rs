//! Partida dos APs por INIT-SIPI-SIPI (ADR 0030, itens 2 e 3; T-318).
//!
//! O BSP liga os APs um por vez, reaproveitando a página de parâmetros do
//! trampolim. Para cada um: `PerCpu` nova do buddy (no mapa direto),
//! pilhas na janela por CPU, parâmetros, INIT, 10 ms, SIPI, 200 µs, um
//! segundo SIPI se o AP ainda não deu sinal, e espera de até 100 ms por
//! `PerCpu::online`. O AP que não responde leva outro INIT (volta a
//! esperar SIPI, sem rodar com parâmetros velhos) e fica fora, com aviso.
//!
//! Janela por CPU (`PERCPU_WINDOW`, 256 KiB cada): quatro pilhas de 16 KiB
//! (boot e ocioso, falta dupla, NMI e verificação de máquina), cada uma com
//! 16 KiB de guarda não mapeada abaixo. A metade alta do PML4 é a mesma em
//! todos os espaços, então a janela aparece em todos.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use kabi::MAX_CPUS;
use okernel::mm::paging::{Flags, PageSize};
use okernel::mm::{FRAME_SIZE, frames};

use crate::arch::x86_64::ap::Trampoline;
use crate::arch::x86_64::percpu::{self, PerCpu};
use crate::arch::x86_64::{apic, cpu, idt, syscall};
use crate::{bootinfo, kmem, ktime};

/// Início da janela de áreas e pilhas por CPU (seção 6.4).
pub const PERCPU_WINDOW: u64 = 0xffff_f000_0000_0000;
/// Bytes da janela de cada CPU.
const WINDOW_PER_CPU: u64 = 256 << 10;
/// Bytes de cada pilha (e de cada guarda).
const STACK: u64 = 16 << 10;
/// Pilhas por CPU: boot/ocioso, falta dupla, NMI e verificação de máquina.
const STACKS: u64 = 4;

const MS: u64 = 1_000_000;

/// `PerCpu` de cada CPU ligada, pelo id lógico (nula se desligada).
static PERCPUS: [AtomicPtr<PerCpu>; MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];
/// Máscara das CPUs ligadas (256 bits).
static ONLINE: [AtomicU64; MAX_CPUS / 64] = [const { AtomicU64::new(0) }; MAX_CPUS / 64];

/// Topo da pilha `j` (0 = boot/ocioso, 1 a 3 = ISTs) da CPU `cpu`.
pub fn stack_top(cpu: u32, j: u64) -> u64 {
    PERCPU_WINDOW + u64::from(cpu) * WINDOW_PER_CPU + (2 * j + 2) * STACK
}

/// Marca `cpu` ligada, com a área `p`.
fn mark_online(cpu: u32, p: &'static PerCpu) {
    let i = cpu as usize;
    PERCPUS[i].store(core::ptr::from_ref(p).cast_mut(), Ordering::Release);
    ONLINE[i / 64].fetch_or(1 << (i % 64), Ordering::SeqCst);
}

/// A CPU de id lógico `cpu` está ligada.
pub fn is_online(cpu: usize) -> bool {
    cpu < MAX_CPUS && ONLINE[cpu / 64].load(Ordering::Acquire) & (1 << (cpu % 64)) != 0
}

/// CPUs ligadas.
pub fn online_count() -> usize {
    ONLINE
        .iter()
        .map(|w| w.load(Ordering::Acquire).count_ones() as usize)
        .sum()
}

/// Mapeia as quatro pilhas da CPU `cpu` na janela.
fn map_stacks(cpu: u32) -> bool {
    for j in 0..STACKS {
        let top = stack_top(cpu, j);
        for page in (0..STACK / FRAME_SIZE).map(|i| top - STACK + i * FRAME_SIZE) {
            let Some(frame) = kmem::alloc_frames(0) else {
                return false;
            };
            if kmem::map(page, frame, PageSize::Size4K, Flags::RW).is_err() {
                kmem::free_frames(frame, 0);
                return false;
            }
        }
    }
    true
}

/// Uma `PerCpu` nova para `cpu`, do buddy, no mapa direto.
fn new_percpu(cpu: u32, apic_id: u32) -> Option<&'static PerCpu> {
    let pages = size_of::<PerCpu>().div_ceil(4096);
    let order = pages.next_power_of_two().trailing_zeros() as usize;
    let frame = kmem::alloc_frames(order)?;
    let p = kmem::direct(frame) as *mut PerCpu;
    // SAFETY: frames recém-saídos do buddy, só nossos, alinhados a 4 KiB
    // (o alinhamento da `PerCpu`) e com espaço para ela; nunca voltam ao
    // buddy, então a referência vive para sempre.
    unsafe {
        p.write(PerCpu::new(cpu));
        (*p).set_apic_id(apic_id);
        Some(&*p)
    }
}

/// Espera até `ns` do relógio, ou até `done()`; devolve `done()`.
fn wait_until(ns: u64, done: impl Fn() -> bool) -> bool {
    while ktime::now_ns() < ns {
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

/// Liga os APs da topologia, um por vez.
pub fn start_aps() {
    mark_online(0, percpu::bsp());
    let count = super::count();
    if count < 2 {
        return;
    }
    if ktime::tsc_hz() == 0 {
        warn!("okernel: sem relógio para a partida dos APs; só o BSP");
        return;
    }
    let Some(base) = bootinfo::get()
        .and_then(bootinfo::memory_map)
        .and_then(frames::trampoline_base)
    else {
        warn!("okernel: sem 24 KiB livres abaixo de 1 MiB para o trampolim; só o BSP");
        return;
    };
    let Some(root) = kmem::kernel_root() else {
        return;
    };
    // SAFETY: `trampoline_base` só devolve RAM usável abaixo de 1 MiB, que
    // o buddy não gerencia e nada mais usa; o mapa direto a cobre (RW), e
    // o PML4 do kernel está no mapa direto.
    let tramp = unsafe {
        Trampoline::install(
            base,
            kmem::direct_base(),
            root.0,
            kmem::direct(root) as *const u64,
        )
    };
    info!(
        "okernel: trampolim dos APs em {base:#x} (SIPI {:#x})",
        tramp.vector()
    );
    for cpu in 1..count {
        let Some(apic_id) = super::apic_id(cpu) else {
            break;
        };
        let cpu = u32::try_from(cpu).unwrap_or(u32::MAX);
        if !start_one(&tramp, cpu, apic_id) {
            warn!("okernel: cpu{cpu} (APIC {apic_id}) não respondeu; segue sem ela");
        }
    }
    info!("okernel: {} de {count} CPU(s) ligadas", online_count());
}

fn start_one(tramp: &Trampoline, cpu: u32, apic_id: u32) -> bool {
    if !map_stacks(cpu) {
        warn!("okernel: sem memória para as pilhas da cpu{cpu}");
        return false;
    }
    let Some(p) = new_percpu(cpu, apic_id) else {
        warn!("okernel: sem memória para a área da cpu{cpu}");
        return false;
    };
    for j in 1..STACKS {
        // SAFETY: a pilha acabou de ser mapeada (RW) e só esta CPU a usará.
        unsafe { percpu::prepare_ist(stack_top(cpu, j), p) };
    }
    tramp.set_params(stack_top(cpu, 0), core::ptr::from_ref(p).addr() as u64);
    apic::send_init(apic_id);
    let now = ktime::now_ns();
    wait_until(now + 10 * MS, || false);
    apic::send_sipi(apic_id, tramp.vector());
    if !wait_until(ktime::now_ns() + MS / 5, || p.online()) {
        apic::send_sipi(apic_id, tramp.vector());
    }
    if wait_until(ktime::now_ns() + 100 * MS, || p.online()) {
        mark_online(cpu, p);
        true
    } else {
        // Volta a esperar SIPI: nunca roda com os parâmetros do próximo.
        apic::send_init(apic_id);
        false
    }
}

/// Primeira função em Rust de um AP, chamada por `ap_entry64` na pilha de
/// boot dele, com interrupções desligadas e o CR3 do kernel.
#[unsafe(no_mangle)]
extern "sysv64" fn ap_main(p: &'static PerCpu) -> ! {
    let cpu = p.cpu_id();
    let tops = [1, 2, 3].map(|j| stack_top(cpu, j) - 16);
    // SAFETY: primeira coisa nesta CPU, com IF=0: a área e as pilhas são
    // só dela (preparadas pelo BSP); a GDT vem antes da IDT porque as
    // portas usam os seletores dela, e o GS antes de qualquer trava.
    unsafe {
        p.install(p.apic_id(), tops);
        idt::load();
        syscall::init();
    }
    let hw = cpu::apic_id();
    if hw != p.apic_id() {
        // Outra CPU acordou com estes parâmetros (não deveria): para sem
        // tocar em nada.
        crate::arch::x86_64::halt();
    }
    info!("okernel: cpu{cpu} online (APIC {hw})");
    p.set_online();
    // A inicialização completa e o laço ocioso vêm no T-319.
    crate::arch::x86_64::halt()
}
