//! TLB shootdown entre CPUs (ADR 0031, item 7; T-326), sem PCID.
//!
//! Sem PCID, trocar de `CR3` descarta as traduções do espaço anterior;
//! então só as CPUs com o `CR3` de um espaço carregado **agora** podem ter
//! traduções velhas dele. Cada CPU anota em [`LOADED`] a raiz que vai
//! carregar, com uma troca atômica (barreira completa) **antes** do
//! `mov cr3` ([`note_root`]). Quem muda um espaço troca as entradas,
//! invalida a própria TLB, faz `fence(SeqCst)` e lê [`LOADED`]: uma CPU
//! que carregou o espaço antes aparece ali e recebe o pedido; uma que
//! carregou depois já percorre as tabelas novas. A máscara `active` da ADR
//! fica assim espalhada, uma palavra por CPU.
//!
//! Pedidos do kernel (metade alta, [`KERNEL_ROOT`]) vão a toda CPU ligada.
//!
//! O protocolo (pedido de cada CPU, caixa de entrada com um bit por CPU que
//! pede) está em `okernel::tlb`; aqui ficam o IPI, a espera e a
//! invalidação. Quem pede espera as confirmações atendendo a própria caixa
//! (duas CPUs que pedem uma à outra não travam) e só então volta, para que
//! quem chamou libere frames e tabelas.

use core::sync::atomic::{AtomicU64, Ordering, fence};

use kabi::MAX_CPUS;
use okernel::ipi::TLB;
use okernel::tlb::{self, Flush, KERNEL_ROOT};

use crate::arch::x86_64::{apic, cpu, percpu};
use crate::ktime;

/// Bits do endereço físico do PML4 no CR3.
const CR3_ADDR: u64 = 0x000f_ffff_ffff_f000;
/// Prazo para todos os alvos confirmarem; no TCG uma vCPU pode ficar sem
/// rodar no host por mais que isso, então lá vale 1 s.
const TIMEOUT_NS: u64 = 100_000_000;
const TCG_TIMEOUT_NS: u64 = 1_000_000_000;

/// Raiz no CR3 de cada CPU ([`KERNEL_ROOT`] antes da primeira troca).
static LOADED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(KERNEL_ROOT) }; MAX_CPUS];

/// Esta CPU vai carregar `root` no CR3: chamar antes do `mov cr3`. A troca
/// atômica é a barreira que casa com a `fence` de quem pede.
pub fn note_root(root: u64) {
    if let Some(slot) = LOADED.get(percpu::cpu_id() as usize) {
        slot.swap(root & CR3_ADDR, Ordering::SeqCst);
    }
}

/// Invalida aqui o que o pedido manda, se ele vale para o CR3 desta CPU.
fn invalidate(root: u64, flush: Flush) {
    if !tlb::applies(root, cpu::read_cr3() & CR3_ADDR) {
        return;
    }
    match flush {
        Flush::Pages { start, pages } => {
            for i in 0..pages {
                cpu::invlpg(start + i * 4096);
            }
        }
        // As páginas do kernel podem ser globais: só desligar o PGE as tira.
        Flush::All if root == KERNEL_ROOT => cpu::flush_tlb_all(),
        Flush::All => cpu::flush_tlb(),
    }
}

/// Invalida as traduções de `flush` no espaço de raiz `root` (ou do
/// kernel, com [`KERNEL_ROOT`]) aqui e em toda outra CPU que as possa ter,
/// e só volta depois de todas confirmarem.
///
/// # Panics
///
/// Se um alvo não confirmar no prazo: ele está preso com IF=0 sem passar
/// por espera nenhuma, o que é bug do kernel.
pub fn flush(root: u64, flush: Flush) {
    let root = root & CR3_ADDR;
    invalidate(root, flush);
    let n = super::count().min(MAX_CPUS);
    if n < 2 {
        return;
    }
    let me = percpu::cpu_id() as usize;
    // Casa com a troca atômica de `note_root`: ou a CPU aparece aqui com a
    // raiz, ou já carregou o CR3 depois das entradas novas.
    fence(Ordering::SeqCst);
    let mut targets = [0u64; MAX_CPUS / 64];
    let mut count = 0;
    for c in (0..n).filter(|&c| c != me && super::start::is_online(c)) {
        if root == KERNEL_ROOT || LOADED[c].load(Ordering::SeqCst) == root {
            targets[c / 64] |= 1 << (c % 64);
            count += 1;
        }
    }
    if count == 0 {
        return;
    }
    let request = percpu::mailbox().tlb_request();
    request.post(root, flush, count);
    for c in (0..n).filter(|&c| targets[c / 64] & (1 << (c % 64)) != 0) {
        let Some(p) = super::start::percpu_of(c) else {
            request.ack();
            continue;
        };
        p.mailbox().tlb_inbox().signal(me);
        p.mailbox().post(TLB);
        apic::send_ipi(p.apic_id(), apic::TLB_VECTOR);
    }
    let limit = if cpu::under_tcg() {
        TCG_TIMEOUT_NS
    } else {
        TIMEOUT_NS
    };
    let deadline = ktime::now_ns() + limit;
    while !request.done() {
        super::ipi::poll();
        core::hint::spin_loop();
        if ktime::now_ns() >= deadline {
            laggards(me, &targets, n);
            panic!(
                "{} CPU(s) não confirmaram o shootdown em {} ms",
                request.pending(),
                limit / 1_000_000
            );
        }
    }
}

/// Diagnóstico do pânico por prazo: para cada alvo, se o pedido ainda está
/// na caixa dele (nunca atendido) e a raiz que ele tem carregada.
fn laggards(me: usize, targets: &[u64; MAX_CPUS / 64], n: usize) {
    for c in (0..n).filter(|&c| targets[c / 64] & (1 << (c % 64)) != 0) {
        if let Some(p) = super::start::percpu_of(c) {
            error!(
                "okernel: shootdown de cpu{me}: cpu{c} pedido na caixa {}, raiz carregada {:#x}",
                p.mailbox().tlb_inbox().signaled(me),
                LOADED[c].load(Ordering::Relaxed)
            );
        }
    }
}

/// Atende os pedidos de shootdown para esta CPU (de `ipi::poll`): não toma
/// trava, não espera e não manda IPI.
pub fn serve() {
    percpu::mailbox().tlb_inbox().drain(&mut |from| {
        if let Some(p) = super::start::percpu_of(from) {
            let request = p.mailbox().tlb_request();
            let (root, flush) = request.read();
            invalidate(root, flush);
            request.ack();
        }
    });
}
