//! Caixa de pedidos entre CPUs (ADR 0031, item 5; T-322).
//!
//! Cada CPU tem uma [`Mailbox`]. Quem pede liga um bit em `pending` (e,
//! para função remota, preenche antes o pedido) e manda o IPI do vetor
//! correspondente; a CPU de destino atende com [`Mailbox::poll`] no
//! tratador do IPI e em toda espera ativa. O atendimento não toma trava,
//! não espera e não manda IPI, então pode rodar em qualquer espera, mesmo
//! com travas na mão.
//!
//! Função remota: uma por vez por destino. Quem pede toma o pedido
//! ([`Mailbox::claim_call`]), grava função e argumento, liga `CALL`
//! ([`Mailbox::post_call`]), espera [`Mailbox::call_done`] atendendo a
//! própria caixa e devolve o pedido ([`Mailbox::release_call`]).

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use crate::tlb;

/// Bit de `pending`: reavaliar quem roda (vetor `0xF0`).
pub const RESCHED: u32 = 1 << 0;
/// Bit de `pending`: função remota (vetor `0xF1`).
pub const CALL: u32 = 1 << 1;
/// Bit de `pending`: TLB shootdown (vetor `0xF2`, T-326).
pub const TLB: u32 = 1 << 2;

/// Função remota: roda na CPU de destino com o argumento do pedido. Não
/// toma trava, não espera e não manda IPI.
pub type RemoteFn = fn(u64);

/// Pedidos pendentes de uma CPU.
pub struct Mailbox {
    /// Resumo dos pedidos, lido numa só carga.
    pending: AtomicU32,
    /// Alguém é dono do pedido de função remota.
    call_busy: AtomicBool,
    /// Função (`RemoteFn` como ponteiro) e argumento do pedido.
    call_func: AtomicPtr<()>,
    call_arg: AtomicU64,
    /// O destino rodou a função do pedido atual.
    call_done: AtomicBool,
    /// Um `RESCHED` chegou e ainda não foi consumido (ADR 0032).
    need_resched: AtomicBool,
    /// Pedidos atendidos, por bit (estatística dos testes).
    handled: [AtomicU64; 3],
    /// Pedido de shootdown desta CPU para as outras (T-326).
    tlb_request: tlb::Request,
    /// CPUs com pedido de shootdown para esta.
    tlb_inbox: tlb::Inbox,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Mailbox {
    /// Caixa vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: AtomicU32::new(0),
            call_busy: AtomicBool::new(false),
            call_func: AtomicPtr::new(core::ptr::null_mut()),
            call_arg: AtomicU64::new(0),
            call_done: AtomicBool::new(false),
            need_resched: AtomicBool::new(false),
            handled: [const { AtomicU64::new(0) }; 3],
            tlb_request: tlb::Request::new(),
            tlb_inbox: tlb::Inbox::new(),
        }
    }

    /// O pedido de shootdown desta CPU (ela o preenche; os alvos o leem).
    pub const fn tlb_request(&self) -> &tlb::Request {
        &self.tlb_request
    }

    /// A caixa de entrada de shootdown desta CPU. Quem pede liga o próprio
    /// bit nela e depois `TLB` com [`post`](Self::post); o bit `TLB` que
    /// [`poll`](Self::poll) devolve manda esvaziá-la.
    pub const fn tlb_inbox(&self) -> &tlb::Inbox {
        &self.tlb_inbox
    }

    /// Liga `bits` (`RESCHED` ou `TLB`); quem chama manda o IPI depois.
    pub fn post(&self, bits: u32) {
        self.pending.fetch_or(bits, Ordering::Release);
    }

    /// Tenta tomar o pedido de função remota; `false` se outro o tem.
    pub fn claim_call(&self) -> bool {
        self.call_busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Preenche o pedido tomado com [`claim_call`](Self::claim_call) e
    /// liga `CALL`; quem chama manda o IPI depois.
    pub fn post_call(&self, func: RemoteFn, arg: u64) {
        self.call_func.store(func as *mut (), Ordering::Relaxed);
        self.call_arg.store(arg, Ordering::Relaxed);
        self.call_done.store(false, Ordering::Relaxed);
        self.pending.fetch_or(CALL, Ordering::Release);
    }

    /// O destino terminou a função do pedido.
    pub fn call_done(&self) -> bool {
        self.call_done.load(Ordering::Acquire)
    }

    /// Devolve o pedido (depois de [`call_done`](Self::call_done)).
    pub fn release_call(&self) {
        self.call_busy.store(false, Ordering::Release);
    }

    /// Atende os pedidos desta caixa (só a CPU dona a atende); devolve os
    /// bits atendidos. Sem pedido, custa uma carga.
    pub fn poll(&self) -> u32 {
        if self.pending.load(Ordering::Relaxed) == 0 {
            return 0;
        }
        let bits = self.pending.swap(0, Ordering::Acquire);
        if bits & CALL != 0 {
            let func = self.call_func.load(Ordering::Relaxed);
            let arg = self.call_arg.load(Ordering::Relaxed);
            if !func.is_null() {
                // SAFETY: só `post_call` grava `call_func`, sempre com uma
                // `RemoteFn` convertida em ponteiro; a conversão de volta
                // recupera a mesma função.
                let func = unsafe { core::mem::transmute::<*mut (), RemoteFn>(func) };
                func(arg);
            }
            self.call_done.store(true, Ordering::Release);
        }
        if bits & RESCHED != 0 {
            self.need_resched.store(true, Ordering::Release);
        }
        for (i, counter) in self.handled.iter().enumerate() {
            if bits & (1 << i) != 0 {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        bits
    }

    /// Consome o `RESCHED` pendente.
    pub fn take_resched(&self) -> bool {
        self.need_resched.swap(false, Ordering::AcqRel)
    }

    /// Há `RESCHED` pendente (sem consumir).
    pub fn resched_pending(&self) -> bool {
        self.need_resched.load(Ordering::Acquire)
    }

    /// Pedidos atendidos de cada tipo: `RESCHED`, `CALL`, `TLB`.
    pub fn handled(&self) -> [u64; 3] {
        [0, 1, 2].map(|i| self.handled[i].load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests;
