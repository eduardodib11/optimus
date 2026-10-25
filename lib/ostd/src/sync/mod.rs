//! Sincronização sobre `futex_wait` e `futex_wake` (T-336; ADR 0039, item 6):
//! [`Mutex`], [`Condvar`], [`Once`], [`OnceLock`] e [`RwLock`], com a forma da
//! `std`.
//!
//! Todas as travas são uma ou duas palavras de 32 bits atômicas; o kernel
//! confere a palavra com a trava do balde na mão (`futex.rs`), então nenhum
//! despertar se perde entre o teste e a espera. As esperas
//! comuns são sem prazo (o `futex_wait` do kernel não tem tempo-limite), e um
//! `futex_wait` que o kernel recusa por a palavra já ter mudado volta
//! como um despertar espúrio: todo laço relê a palavra.
//!
//! **Prazos (T-338).** [`Condvar::wait_timeout`] e companhia não esperam no
//! futex: a thread espera na `Notification` dela (com o `Timer` da thread
//! armado no prazo; ver [`crate::time`]) e fica numa lista do `Condvar`;
//! `notify_one`/`notify_all` acordam também os que estão nela. Mutex com
//! prazo (`lock_timeout`) não existe: o `unlock` teria de conhecer os
//! esperadores com prazo, e o caminho rápido dele hoje é um `swap`.
//!
//! **Envenenamento: não há.** O perfil do `ostd` é `panic = abort` (ADR 0039,
//! item 5): um pânico encerra o processo, nenhuma guarda é largada no meio
//! de um pânico e nenhum outro código vê um dado pela metade. Por isso
//! `lock`, `read` e `write` devolvem a guarda direto, sem `Result`.
//!
//! **Escolhas.** [`Mutex`]: as três posições clássicas (0 livre, 1 tomada,
//! 2 tomada com espera), com `futex_wake` só quando há quem espere.
//! [`RwLock`]: prefere escritores (um escritor à espera impede leitores
//! novos, então não passam fome; leitores só passam fome se escritores se
//! sucederem sem folga). [`Condvar`]: contador de sequência; `wait` lê o
//! contador antes de soltar o `Mutex`, então um `notify` depois disso muda o
//! contador e a espera não bloqueia: nenhum sinal se perde. Despertares
//! espúrios são permitidos, como na `std`; use `wait_while` ou um laço.
//!
//! # Unsafe
//!
//! Só o necessário para guardar o dado dentro da trava: o acesso ao
//! `UnsafeCell` nas guardas (só existe uma guarda de escrita, ou só guardas
//! de leitura, de cada vez, pelo protocolo da palavra atômica) e os `unsafe
//! impl Send`/`Sync` que isso exige. O teto está em `unsafe-allowlist.toml`.

#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

use alloc_crate::vec::Vec;
use kabi::{Handle, Syscall};

use crate::sys::syscall;
use crate::time::{self, EVENT};

/// Espera enquanto `word` valer `expected` (ou até um despertar espúrio).
fn futex_wait(word: &AtomicU32, expected: u32) {
    let addr = core::ptr::from_ref(word).addr() as u64;
    let _ = syscall(Syscall::FutexWait, [addr, u64::from(expected), 0, 0, 0, 0]);
}

/// Acorda até `n` threads esperando em `word`.
fn futex_wake(word: &AtomicU32, n: u64) {
    let addr = core::ptr::from_ref(word).addr() as u64;
    let _ = syscall(Syscall::FutexWake, [addr, n, 0, 0, 0, 0]);
}

const WAKE_ALL: u64 = u32::MAX as u64;

// ---------------------------------------------------------------- Mutex

const FREE: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;

/// Exclusão mútua que guarda um `T`.
pub struct Mutex<T> {
    state: AtomicU32,
    data: UnsafeCell<T>,
}

// SAFETY: o `Mutex` entrega `&mut T` a uma thread de cada vez, então basta
// `T: Send` (mesma regra da `std`).
unsafe impl<T: Send> Send for Mutex<T> {}
// SAFETY: idem; o acesso compartilhado ao `T` passa sempre pela trava.
unsafe impl<T: Send> Sync for Mutex<T> {}

/// Guarda de um [`Mutex`] tomado; solta a trava ao ser largada.
pub struct MutexGuard<'a, T> {
    lock: &'a Mutex<T>,
    /// Não é `Send`, como na `std`.
    _not_send: PhantomData<*const ()>,
}

// SAFETY: a guarda só dá `&T` (ou `&mut T` exclusivo), como `&mut T`.
unsafe impl<T: Sync> Sync for MutexGuard<'_, T> {}

impl<T> Mutex<T> {
    /// Trava livre com `value` dentro.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(FREE),
            data: UnsafeCell::new(value),
        }
    }

    fn guard(&self) -> MutexGuard<'_, T> {
        MutexGuard {
            lock: self,
            _not_send: PhantomData,
        }
    }

    /// Toma a trava, esperando se preciso.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        if self
            .state
            .compare_exchange(FREE, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            self.lock_contended();
        }
        self.guard()
    }

    #[cold]
    fn lock_contended(&self) {
        // Gira um pouco antes de dormir: as seções críticas são curtas.
        for _ in 0..100 {
            if self.state.load(Ordering::Relaxed) == FREE
                && self
                    .state
                    .compare_exchange(FREE, LOCKED, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return;
            }
            core::hint::spin_loop();
        }
        // Daqui em diante marca CONTENDED: quem solta acorda uma thread.
        while self.state.swap(CONTENDED, Ordering::Acquire) != FREE {
            futex_wait(&self.state, CONTENDED);
        }
    }

    /// Toma a trava se estiver livre.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.state
            .compare_exchange(FREE, LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| self.guard())
    }

    /// Acesso exclusivo sem tomar a trava (o `&mut self` já o garante).
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Devolve o dado.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }

    fn unlock(&self) {
        if self.state.swap(FREE, Ordering::Release) == CONTENDED {
            futex_wake(&self.state, 1);
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: a guarda existe, logo a trava é desta thread.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: a trava é desta thread e `&mut self` é exclusivo.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

// -------------------------------------------------------------- Condvar

/// Variável de condição para usar com [`Mutex`].
pub struct Condvar {
    /// Contador de sequência: cada `notify` o incrementa.
    seq: AtomicU32,
    /// `Notification`s das threads em espera com prazo (só dentro do
    /// processo: os handles valem na tabela dele).
    timed: Mutex<Vec<Handle>>,
    /// Tamanho de `timed`, para o `notify` sem esperas com prazo não tomar
    /// a trava.
    timed_len: AtomicU32,
}

/// Resultado de uma espera com prazo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitTimeoutResult(bool);

impl WaitTimeoutResult {
    /// O prazo venceu sem que um `notify` acordasse a espera.
    #[must_use]
    pub const fn timed_out(self) -> bool {
        self.0
    }
}

impl Condvar {
    /// Variável sem esperas.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            timed: Mutex::new(Vec::new()),
            timed_len: AtomicU32::new(0),
        }
    }

    /// Solta a trava de `guard`, espera um `notify` e toma a trava de novo.
    /// Pode voltar sem `notify` algum (despertar espúrio): confira a
    /// condição num laço, ou use [`Condvar::wait_while`].
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        // Lê o contador com a trava ainda tomada: um `notify` depois disto
        // muda o contador, e o `futex_wait` recusa a espera.
        let seq = self.seq.load(Ordering::Relaxed);
        let lock = guard.lock;
        drop(guard);
        futex_wait(&self.seq, seq);
        lock.lock()
    }

    /// Espera enquanto `condition` der `true`.
    pub fn wait_while<'a, T, F>(
        &self,
        mut guard: MutexGuard<'a, T>,
        mut condition: F,
    ) -> MutexGuard<'a, T>
    where
        F: FnMut(&mut T) -> bool,
    {
        while condition(&mut guard) {
            guard = self.wait(guard);
        }
        guard
    }

    /// Como [`wait`](Self::wait), com prazo: volta, com a trava tomada, num
    /// `notify`, no fim de `dur` (o resultado diz `timed_out`) ou por um
    /// despertar espúrio (que não conta como prazo vencido). Um `notify`
    /// que chega junto com o prazo vale como `notify` (`timed_out` falso).
    pub fn wait_timeout<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        dur: Duration,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult) {
        let deadline = (time::Instant::now() + dur).as_ns();
        self.wait_until(guard, deadline)
    }

    /// Espera enquanto `condition` der `true`, até `dur` no total. O
    /// resultado diz `timed_out` se a condição ainda valia no fim do prazo.
    pub fn wait_timeout_while<'a, T, F>(
        &self,
        mut guard: MutexGuard<'a, T>,
        dur: Duration,
        mut condition: F,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult)
    where
        F: FnMut(&mut T) -> bool,
    {
        let deadline = (time::Instant::now() + dur).as_ns();
        loop {
            if !condition(&mut guard) {
                return (guard, WaitTimeoutResult(false));
            }
            if time::now_ns() >= deadline {
                return (guard, WaitTimeoutResult(true));
            }
            guard = self.wait_until(guard, deadline).0;
        }
    }

    /// Uma espera com prazo absoluto `deadline` (ns do relógio do kernel).
    fn wait_until<'a, T>(
        &self,
        guard: MutexGuard<'a, T>,
        deadline: u64,
    ) -> (MutexGuard<'a, T>, WaitTimeoutResult) {
        let seq = self.seq.load(Ordering::Relaxed);
        let lock = guard.lock;
        // Entra na lista e arma o `Timer` com a trava do usuário ainda
        // tomada: um `notify` depois disto acha a thread na lista.
        let waiter = time::waiter().filter(|w| {
            if !self.register(w.ntfy) {
                return false;
            }
            if w.arm(deadline) {
                return true;
            }
            self.deregister(w.ntfy);
            false
        });
        drop(guard);
        let timed_out = match waiter {
            Some(w) => self.block_timed(w, deadline),
            None => {
                // Plano B sem objetos: cede a vez até o contador mudar.
                loop {
                    if self.seq.load(Ordering::Acquire) != seq {
                        break false;
                    }
                    if time::now_ns() >= deadline {
                        break true;
                    }
                    crate::thread::yield_now();
                }
            }
        };
        (lock.lock(), WaitTimeoutResult(timed_out))
    }

    /// Espera na `Notification` da thread por `EVENT` ou pelo prazo.
    fn block_timed(&self, w: time::Waiter, deadline: u64) -> bool {
        let mut timed_out = false;
        loop {
            let bits = w.wait();
            if bits & EVENT != 0 {
                break;
            }
            if time::now_ns() >= deadline {
                timed_out = true;
                break;
            }
            // Bit velho do `Timer` (ou espera recusada): espera de novo.
            if bits == 0 {
                crate::thread::yield_now();
            }
        }
        w.disarm();
        // Quem já não está na lista foi acordado por um `notify` (que
        // sinaliza com a trava da lista na mão): o sinal já chegou, e
        // vale mais que o prazo.
        if !self.deregister(w.ntfy) {
            timed_out = false;
        }
        w.drain();
        timed_out
    }

    /// Põe `h` na lista das esperas com prazo; `false` sem memória.
    fn register(&self, h: Handle) -> bool {
        let mut list = self.timed.lock();
        if list.try_reserve(1).is_err() {
            return false;
        }
        list.push(h);
        self.timed_len.store(
            u32::try_from(list.len()).unwrap_or(u32::MAX),
            Ordering::SeqCst,
        );
        true
    }

    /// Tira `h` da lista; `false` se um `notify` já o tinha tirado.
    fn deregister(&self, h: Handle) -> bool {
        let mut list = self.timed.lock();
        let found = list.iter().position(|x| *x == h).map(|i| list.remove(i));
        self.timed_len.store(
            u32::try_from(list.len()).unwrap_or(u32::MAX),
            Ordering::SeqCst,
        );
        found.is_some()
    }

    /// Acorda até `n` esperas com prazo (as mais antigas primeiro).
    fn wake_timed(&self, n: usize) {
        if self.timed_len.load(Ordering::SeqCst) == 0 {
            return;
        }
        let mut list = self.timed.lock();
        let k = n.min(list.len());
        for h in list.drain(..k) {
            let _ = crate::cap::ntfy_signal(h, EVENT);
        }
        self.timed_len.store(
            u32::try_from(list.len()).unwrap_or(u32::MAX),
            Ordering::SeqCst,
        );
    }

    /// Acorda uma thread esperando (e uma das com prazo, se houver: uma
    /// espera que vence junto com o `notify` não pode perdê-lo; o excesso
    /// é um despertar espúrio).
    pub fn notify_one(&self) {
        self.seq.fetch_add(1, Ordering::SeqCst);
        futex_wake(&self.seq, 1);
        self.wake_timed(1);
    }

    /// Acorda todas as threads esperando.
    pub fn notify_all(&self) {
        self.seq.fetch_add(1, Ordering::SeqCst);
        futex_wake(&self.seq, WAKE_ALL);
        self.wake_timed(usize::MAX);
    }
}

impl Default for Condvar {
    fn default() -> Self {
        Self::new()
    }
}

// ----------------------------------------------------------------- Once

const INCOMPLETE: u32 = 0;
const RUNNING: u32 = 1;
const COMPLETE: u32 = 2;

/// Executa uma inicialização uma única vez.
pub struct Once {
    state: AtomicU32,
}

impl Once {
    /// Ainda não executada.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(INCOMPLETE),
        }
    }

    /// A inicialização já terminou.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == COMPLETE
    }

    /// Roda `f` na primeira chamada; as outras esperam que ela termine.
    pub fn call_once<F: FnOnce()>(&self, f: F) {
        if self.is_completed() {
            return;
        }
        loop {
            match self.state.compare_exchange(
                INCOMPLETE,
                RUNNING,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    f();
                    self.state.store(COMPLETE, Ordering::Release);
                    futex_wake(&self.state, WAKE_ALL);
                    return;
                }
                Err(COMPLETE) => return,
                Err(_) => futex_wait(&self.state, RUNNING),
            }
        }
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

/// Célula que recebe o valor uma só vez.
pub struct OnceLock<T> {
    once: Once,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: o valor é escrito uma vez, por uma thread, antes de `once` ficar
// completa (Release) e só é lido depois (Acquire); como `Mutex`/`Arc`.
unsafe impl<T: Send + Sync> Sync for OnceLock<T> {}
// SAFETY: a célula leva o `T` junto.
unsafe impl<T: Send> Send for OnceLock<T> {}

impl<T> OnceLock<T> {
    /// Célula vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            once: Once::new(),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// O valor, se já foi definido.
    pub fn get(&self) -> Option<&T> {
        if self.once.is_completed() {
            // SAFETY: completa significa que o valor foi escrito e nunca
            // mais muda.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }

    /// O valor, calculando-o com `f` na primeira chamada (uma só `f` roda).
    pub fn get_or_init<F: FnOnce() -> T>(&self, f: F) -> &T {
        self.once.call_once(|| {
            // SAFETY: só quem está dentro de `call_once` escreve, uma vez.
            unsafe { (*self.value.get()).write(f()) };
        });
        // SAFETY: `call_once` voltou, então o valor está escrito.
        unsafe { (*self.value.get()).assume_init_ref() }
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for OnceLock<T> {
    fn drop(&mut self) {
        if self.once.is_completed() {
            // SAFETY: escrito e, com `&mut self`, ninguém mais o vê.
            unsafe { self.value.get_mut().assume_init_drop() };
        }
    }
}

// --------------------------------------------------------------- RwLock

/// Bits 0 a 29: leitores; bit 30: escritor; bit 31: há escritor esperando.
const READERS: u32 = (1 << 30) - 1;
const WRITER: u32 = 1 << 30;
const WRITER_WAITING: u32 = 1 << 31;

/// Trava de leitura e escrita que guarda um `T`; prefere escritores.
pub struct RwLock<T> {
    state: AtomicU32,
    data: UnsafeCell<T>,
}

// SAFETY: como `std::sync::RwLock`: escrita exclusiva exige `T: Send`.
unsafe impl<T: Send> Send for RwLock<T> {}
// SAFETY: leitores simultâneos veem `&T` (`Sync`) e o escritor leva `&mut T`
// entre threads (`Send`).
unsafe impl<T: Send + Sync> Sync for RwLock<T> {}

/// Guarda de leitura.
pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
    _not_send: PhantomData<*const ()>,
}

/// Guarda de escrita.
pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
    _not_send: PhantomData<*const ()>,
}

// SAFETY: a guarda de leitura só dá `&T`.
unsafe impl<T: Sync> Sync for RwLockReadGuard<'_, T> {}
// SAFETY: a guarda de escrita dá `&mut T` apenas a quem a tem.
unsafe impl<T: Sync> Sync for RwLockWriteGuard<'_, T> {}

impl<T> RwLock<T> {
    /// Trava livre com `value` dentro.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            data: UnsafeCell::new(value),
        }
    }

    /// Toma para leitura; espera se há escritor ativo ou esperando.
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & (WRITER | WRITER_WAITING) != 0 {
                futex_wait(&self.state, s);
            } else if self
                .state
                .compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return RwLockReadGuard {
                    lock: self,
                    _not_send: PhantomData,
                };
            }
        }
    }

    /// Toma para escrita; espera os leitores e o escritor ativo.
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & (READERS | WRITER) == 0 {
                // Ao tomar, apaga a marca de espera; os outros escritores
                // esperando a repõem ao acordar e não conseguir.
                if self
                    .state
                    .compare_exchange_weak(s, WRITER, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return RwLockWriteGuard {
                        lock: self,
                        _not_send: PhantomData,
                    };
                }
            } else {
                let marked = s | WRITER_WAITING;
                if s == marked
                    || self
                        .state
                        .compare_exchange_weak(s, marked, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                {
                    futex_wait(&self.state, marked);
                }
            }
        }
    }

    /// Acesso exclusivo sem tomar a trava.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Devolve o dado.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: há um leitor contado e nenhum escritor pode entrar.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        let prev = self.lock.state.fetch_sub(1, Ordering::Release);
        // O último leitor acorda o escritor que espera.
        if prev & READERS == 1 && prev & WRITER_WAITING != 0 {
            futex_wake(&self.lock.state, WAKE_ALL);
        }
    }
}

impl<T> Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: o escritor é exclusivo.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: o escritor é exclusivo e `&mut self` também.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        // Solta o bit de escritor, mantendo a marca de escritores esperando.
        self.lock.state.fetch_and(!WRITER, Ordering::Release);
        futex_wake(&self.lock.state, WAKE_ALL);
    }
}
