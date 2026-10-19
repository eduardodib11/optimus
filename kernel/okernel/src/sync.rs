//! Ticket spinlock com classe e verificação da ordem de travas (ADR 0031,
//! itens 1 a 4; SDD v1.0, seção 6.9).
//!
//! Cada [`SpinLock`] tem dois contadores, `next` e `serving`: quem chega
//! pega a próxima senha e gira até ela ser chamada, então quem pediu
//! primeiro entra primeiro (justiça FIFO) e a espera fica limitada a
//! (CPUs − 1) seções críticas. Só a dona grava `serving`, por isso soltar
//! é um `store` sem RMW.
//!
//! Toda trava pertence a uma [`LockClass`] com nível fixo. Em debug, o
//! kernel instala [`Hooks`] que dão a pilha de classes tomadas desta CPU
//! ([`HeldLocks`]); `lock` confere que a nova trava vem depois de todas
//! as que já estão na mão e que as interrupções estão desligadas, e acusa
//! pânico depois de [`SPIN_LIMIT`] voltas na mesma trava. Em release a
//! pilha não é consultada e a trava custa só os dois contadores. A cada
//! volta de espera, o gancho `relax` atende a caixa de IPIs da CPU (ADR
//! 0031, item 5).

use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::panic::Location;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicUsize, Ordering};

/// Classe de uma trava, na ordem global da ADR 0031 (item 3). Só se toma
/// uma trava de classe posterior às que já estão na mão; duas da mesma
/// classe só em [`LockClass::RunQueue`], em ordem crescente de chave (id
/// lógico da CPU).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LockClass {
    /// Sem classe: fora da verificação. Só as travas dos testes de host.
    Unchecked = 0,
    /// Nível 1: a trava global da árvore de derivação (ADR 0028).
    Cdt = 10,
    /// Nível 2: um `CapSpace` por vez.
    CapSpace = 20,
    /// Nível 3: filas de objetos (`Endpoint`, `Reply`, `Notification`,
    /// `Interrupt`, baldes de futex), `Thread.binding`, tabelas de IRQ.
    Object = 30,
    /// Nível 4: `Thread.ipc`, depois do objeto.
    IpcSlot = 40,
    /// Nível 5: um `AddressSpace` por vez.
    AddressSpace = 50,
    /// Nível 6: fila de prontas de uma CPU; duas só em ordem de id.
    RunQueue = 60,
    /// Nível 7: folha do escalonador (`Thread.sched`, com o
    /// `SchedContext` dela e o doado; orçamento do `SchedContext`).
    SchedLeaf = 70,
    /// Nível 8, primeira: as faixas de pilhas de kernel (`kvm`).
    KernelStacks = 80,
    /// Nível 8, depois: as tabelas de página do kernel (`kmem`).
    KernelPageTables = 81,
    /// Nível 9, primeira: o heap do kernel.
    Heap = 90,
    /// Nível 9, depois: o buddy de frames.
    Frames = 91,
    /// Nível 10: diagnóstico (registros dos testes, última falta), folha.
    Diagnostic = 100,
}

impl LockClass {
    /// Nível da ADR 0031 (1 a 10; 0 para [`LockClass::Unchecked`]).
    #[must_use]
    pub const fn level(self) -> u8 {
        (self as u8) / 10
    }

    /// Nome para as mensagens de violação.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unchecked => "Unchecked",
            Self::Cdt => "Cdt",
            Self::CapSpace => "CapSpace",
            Self::Object => "Objeto",
            Self::IpcSlot => "IpcSlot",
            Self::AddressSpace => "AddressSpace",
            Self::RunQueue => "Fila",
            Self::SchedLeaf => "FolhaSched",
            Self::KernelStacks => "TabelasKernel(pilhas)",
            Self::KernelPageTables => "TabelasKernel(PT)",
            Self::Heap => "Alocador(heap)",
            Self::Frames => "Alocador(frames)",
            Self::Diagnostic => "Diagnóstico",
        }
    }

    fn from_u8(value: u8) -> Self {
        [
            Self::Cdt,
            Self::CapSpace,
            Self::Object,
            Self::IpcSlot,
            Self::AddressSpace,
            Self::RunQueue,
            Self::SchedLeaf,
            Self::KernelStacks,
            Self::KernelPageTables,
            Self::Heap,
            Self::Frames,
            Self::Diagnostic,
        ]
        .into_iter()
        .find(|c| *c as u8 == value)
        .unwrap_or(Self::Unchecked)
    }
}

/// Pode tomar `next` (classe e chave) com `held` na mão?
#[must_use]
pub fn order_allows(held: (LockClass, u32), next: (LockClass, u32)) -> bool {
    let ((hc, hk), (nc, nk)) = (held, next);
    if hc == LockClass::Unchecked || nc == LockClass::Unchecked {
        return true;
    }
    (nc as u8) > (hc as u8) || (nc == LockClass::RunQueue && hc == nc && nk > hk)
}

/// Travas que uma CPU pode segurar ao mesmo tempo.
pub const MAX_HELD: usize = 16;

/// Voltas numa mesma trava antes de acusar provável deadlock (debug).
pub const SPIN_LIMIT: u64 = 100_000_000;

/// Uma violação da ordem: a trava que já estava na mão e a pedida.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Violation {
    /// Classe e chave da trava na mão.
    pub held: (LockClass, u32),
    /// Classe e chave da pedida.
    pub wanted: (LockClass, u32),
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}#{} antes de {}#{}",
            self.held.0.name(),
            self.held.1,
            self.wanted.0.name(),
            self.wanted.1
        )
    }
}

/// Uma trava na mão: endereço, classe, chave e onde foi tomada.
struct Held {
    lock: AtomicUsize,
    class: AtomicU8,
    key: AtomicU32,
    at: AtomicPtr<Location<'static>>,
}

impl Held {
    const fn new() -> Self {
        Self {
            lock: AtomicUsize::new(0),
            class: AtomicU8::new(0),
            key: AtomicU32::new(0),
            at: AtomicPtr::new(ptr::null_mut()),
        }
    }

    fn location(&self) -> Option<&'static Location<'static>> {
        // SAFETY: só `push` grava o campo, sempre com um `&'static Location`.
        unsafe { self.at.load(Ordering::Relaxed).as_ref() }
    }
}

/// Pilha de travas na mão de uma CPU (no kernel, dentro da `PerCpu`; nos
/// testes de host, uma por thread). Só a própria CPU mexe nela, com IF=0;
/// os campos são atômicos para a estrutura poder ser estática.
pub struct HeldLocks {
    depth: AtomicUsize,
    entries: [Held; MAX_HELD],
    /// Com `true`, uma violação é registrada em vez de virar pânico (testes
    /// do próprio mecanismo).
    catching: AtomicBool,
    caught: AtomicU32,
    caught_held: AtomicU32,
    caught_wanted: AtomicU32,
}

impl HeldLocks {
    /// Pilha vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            depth: AtomicUsize::new(0),
            entries: [const { Held::new() }; MAX_HELD],
            catching: AtomicBool::new(false),
            caught: AtomicU32::new(0),
            caught_held: AtomicU32::new(0),
            caught_wanted: AtomicU32::new(0),
        }
    }

    /// Travas classificadas na mão.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth.load(Ordering::Relaxed)
    }

    /// Confere a ordem de `wanted` contra todas as travas na mão.
    fn check(&self, wanted: (LockClass, u32), at: &'static Location<'static>) {
        for h in &self.entries[..self.depth()] {
            let held = (
                LockClass::from_u8(h.class.load(Ordering::Relaxed)),
                h.key.load(Ordering::Relaxed),
            );
            if order_allows(held, wanted) {
                continue;
            }
            if self.catching.load(Ordering::Relaxed) {
                let pack = |(c, k): (LockClass, u32)| (u32::from(c as u8) << 24) | (k & 0xff_ffff);
                self.caught_held.store(pack(held), Ordering::Relaxed);
                self.caught_wanted.store(pack(wanted), Ordering::Relaxed);
                self.caught.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let v = Violation { held, wanted };
            match h.location() {
                Some(l) => panic!("ordem de travas violada: {v} (tomada em {l}, pedida em {at})"),
                None => panic!("ordem de travas violada: {v} (pedida em {at})"),
            }
        }
    }

    fn push(&self, lock: usize, class: LockClass, key: u32, at: &'static Location<'static>) {
        let d = self.depth();
        assert!(d < MAX_HELD, "mais de {MAX_HELD} travas na mão (em {at})");
        let e = &self.entries[d];
        e.lock.store(lock, Ordering::Relaxed);
        e.class.store(class as u8, Ordering::Relaxed);
        e.key.store(key, Ordering::Relaxed);
        e.at.store(ptr::from_ref(at).cast_mut(), Ordering::Relaxed);
        self.depth.store(d + 1, Ordering::Relaxed);
    }

    /// Tira `lock` da pilha (a guarda pode ser solta fora de ordem).
    fn pop(&self, lock: usize) {
        let d = self.depth();
        let Some(i) = (0..d)
            .rev()
            .find(|&i| self.entries[i].lock.load(Ordering::Relaxed) == lock)
        else {
            return;
        };
        for j in i..d - 1 {
            let (to, from) = (&self.entries[j], &self.entries[j + 1]);
            to.lock
                .store(from.lock.load(Ordering::Relaxed), Ordering::Relaxed);
            to.class
                .store(from.class.load(Ordering::Relaxed), Ordering::Relaxed);
            to.key
                .store(from.key.load(Ordering::Relaxed), Ordering::Relaxed);
            to.at
                .store(from.at.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        self.depth.store(d - 1, Ordering::Relaxed);
    }

    /// Roda `f` registrando as violações de ordem em vez de entrar em
    /// pânico; devolve a primeira, se houver. Para os testes do mecanismo.
    pub fn catch_violation(&self, f: impl FnOnce()) -> Option<Violation> {
        self.caught.store(0, Ordering::Relaxed);
        self.catching.store(true, Ordering::Relaxed);
        f();
        self.catching.store(false, Ordering::Relaxed);
        if self.caught.load(Ordering::Relaxed) == 0 {
            return None;
        }
        let unpack = |v: u32| {
            #[allow(clippy::cast_possible_truncation, reason = "classe nos 8 bits altos")]
            let class = LockClass::from_u8((v >> 24) as u8);
            (class, v & 0xff_ffff)
        };
        Some(Violation {
            held: unpack(self.caught_held.load(Ordering::Relaxed)),
            wanted: unpack(self.caught_wanted.load(Ordering::Relaxed)),
        })
    }
}

impl Default for HeldLocks {
    fn default() -> Self {
        Self::new()
    }
}

/// O que a verificação pede ao ambiente (o kernel instala no boot).
pub struct Hooks {
    /// Pilha de travas desta CPU, ou `None` para não verificar.
    pub held: fn() -> Option<&'static HeldLocks>,
    /// Chamado a cada volta de espera (atende a caixa de IPIs).
    pub relax: fn(),
    /// As interrupções desta CPU estão ligadas?
    pub interrupts_enabled: fn() -> bool,
}

static HOOKS: AtomicPtr<Hooks> = AtomicPtr::new(ptr::null_mut());

/// Instala os ganchos (uma vez, no boot; nos testes de host, por processo).
pub fn install(hooks: &'static Hooks) {
    HOOKS.store(ptr::from_ref(hooks).cast_mut(), Ordering::Release);
}

#[inline]
fn hooks() -> Option<&'static Hooks> {
    // SAFETY: só `install` grava o ponteiro, sempre com um `&'static Hooks`.
    unsafe { HOOKS.load(Ordering::Acquire).as_ref() }
}

/// Travas classificadas na mão desta CPU (0 sem ganchos).
#[must_use]
pub fn held_count() -> usize {
    hooks().and_then(|h| (h.held)()).map_or(0, HeldLocks::depth)
}

/// Trava de exclusão mútua por senha (ticket), com classe na ordem global.
pub struct SpinLock<T> {
    next: AtomicU32,
    serving: AtomicU32,
    class: LockClass,
    /// Desempate entre travas da mesma classe (id da CPU nas filas).
    key: u32,
    value: UnsafeCell<T>,
}

// SAFETY: o valor só é acessado por quem segura a trava (um por vez), então
// compartilhar a trava entre threads só exige que `T` possa mudar de thread.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Trava livre com `value`, sem classe (fora da verificação). Só nos
    /// testes de host: toda trava do kernel tem classe (T-315).
    #[cfg(test)]
    pub const fn new(value: T) -> Self {
        Self::with_class(LockClass::Unchecked, value)
    }

    /// Trava livre da classe `class` com `value`.
    pub const fn with_class(class: LockClass, value: T) -> Self {
        Self::with_key(class, 0, value)
    }

    /// Trava livre da classe `class`, com chave de desempate `key`.
    pub const fn with_key(class: LockClass, key: u32, value: T) -> Self {
        Self {
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
            class,
            key,
            value: UnsafeCell::new(value),
        }
    }

    /// Classe da trava.
    pub const fn class(&self) -> LockClass {
        self.class
    }

    fn addr(&self) -> usize {
        ptr::from_ref(self).addr()
    }

    /// Pega uma senha e gira até ser atendido.
    ///
    /// # Panics
    ///
    /// Em debug, se a ordem de travas for violada, se as interrupções
    /// estiverem ligadas ou depois de [`SPIN_LIMIT`] voltas.
    #[track_caller]
    pub fn lock(&self) -> SpinGuard<'_, T> {
        let hooks = hooks();
        let at = Location::caller();
        let held = self.before_lock(hooks, at);
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        let mut spins: u64 = 0;
        while self.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
            if let Some(h) = hooks {
                (h.relax)();
            }
            spins += 1;
            assert!(
                !(cfg!(debug_assertions) && spins == SPIN_LIMIT),
                "provável deadlock na classe {} (pedida em {at})",
                self.class.name()
            );
        }
        self.acquired(held, at)
    }

    /// Toma a trava se ninguém a segura nem espera; nunca gira (pânico).
    #[track_caller]
    pub fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        let s = self.serving.load(Ordering::Acquire);
        self.next
            .compare_exchange(s, s.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let held = if cfg!(debug_assertions) && self.class != LockClass::Unchecked {
            hooks().and_then(|h| (h.held)())
        } else {
            None
        };
        Some(self.acquired(held, Location::caller()))
    }

    /// Verificações de debug antes de pegar a senha; devolve a pilha.
    fn before_lock(
        &self,
        hooks: Option<&'static Hooks>,
        at: &'static Location<'static>,
    ) -> Option<&'static HeldLocks> {
        if !cfg!(debug_assertions) || self.class == LockClass::Unchecked {
            return None;
        }
        let hooks = hooks?;
        assert!(
            !(hooks.interrupts_enabled)(),
            "trava {} tomada com interrupções ligadas (em {at})",
            self.class.name()
        );
        let held = (hooks.held)()?;
        held.check((self.class, self.key), at);
        Some(held)
    }

    fn acquired(
        &self,
        held: Option<&'static HeldLocks>,
        at: &'static Location<'static>,
    ) -> SpinGuard<'_, T> {
        let held = held.filter(|_| self.class != LockClass::Unchecked);
        if let Some(h) = held {
            h.push(self.addr(), self.class, self.key, at);
        }
        SpinGuard { lock: self, held }
    }

    /// Senhas tiradas e ainda não atendidas, contando a dona (testes).
    #[cfg(test)]
    fn queued(&self) -> u32 {
        self.next
            .load(Ordering::Relaxed)
            .wrapping_sub(self.serving.load(Ordering::Relaxed))
    }
}

/// Acesso exclusivo ao valor; solta a trava ao sair de escopo.
pub struct SpinGuard<'a, T> {
    lock: &'a SpinLock<T>,
    held: Option<&'static HeldLocks>,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: a guarda prova que esta é a única dona da trava.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: idem, e `&mut self` impede outro empréstimo pela guarda.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(h) = self.held {
            h.pop(self.lock.addr());
        }
        // Só a dona grava `serving`: a próxima senha é a seguinte à dela,
        // que é o valor atual mais um.
        let s = self.lock.serving.load(Ordering::Relaxed);
        self.lock
            .serving
            .store(s.wrapping_add(1), Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
