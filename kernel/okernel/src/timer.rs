//! Objeto `Timer` e fila de timers por CPU (T-349; ADR 0035, item 6; ADR
//! 0031, emenda da classe `FilaTimers`).
//!
//! Um [`Timer`] é um prazo ligado a bits de uma `Notification`: armado por
//! `obj_bind_notify(timer, ntfy, bits, prazo, período, flags)`, ele entra na
//! fila da CPU que armou (a **dona**), ordenada por prazo, e o tratador do
//! timer dessa CPU o tira de lá quando vence ([`TimerQueues::expire`]) e
//! sinaliza os bits. Disparo único deixa o `Timer` desarmado; o periódico
//! volta à fila no primeiro múltiplo do período depois de agora (atrasos de
//! mais de um período coalescem num sinal só).
//!
//! **Nós intrusivos.** A fila é uma lista duplamente encadeada cujos elos
//! moram dentro de cada `Timer`: armar, rearmar, desarmar e disparar nunca
//! alocam. O `Timer` vive num `Pin<Arc<_>>` (o `Object::Timer` do
//! `CapSpace`) e é `!Unpin`, então não se move enquanto está ligado; ao
//! morrer (última capability apagada), o `Drop` o tira da fila antes de a
//! memória voltar ao heap. A fila não guarda referência contada: um `Timer`
//! armado não impede a destruição, e a cota volta inteira.
//!
//! **Travas.** O estado do `Timer` (prazo, período, ligação e elos) é
//! protegido **só** pela trava da fila da CPU dona (`Timer::cpu`, classe
//! [`LockClass::TimerQueue`], folha): o tratador não toma a trava do objeto
//! e não inverte a ordem objeto → fila. Quem segura a fila só mexe nos
//! elos, copia ou tira a ligação e solta; a `Notification` é sinalizada (e a
//! referência a ela, solta) só depois.
//!
//! **CPU dona.** É a que armou por último. Armar de outra CPU toma a fila da
//! dona, tira o `Timer` de lá, marca a dona como [`MOVING`] e solta; grava o
//! estado novo, toma a fila desta CPU, liga o `Timer` e grava a dona nova
//! com essa trava na mão. Nunca há duas filas de timers na mão. Quem acha
//! [`MOVING`] (outro `obj_bind_notify` concorrente sobre o mesmo `Timer`)
//! espera sem trava nenhuma, atendendo IPIs; o `Drop` nunca o acha, porque
//! quem migra segura uma referência. O tratador só vê os `Timer`s da
//! própria fila e nunca um em migração. Desarmar de outra CPU só toma a fila
//! da dona.
//!
//! **Disparo concorrente.** Um disparo que já tirou o `Timer` da fila (com a
//! trava) acontece antes de um rearme ou de um desarme que chegue depois
//! nela: a sinalização desse disparo pode chegar à `Notification` logo
//! depois de o rearme ou o desarme voltar (o bit é idempotente; quem precisa
//! distinguir confere o relógio).
//!
//! # Unsafe
//!
//! O estado mora numa `UnsafeCell` e os elos são ponteiros crus para outros
//! `Timer`s. Todo acesso a eles acontece com a trava da fila da dona na mão
//! (ou, durante a migração, por quem marcou [`MOVING`], com o `Timer` fora
//! de toda fila), e todo `Timer` ligado está vivo e fixo: o `Drop` o
//! desliga sob a mesma trava antes de a memória ser liberada.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use kabi::timer::{ALL_FLAGS, MIN_PERIOD_NS, RELATIVE};
use kabi::{Error, MAX_CPUS};

use crate::cap::object::object_bytes;
use crate::cap::{Charge, MemoryQuota};
use crate::notify::Notification;
use crate::sync::{self, LockClass, SpinGuard, SpinLock};

/// O que um disparo sinaliza: a notificação e a máscara de bits.
pub type Binding = (Arc<Notification>, u64);

/// Dona de um `Timer` em migração (ver a documentação do módulo).
pub const MOVING: u32 = u32::MAX;

/// Prazo de [`TimerQueues::first`] numa fila vazia.
pub const NO_DEADLINE: u64 = u64::MAX;

/// Os argumentos de `obj_bind_notify` de um `Timer` (ADR 0035, item 6):
/// `Some((prazo absoluto, período))` arma, `None` desarma (`bits = 0` ou
/// `prazo = 0`, com ou sem [`RELATIVE`]). Prazo relativo soma `now`
/// (saturando: um prazo além do fim do relógio nunca vence).
///
/// # Errors
///
/// [`Error::InvalidArgument`] para flags desconhecidas ou período não zero
/// abaixo de [`MIN_PERIOD_NS`] (também ao desarmar).
pub fn parse(
    now: u64,
    bits: u64,
    deadline: u64,
    period: u64,
    flags: u64,
) -> Result<Option<(u64, u64)>, Error> {
    if flags & !ALL_FLAGS != 0 || (period != 0 && period < MIN_PERIOD_NS) {
        return Err(Error::InvalidArgument);
    }
    if bits == 0 || deadline == 0 {
        return Ok(None);
    }
    let at = if flags & RELATIVE != 0 {
        now.saturating_add(deadline)
    } else {
        deadline
    };
    Ok(Some((at, period)))
}

/// Próximo prazo de um periódico que venceu em `deadline` (≤ `now`): o
/// primeiro `deadline + k × period` depois de `now` (coalescência).
#[must_use]
pub fn next_after(deadline: u64, period: u64, now: u64) -> u64 {
    let late = now.saturating_sub(deadline);
    let k = late / period.max(1) + 1;
    deadline.saturating_add(k.saturating_mul(period))
}

/// Lista de `Timer`s armados de uma CPU, em ordem de prazo (FIFO entre
/// prazos iguais).
struct List {
    head: *const Timer,
    tail: *const Timer,
    len: usize,
}

// SAFETY: os ponteiros só são seguidos com a trava da fila na mão, que
// serializa o acesso entre CPUs; os `Timer`s apontados são `Sync`.
unsafe impl Send for List {}

/// Fila de uma CPU: a lista sob a trava e o primeiro prazo, para o
/// escalonador ler sem a trava.
struct Queue {
    list: SpinLock<List>,
    first: AtomicU64,
}

/// As filas de timers de todas as CPUs (o kernel tem uma estática,
/// [`QUEUES`]; os testes de host criam as suas).
pub struct TimerQueues {
    cpus: [Queue; MAX_CPUS],
}

/// As filas do kernel.
pub static QUEUES: TimerQueues = TimerQueues::new();

impl Default for TimerQueues {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerQueues {
    /// Filas vazias; a chave da trava de cada uma é o id da CPU.
    #[must_use]
    pub const fn new() -> Self {
        let mut cpus = [const {
            Queue {
                list: SpinLock::with_class(
                    LockClass::TimerQueue,
                    List {
                        head: ptr::null(),
                        tail: ptr::null(),
                        len: 0,
                    },
                ),
                first: AtomicU64::new(NO_DEADLINE),
            }
        }; MAX_CPUS];
        let mut i = 0;
        while i < MAX_CPUS {
            #[allow(clippy::cast_possible_truncation, reason = "MAX_CPUS cabe em u32")]
            let key = i as u32;
            cpus[i].list = SpinLock::with_key(
                LockClass::TimerQueue,
                key,
                List {
                    head: ptr::null(),
                    tail: ptr::null(),
                    len: 0,
                },
            );
            i += 1;
        }
        Self { cpus }
    }

    fn queue(&self, cpu: u32) -> &Queue {
        &self.cpus[cpu as usize % MAX_CPUS]
    }

    #[track_caller]
    fn lock(&self, cpu: u32) -> Locked<'_> {
        let q = self.queue(cpu);
        Locked {
            cpu,
            list: q.list.lock(),
            first: &q.first,
        }
    }

    /// Prazo do primeiro `Timer` da fila da CPU `cpu` ([`NO_DEADLINE`] sem
    /// nenhum), lido sem a trava: o escalonador o soma ao próximo evento do
    /// timer de hardware.
    #[must_use]
    pub fn first(&self, cpu: u32) -> u64 {
        self.queue(cpu).first.load(Ordering::Acquire)
    }

    /// `Timer`s armados na fila da CPU `cpu`.
    #[must_use]
    pub fn len(&self, cpu: u32) -> usize {
        self.lock(cpu).list.len
    }

    /// A fila da CPU `cpu` está vazia.
    #[must_use]
    pub fn is_empty(&self, cpu: u32) -> bool {
        self.len(cpu) == 0
    }

    /// Prazos da fila da CPU `cpu`, na ordem (testes).
    pub fn deadlines(&self, cpu: u32, out: &mut [u64]) -> usize {
        let q = self.lock(cpu);
        let mut at = q.list.head;
        let mut n = 0;
        while !at.is_null() && n < out.len() {
            // SAFETY: `at` está ligado nesta fila, cuja trava está na mão.
            let s = unsafe { &*state(at) };
            out[n] = s.deadline;
            n += 1;
            at = s.next;
        }
        n
    }

    /// Disparo na CPU `cpu`: tira da fila o primeiro `Timer` vencido em
    /// `now` e devolve o que sinalizar (com o prazo que venceu). O periódico
    /// volta à fila com o próximo prazo depois de `now`; o único fica
    /// desarmado e entrega a própria ligação. Quem chama sinaliza sem
    /// trava nenhuma e chama de novo até `None` (com o mesmo `now`, a
    /// repetição termina: nada volta à fila com prazo ≤ `now`).
    pub fn expire(&self, cpu: u32, now: u64) -> Option<Fired> {
        let mut q = self.lock(cpu);
        let head = q.list.head;
        if head.is_null() {
            return None;
        }
        // SAFETY: `head` está ligado nesta fila, cuja trava está na mão; nada
        // mais o acessa enquanto ela estiver.
        unsafe {
            let s = state(head);
            let deadline = (*s).deadline;
            if deadline > now {
                return None;
            }
            q.remove(head);
            let binding = if (*s).period == 0 {
                (*s).deadline = 0;
                (*s).binding.take()
            } else {
                (*s).deadline = next_after(deadline, (*s).period, now);
                q.insert(head);
                (*s).binding.clone()
            };
            q.refresh();
            drop(q);
            binding.map(|binding| Fired { binding, deadline })
        }
    }
}

/// Um disparo de [`TimerQueues::expire`].
pub struct Fired {
    /// O que sinalizar.
    pub binding: Binding,
    /// O prazo que venceu.
    pub deadline: u64,
}

/// A fila de uma CPU com a trava na mão.
struct Locked<'q> {
    cpu: u32,
    list: SpinGuard<'q, List>,
    first: &'q AtomicU64,
}

/// O estado de `t`.
///
/// # Safety
///
/// `t` aponta para um `Timer` vivo. Ler ou gravar pelo ponteiro devolvido
/// exige a trava da fila da dona dele (ou ser quem o marcou [`MOVING`]).
unsafe fn state(t: *const Timer) -> *mut State {
    // SAFETY: `t` é válido (contrato); `raw_get` não cria referência.
    unsafe { UnsafeCell::raw_get(&raw const (*t).state) }
}

impl Locked<'_> {
    /// Liga `t` na posição do prazo dele (depois dos de prazo menor ou
    /// igual), procurando a partir do fim: prazos que crescem, o caso
    /// comum, entram em tempo constante.
    ///
    /// # Safety
    ///
    /// `t` é um `Timer` vivo e fixo, fora de toda fila, cuja dona é esta
    /// fila (ou que quem chama marcou [`MOVING`] e vai entregar a ela).
    unsafe fn insert(&mut self, t: *const Timer) {
        // SAFETY: `t` e os `Timer`s ligados nesta lista estão vivos e são
        // protegidos pela trava desta fila, que está na mão.
        unsafe {
            let s = state(t);
            let d = (*s).deadline;
            let mut after = self.list.tail;
            while !after.is_null() && (*state(after)).deadline > d {
                after = (*state(after)).prev;
            }
            let next = if after.is_null() {
                self.list.head
            } else {
                (*state(after)).next
            };
            (*s).prev = after;
            (*s).next = next;
            if after.is_null() {
                self.list.head = t;
            } else {
                (*state(after)).next = t;
            }
            if next.is_null() {
                self.list.tail = t;
            } else {
                (*state(next)).prev = t;
            }
        }
        self.list.len += 1;
    }

    /// Desliga `t`.
    ///
    /// # Safety
    ///
    /// `t` está ligado nesta lista.
    unsafe fn remove(&mut self, t: *const Timer) {
        // SAFETY: `t` e os vizinhos estão ligados nesta lista, protegida pela
        // trava na mão.
        unsafe {
            let s = state(t);
            let (prev, next) = ((*s).prev, (*s).next);
            if prev.is_null() {
                self.list.head = next;
            } else {
                (*state(prev)).next = next;
            }
            if next.is_null() {
                self.list.tail = prev;
            } else {
                (*state(next)).prev = prev;
            }
            (*s).prev = ptr::null();
            (*s).next = ptr::null();
        }
        self.list.len -= 1;
    }

    /// Publica o prazo do primeiro.
    fn refresh(&self) {
        let head = self.list.head;
        let first = if head.is_null() {
            NO_DEADLINE
        } else {
            // SAFETY: `head` está ligado nesta lista, com a trava na mão.
            unsafe { (*state(head)).deadline }
        };
        self.first.store(first, Ordering::Release);
    }

    /// Grava o arme em `t` (fora de toda fila) e o liga se ele fica armado.
    /// Devolve o que sinalizar já: prazo vencido. O único vencido fica
    /// desarmado e entrega a ligação; o periódico vencido entra com o
    /// próximo prazo.
    ///
    /// # Safety
    ///
    /// Os de [`Self::insert`].
    unsafe fn place(&mut self, t: *const Timer, arm: Arm) -> Option<Binding> {
        let Arm {
            now,
            deadline,
            period,
            binding,
            ..
        } = arm;
        // SAFETY: `t` é desta fila (ou marcado `MOVING` por quem chama) e
        // está fora de toda lista.
        unsafe {
            let s = state(t);
            let fire = if deadline > now {
                (*s).deadline = deadline;
                None
            } else if period == 0 {
                (*s).deadline = 0;
                (*s).period = 0;
                return Some(binding);
            } else {
                (*s).deadline = next_after(deadline, period, now);
                Some(binding.clone())
            };
            (*s).period = period;
            (*s).binding = Some(binding);
            self.insert(t);
            fire
        }
    }
}

/// Estado de um `Timer`, sob a trava da fila da dona.
struct State {
    /// Prazo; zero se desarmado. Armado ⇔ ligado na fila da dona ⇔ com
    /// ligação.
    deadline: u64,
    period: u64,
    binding: Option<Binding>,
    prev: *const Timer,
    next: *const Timer,
}

/// Prazo ligável a bits de uma `Notification` (`ObjectType::Timer`).
pub struct Timer {
    _charge: Charge,
    queues: &'static TimerQueues,
    /// CPU dona (a da fila cuja trava protege `state`) ou [`MOVING`].
    cpu: AtomicU32,
    state: UnsafeCell<State>,
    /// Ligado numa fila, o `Timer` não pode mudar de endereço: só vive
    /// em `Pin` (e `&mut Timer` não vale como exclusivo, ver o `Drop`).
    _pin: PhantomPinned,
}

// SAFETY: o estado só é acessado com a trava da fila da dona na mão (ou,
// em migração, só por quem marcou `MOVING`); os demais campos são
// imutáveis ou atômicos.
unsafe impl Send for Timer {}
// SAFETY: idem.
unsafe impl Sync for Timer {}

impl fmt::Debug for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timer(cpu {})", self.cpu.load(Ordering::Relaxed))
    }
}

/// Um pedido de arme (de [`parse`]).
pub struct Arm {
    /// CPU de quem arma: a dona nova.
    pub cpu: u32,
    /// Agora, no relógio.
    pub now: u64,
    /// Prazo absoluto (não zero).
    pub deadline: u64,
    /// Período (0 = único; senão ≥ [`MIN_PERIOD_NS`]).
    pub period: u64,
    /// O que sinalizar.
    pub binding: Binding,
}

/// Resultado de [`Timer::arm`]; quem recebe solta tudo sem trava.
pub struct Armed {
    /// Prazo vencido: sinalizar já.
    pub fire: Option<Binding>,
    /// A fila desta CPU ganhou um primeiro prazo mais cedo: o timer de
    /// hardware precisa ser armado até ele.
    pub earlier: Option<u64>,
    /// A ligação do arme anterior.
    pub old: Option<Binding>,
}

impl Timer {
    /// `Timer` desarmado, cobrado de `quota`, com as filas `queues`.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem cota.
    pub fn new(quota: &Arc<MemoryQuota>, queues: &'static TimerQueues) -> Result<Self, Error> {
        Ok(Self {
            _charge: quota.charge(object_bytes::<Self>())?,
            queues,
            cpu: AtomicU32::new(0),
            state: UnsafeCell::new(State {
                deadline: 0,
                period: 0,
                binding: None,
                prev: ptr::null(),
                next: ptr::null(),
            }),
            _pin: PhantomPinned,
        })
    }

    /// A fila da dona com a trava na mão (conferida depois de tomada: a dona
    /// pode ter mudado no meio). Em migração, espera sem trava.
    fn lock_owner(&self) -> Locked<'static> {
        loop {
            let cpu = self.cpu.load(Ordering::Acquire);
            if cpu == MOVING {
                sync::relax();
                continue;
            }
            let q = self.queues.lock(cpu);
            if self.cpu.load(Ordering::Acquire) == cpu {
                return q;
            }
        }
    }

    /// CPU dona (a última que armou; 0 se nunca armado).
    #[must_use]
    pub fn owner(&self) -> u32 {
        let q = self.lock_owner();
        q.cpu
    }

    /// Prazo e período, se armado.
    #[must_use]
    pub fn armed(&self) -> Option<(u64, u64)> {
        let q = self.lock_owner();
        // SAFETY: a trava da dona está na mão.
        let s = unsafe { &*state(self) };
        let armed = (s.deadline != 0).then_some((s.deadline, s.period));
        drop(q);
        armed
    }

    /// Arma (ou rearma) com `arm`: o `Timer` sai da fila em que estiver e
    /// entra na da CPU de quem arma, ou dispara já se o prazo venceu.
    #[must_use]
    pub fn arm(self: Pin<&Self>, arm: Arm) -> Armed {
        let this: &Self = self.get_ref();
        let t = ptr::from_ref(this);
        let me = arm.cpu;
        let mut q = this.lock_owner();
        // SAFETY: a trava da dona está na mão.
        let linked = unsafe { (*state(t)).deadline != 0 };
        let mut old = None;
        if linked {
            // SAFETY: armado ⇔ ligado na fila da dona, que está na mão.
            unsafe {
                q.remove(t);
                (*state(t)).deadline = 0;
                old = (*state(t)).binding.take();
            }
            q.refresh();
        }
        let stays = q.cpu == me || (arm.deadline <= arm.now && arm.period == 0);
        let mut q = if stays {
            q
        } else {
            // Migração: ninguém mais acessa o estado até a dona nova.
            this.cpu.store(MOVING, Ordering::Release);
            drop(q);
            this.queues.lock(me)
        };
        let before = q.first.load(Ordering::Relaxed);
        // SAFETY: o `Timer` está fora de toda fila e é desta (`stays`) ou
        // marcado `MOVING` por esta chamada.
        let fire = unsafe { q.place(t, arm) };
        q.refresh();
        if !stays {
            this.cpu.store(me, Ordering::Release);
        }
        let after = q.first.load(Ordering::Relaxed);
        let local = q.cpu == me;
        drop(q);
        Armed {
            fire,
            earlier: (local && after < before).then_some(after),
            old,
        }
    }

    /// Desarma: sai da fila da dona (de qualquer CPU) e devolve a ligação,
    /// para quem chama soltar sem trava.
    pub fn disarm(&self) -> Option<Binding> {
        let t = ptr::from_ref(self);
        let mut q = self.lock_owner();
        // SAFETY: a trava da dona está na mão; armado ⇔ ligado nela.
        let old = unsafe {
            if (*state(t)).deadline == 0 {
                None
            } else {
                q.remove(t);
                (*state(t)).deadline = 0;
                (*state(t)).period = 0;
                (*state(t)).binding.take()
            }
        };
        q.refresh();
        drop(q);
        old
    }
}

impl Drop for Timer {
    /// A última capability sumiu: sai da fila antes de a memória ser
    /// liberada (ADR 0035, item 6). A ligação é solta depois da trava.
    ///
    /// `&mut self` aqui não exclui os outros acessos ao estado (o tratador
    /// de outra CPU pode estar lendo os elos pela lista): o `Timer` é
    /// `!Unpin`, e só `disarm`, com `&self` e a trava da dona, o toca.
    fn drop(&mut self) {
        let old = self.disarm();
        drop(old);
    }
}

#[cfg(test)]
mod tests;
