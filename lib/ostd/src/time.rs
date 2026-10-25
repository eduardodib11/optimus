//! Tempo (T-338; ADR 0035, item 6; ADR 0039): [`Instant`], [`Duration`] e
//! [`sleep`] sobre `clock_get` e o objeto `Timer` do kernel.
//!
//! O relógio é o monotônico do kernel em ns ([`now_ns`]), o mesmo dos
//! prazos de IPC e dos `Timer`s. [`Duration`] é a do `core`.
//!
//! **Um `Timer` e uma `Notification` por thread.** [`sleep`] e os prazos
//! das esperas (`Condvar::wait_timeout`, `JoinHandle::join_timeout`) não
//! criam objetos por chamada: cada thread guarda um par (`Timer`,
//! `Notification`) no seu bloco (`thread_local!`), criado na primeira
//! espera com prazo, cobrado da cota do processo e devolvido quando a
//! thread sai. Uma thread encerrada à força (`kill`) não roda destrutores,
//! então o par dela fica até o fim do processo. Sem cota para o par (ou
//! antes de `rt::init`), as esperas caem num laço de `yield_now` até o
//! prazo: correto, mas gasta CPU.
//!
//! **Bits.** O `Timer` sinaliza [`TIMER`] na notificação da thread; as
//! primitivas de sync usam [`EVENT`] (despertar pelo `notify`) e [`DEATH`]
//! (fim da thread). Um disparo que o kernel já tinha começado a entregar
//! pode chegar depois de o `Timer` ser desarmado (ADR 0035, notas da
//! T-349), então nenhuma espera confia no bit sozinho: confere o relógio
//! ([`now_ns`] contra o prazo) ou o estado (o registro de morte) e, se foi
//! um bit velho, espera de novo.

use core::cell::Cell;
use core::ops::{Add, AddAssign, Sub, SubAssign};

pub use core::time::Duration;

use kabi::{Handle, ObjectType};

use crate::cap;

/// Relógio monotônico em ns (`clock_get`).
#[must_use]
pub fn now_ns() -> u64 {
    crate::sys::syscall(kabi::Syscall::ClockGet, [0; 6]).map_or(0, |v| v[0])
}

/// `d` em ns, saturando em `u64::MAX` (cerca de 584 anos).
fn ns_of(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// Um instante do relógio monotônico, como o `Instant` da `std`. Não volta
/// atrás (o relógio do kernel é monotônico entre CPUs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// O instante de agora.
    #[must_use]
    pub fn now() -> Self {
        Self(now_ns())
    }

    /// O instante `ns` do relógio do kernel (o mesmo que [`now_ns`] daria
    /// então), por exemplo um prazo para `ipc` ou `arm_timer`.
    #[must_use]
    pub const fn from_ns(ns: u64) -> Self {
        Self(ns)
    }

    /// Este instante em ns do relógio do kernel.
    #[must_use]
    pub const fn as_ns(self) -> u64 {
        self.0
    }

    /// O tempo desde `earlier`, ou `None` se `earlier` é posterior.
    #[must_use]
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }

    /// O tempo desde `earlier`, ou zero se `earlier` é posterior.
    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    /// Como [`saturating_duration_since`](Self::saturating_duration_since)
    /// (a `std` tem esta forma; aqui também nunca entra em pânico).
    #[must_use]
    pub fn duration_since(self, earlier: Self) -> Duration {
        self.saturating_duration_since(earlier)
    }

    /// O tempo passado desde este instante.
    #[must_use]
    pub fn elapsed(self) -> Duration {
        Self::now().saturating_duration_since(self)
    }

    /// Este instante mais `d`, ou `None` se estoura o relógio.
    #[must_use]
    pub fn checked_add(self, d: Duration) -> Option<Self> {
        let ns = u64::try_from(d.as_nanos()).ok()?;
        self.0.checked_add(ns).map(Self)
    }

    /// Este instante menos `d`, ou `None` se passa de zero.
    #[must_use]
    pub fn checked_sub(self, d: Duration) -> Option<Self> {
        let ns = u64::try_from(d.as_nanos()).ok()?;
        self.0.checked_sub(ns).map(Self)
    }
}

impl Add<Duration> for Instant {
    type Output = Self;
    /// Satura no fim do relógio (um prazo que nunca vence).
    fn add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(ns_of(d)))
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, d: Duration) {
        *self = *self + d;
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;
    /// Satura em zero.
    fn sub(self, d: Duration) -> Self {
        Self(self.0.saturating_sub(ns_of(d)))
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, d: Duration) {
        *self = *self - d;
    }
}

impl Sub for Instant {
    type Output = Duration;
    /// Zero se `rhs` é posterior.
    fn sub(self, rhs: Self) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

// ---------------------------------------------------------------- sleep

/// Bit do `Timer` da thread: o prazo venceu.
pub(crate) const TIMER: u64 = 1 << 0;
/// Bit de um `Condvar::notify` a uma espera com prazo.
pub(crate) const EVENT: u64 = 1 << 1;
/// Bit da morte da thread esperada por `JoinHandle::join_timeout`.
pub(crate) const DEATH: u64 = 1 << 2;

/// O par de objetos de uma thread (ver o módulo).
#[derive(Clone, Copy)]
pub(crate) struct Waiter {
    timer: Handle,
    pub(crate) ntfy: Handle,
}

impl Waiter {
    /// Arma o `Timer` para o instante absoluto `deadline` (ns do kernel);
    /// `false` se o kernel recusou.
    pub(crate) fn arm(self, deadline: u64) -> bool {
        // Prazo 0 desarmaria.
        cap::arm_timer(self.timer, self.ntfy, TIMER, deadline.max(1), 0, 0).is_ok()
    }

    pub(crate) fn disarm(self) {
        let _ = cap::disarm_timer(self.timer, self.ntfy);
    }

    /// Bloqueia até haver bits; 0 se o kernel recusou a espera.
    pub(crate) fn wait(self) -> u64 {
        cap::ntfy_wait(self.ntfy).unwrap_or(0)
    }

    /// Apaga os bits pendentes (sinais velhos).
    pub(crate) fn drain(self) {
        let _ = cap::ntfy_poll(self.ntfy);
    }
}

/// O par guardado no bloco da thread; apaga os dois ao sair.
struct Slot(Cell<Option<Waiter>>);

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(w) = self.0.get() {
            let _ = cap::delete(w.timer);
            let _ = cap::delete(w.ntfy);
        }
    }
}

crate::thread_local! {
    static SLOT: Slot = Slot(Cell::new(None));
}

/// O par (`Timer`, `Notification`) da thread atual, criado na primeira
/// vez; `None` sem cota para ele ou antes de `rt::init` (tenta de novo na
/// próxima chamada).
pub(crate) fn waiter() -> Option<Waiter> {
    SLOT.with(|slot| {
        if let Some(w) = slot.0.get() {
            return Some(w);
        }
        let quota = crate::rt::env()?.quota;
        let ntfy = cap::create(quota, ObjectType::Notification, 0).ok()?;
        let Ok(timer) = cap::create(quota, ObjectType::Timer, 0) else {
            let _ = cap::delete(ntfy);
            return None;
        };
        let w = Waiter { timer, ntfy };
        slot.0.set(Some(w));
        Some(w)
    })
}

/// Cede a vez até `deadline` (sem `Timer`: o plano B das esperas).
pub(crate) fn yield_until(deadline: u64) {
    while now_ns() < deadline {
        crate::thread::yield_now();
    }
}

/// Dorme a thread atual por pelo menos `dur` (o tempo é medido a partir da
/// chamada). Usa o `Timer` e a `Notification` da thread, sem criar objetos
/// por chamada; os outros processos e threads seguem rodando. Um `dur` zero
/// só cede a vez.
pub fn sleep(dur: Duration) {
    sleep_until(Instant::now() + dur);
}

/// Dorme a thread atual até `deadline` (volta já se ele passou).
pub fn sleep_until(deadline: Instant) {
    let at = deadline.as_ns();
    if now_ns() >= at {
        crate::thread::yield_now();
        return;
    }
    let Some(w) = waiter().filter(|w| w.arm(at)) else {
        yield_until(at);
        return;
    };
    // Um bit velho de um disparo anterior acorda cedo: confere o relógio.
    while now_ns() < at {
        if w.wait() == 0 {
            crate::thread::yield_now();
        }
    }
}
