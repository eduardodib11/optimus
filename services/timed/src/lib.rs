//! `timed`: hora de parede (T-358; ADR 0037, itens 1, 2 e 4).
//!
//! [`Clock`] guarda o estado do item 2 e responde `optimus.time.Clock.now`
//! e `optimus.time.Admin.set` em função do relógio monotônico, que o
//! chamador passa (`mono_ns`, ns desde o reset da CPU, a base do
//! `wall_tsc_ns` da `BootInfo`). Sem syscalls: o serviço só liga isto ao
//! `sys_info` e ao IPC, e os testes rodam no host.
//!
//! - Hora inicial: `wall_unix_ns` do RTC lido pelo `optboot` no instante
//!   `wall_tsc_ns`, sem correção.
//! - `Slew`: taxa de ±[`MAX_PPM`] até consumir a diferença; `now()` nunca
//!   regride.
//! - `Step`: para frente sempre; para trás só acima de 1 s (o chamador
//!   registra `warn`), e até 1 s vira `Slew`. O primeiro `set` depois do
//!   boot vale como `Step`.
//! - Hora POSIX, de 1970-01-01 a 2200-01-01.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod zone;

/// Taxa máxima de ajuste, em ppm.
pub const MAX_PPM: i64 = 500;
/// Incerteza inicial: a resolução do RTC.
pub const RTC_RESOLUTION_NS: u64 = 1_000_000_000;
/// Maior recuo que vira `Slew` em vez de `Step`.
pub const STEP_BACK_MIN_NS: i128 = 1_000_000_000;
/// Fim (exclusivo) da faixa aceita: 2200-01-01T00:00:00Z.
pub const MAX_UNIX_NS: i64 = 7_258_118_400 * 1_000_000_000;

const NS_PER_PPM: i128 = 1_000_000;

/// `optimus.time.WallTime`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WallTime {
    /// ns Unix UTC.
    pub unix_ns: i64,
    /// O instante monotônico da leitura.
    pub mono_ns: u64,
    /// Incerteza, em ns.
    pub uncertainty_ns: u64,
    /// Já houve `set` autorizado.
    pub synced: bool,
}

/// `optimus.time.TimeError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeError {
    /// Sem a interface `Admin`.
    AccessDenied,
    /// Hora fora de 1970 a 2200.
    InvalidArgument,
    /// Sem hora do RTC e sem `set`.
    Unavailable,
}

/// `optimus.time.SetMode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetMode {
    /// Ajuste suave.
    Slew,
    /// Salto.
    Step,
}

/// O que um `set` fez.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adjust {
    /// Saltou para frente (ou não mudou).
    Stepped,
    /// Saltou para trás: retrocesso visível, o serviço registra `warn`.
    SteppedBack,
    /// Ajuste suave em andamento até o instante monotônico dado.
    Slewing(u64),
}

/// Estado do `timed` (ADR 0037, item 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    base_wall: i128,
    base_mono: u64,
    rate_ppm: i64,
    /// Duração do ajuste suave a partir de `base_mono`.
    slew_ns: u64,
    valid: bool,
    synced: bool,
    last_sync: u64,
}

impl Clock {
    /// Relógio da hora do boot (`sys_info` classe 4): `wall_unix_ns` lido
    /// em `wall_tsc_ns`; `valid` falso se o `GetTime` falhou.
    #[must_use]
    pub const fn from_boot(wall_unix_ns: i64, wall_tsc_ns: u64, valid: bool) -> Self {
        Self {
            base_wall: wall_unix_ns as i128,
            base_mono: wall_tsc_ns,
            rate_ppm: 0,
            slew_ns: 0,
            valid,
            synced: false,
            last_sync: wall_tsc_ns,
        }
    }

    fn wall_at(&self, mono: u64) -> i128 {
        let elapsed = i128::from(mono.saturating_sub(self.base_mono));
        let slewed = elapsed.min(i128::from(self.slew_ns));
        self.base_wall + elapsed + (slewed * i128::from(self.rate_ppm)).div_euclid(NS_PER_PPM)
    }

    /// `Clock.now()` no instante monotônico `mono_ns`.
    ///
    /// # Errors
    ///
    /// [`TimeError::Unavailable`] sem hora do RTC e sem `set`.
    pub fn now(&self, mono_ns: u64) -> Result<WallTime, TimeError> {
        if !self.valid && !self.synced {
            return Err(TimeError::Unavailable);
        }
        let wall = i64::try_from(self.wall_at(mono_ns)).map_err(|_| TimeError::Unavailable)?;
        let since = mono_ns.saturating_sub(self.last_sync);
        let drift = since / 1_000_000 * MAX_PPM.unsigned_abs();
        let base = if self.synced { 0 } else { RTC_RESOLUTION_NS };
        Ok(WallTime {
            unix_ns: wall,
            mono_ns,
            uncertainty_ns: base.saturating_add(drift),
            synced: self.synced,
        })
    }

    /// `Admin.set(unix_ns, mode)` no instante `mono_ns`.
    ///
    /// # Errors
    ///
    /// [`TimeError::InvalidArgument`] fora de 1970 a 2200.
    pub fn set(&mut self, unix_ns: i64, mode: SetMode, mono_ns: u64) -> Result<Adjust, TimeError> {
        if !(0..MAX_UNIX_NS).contains(&unix_ns) {
            return Err(TimeError::InvalidArgument);
        }
        let current = self.wall_at(mono_ns);
        let delta = i128::from(unix_ns) - current;
        let first = !self.synced || !self.valid;
        let step = first || (mode == SetMode::Step && (delta >= 0 || -delta > STEP_BACK_MIN_NS));
        self.base_mono = mono_ns;
        self.synced = true;
        self.valid = true;
        self.last_sync = mono_ns;
        if step {
            self.base_wall = i128::from(unix_ns);
            self.rate_ppm = 0;
            self.slew_ns = 0;
            return Ok(if delta < 0 {
                Adjust::SteppedBack
            } else {
                Adjust::Stepped
            });
        }
        // Slew: consome `delta` à taxa máxima; dura |delta| / 500 ppm.
        self.base_wall = current;
        self.rate_ppm = if delta < 0 { -MAX_PPM } else { MAX_PPM };
        let len =
            delta.unsigned_abs() * NS_PER_PPM.unsigned_abs() / u128::from(MAX_PPM.unsigned_abs());
        self.slew_ns = u64::try_from(len).unwrap_or(u64::MAX);
        Ok(Adjust::Slewing(mono_ns.saturating_add(self.slew_ns)))
    }
}

#[cfg(test)]
mod tests;
