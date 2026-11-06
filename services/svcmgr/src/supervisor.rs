//! Supervisão e reinício (T-354; ADR 0034, itens 7 e 9; ADR 0035).
//!
//! [`Supervisor`] decide, para cada morte de serviço, se ele volta e
//! quando:
//!
//! - política `always` reinicia sempre; `on-failure` só quando a saída não
//!   foi limpa; `never` nunca;
//! - recuo exponencial de [`BACKOFF_MIN_NS`] (100 ms) a [`BACKOFF_MAX_NS`]
//!   (30 s), que volta ao mínimo depois de [`STABLE_NS`] de execução;
//! - mais de [`MAX_FAILURES`] falhas em [`FAILURE_WINDOW_NS`] (1 min): o
//!   serviço fica `Failed` e a ação é [`Action::Alert`], que o binário
//!   registra como `error` (o "alerta" do §7.2; o consumidor do evento vem
//!   depois).
//!
//! [`revoke_instance`] faz o item 9: revoga e apaga as raízes dos
//! endpoints da instância morta, e os clientes recebem `PeerClosed` e
//! chamam `connect` de novo depois do reinício.
//!
//! Sem syscalls e sem relógio: o tempo (`now_ns`) vem do chamador.

use alloc::vec::Vec;

use kabi::Error as KError;

use crate::broker::{Broker, Caps};

/// Recuo mínimo.
pub const BACKOFF_MIN_NS: u64 = 100_000_000;
/// Recuo máximo.
pub const BACKOFF_MAX_NS: u64 = 30_000_000_000;
/// Execução sem falha que zera o recuo.
pub const STABLE_NS: u64 = BACKOFF_MAX_NS;
/// Janela da contagem de falhas.
pub const FAILURE_WINDOW_NS: u64 = 60_000_000_000;
/// Falhas toleradas na janela; a seguinte gera o alerta.
pub const MAX_FAILURES: usize = 5;

/// Política de reinício do manifesto (`OMAN`: 0, 1, 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// `always`.
    Always,
    /// `on-failure`.
    OnFailure,
    /// `never`.
    Never,
}

impl Policy {
    /// Da codificação do manifesto; valor fora de 0..=2 vira `Never`.
    #[must_use]
    pub const fn from_manifest(v: u8) -> Self {
        match v {
            0 => Self::Always,
            1 => Self::OnFailure,
            _ => Self::Never,
        }
    }
}

/// Como a instância terminou (do registro de morte, ADR 0035).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Saída voluntária com código 0.
    Clean,
    /// Falta, morte forçada ou código diferente de 0.
    Failed,
}

/// Estado de um serviço.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Ainda não partiu.
    Pending,
    /// Rodando desde o instante dado.
    Running(u64),
    /// Esperando o reinício no instante dado.
    Waiting(u64),
    /// Terminou e não volta.
    Stopped,
    /// Desistiu depois de falhas demais.
    Failed,
}

/// O que fazer com uma morte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Reiniciar no instante `at_ns` (recuo `backoff_ns`).
    Restart {
        /// Quando.
        at_ns: u64,
        /// Recuo aplicado.
        backoff_ns: u64,
    },
    /// Não reiniciar (política).
    Stop,
    /// Falhas demais na janela: registrar `error` e não reiniciar.
    Alert {
        /// Falhas contadas na janela.
        failures: usize,
    },
}

#[derive(Clone, Debug)]
struct Slot {
    policy: Policy,
    state: State,
    backoff: u64,
    failures: Vec<u64>,
}

/// Estado de supervisão dos serviços, por id (o do [`Broker`]).
#[derive(Clone, Debug)]
pub struct Supervisor {
    slots: Vec<Slot>,
}

impl Supervisor {
    /// Um serviço por política, na ordem dos ids.
    #[must_use]
    pub fn new(policies: &[Policy]) -> Self {
        let slots = policies
            .iter()
            .map(|&policy| Slot {
                policy,
                state: State::Pending,
                backoff: BACKOFF_MIN_NS,
                failures: Vec::new(),
            })
            .collect();
        Self { slots }
    }

    /// Estado do serviço `id`.
    #[must_use]
    pub fn state(&self, id: u32) -> Option<State> {
        self.slots.get(usize::try_from(id).ok()?).map(|s| s.state)
    }

    /// O serviço `id` partiu em `now_ns`.
    pub fn started(&mut self, id: u32, now_ns: u64) {
        if let Some(s) = self.slot(id) {
            s.state = State::Running(now_ns);
        }
    }

    fn slot(&mut self, id: u32) -> Option<&mut Slot> {
        self.slots.get_mut(usize::try_from(id).ok()?)
    }

    /// O serviço `id` morreu em `now_ns`: a decisão.
    pub fn exited(&mut self, id: u32, exit: Exit, now_ns: u64) -> Action {
        let Some(s) = self.slot(id) else {
            return Action::Stop;
        };
        if let State::Running(since) = s.state
            && now_ns.saturating_sub(since) >= STABLE_NS
        {
            s.backoff = BACKOFF_MIN_NS;
        }
        if exit == Exit::Failed {
            s.failures
                .retain(|&t| now_ns.saturating_sub(t) < FAILURE_WINDOW_NS);
            s.failures.push(now_ns);
            if s.failures.len() > MAX_FAILURES {
                s.state = State::Failed;
                return Action::Alert {
                    failures: s.failures.len(),
                };
            }
        }
        let again = match s.policy {
            Policy::Always => true,
            Policy::OnFailure => exit == Exit::Failed,
            Policy::Never => false,
        };
        if !again {
            s.state = State::Stopped;
            return Action::Stop;
        }
        let backoff_ns = s.backoff;
        let at_ns = now_ns.saturating_add(backoff_ns);
        s.backoff = (s.backoff.saturating_mul(2)).min(BACKOFF_MAX_NS);
        s.state = State::Waiting(at_ns);
        Action::Restart { at_ns, backoff_ns }
    }

    /// Serviços cujo reinício venceu até `now_ns`.
    #[must_use]
    pub fn due(&self, now_ns: u64) -> Vec<u32> {
        (0u32..)
            .zip(&self.slots)
            .filter(|(_, s)| matches!(s.state, State::Waiting(at) if at <= now_ns))
            .map(|(id, _)| id)
            .collect()
    }

    /// Morte induzida de propósito (o teste de caos, T-366): o serviço volta
    /// em `now_ns`, sem contar falha nem mexer no recuo. Não reinicia quem
    /// já está `Failed` ou `Stopped`.
    pub fn induced(&mut self, id: u32, now_ns: u64) {
        if let Some(s) = self.slot(id)
            && !matches!(s.state, State::Failed | State::Stopped)
        {
            s.state = State::Waiting(now_ns);
        }
    }

    /// Próximo instante de reinício pendente, para armar o `Timer`.
    #[must_use]
    pub fn next_due(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|s| match s.state {
                State::Waiting(at) => Some(at),
                _ => None,
            })
            .min()
    }
}

/// Fim da instância de `id` (ADR 0034, item 9): `cap_revoke` e `cap_delete`
/// de cada raiz de endpoint dela, e a geração avança. Os clientes perdem as
/// cópias e quem espera no endpoint recebe `PeerClosed`.
///
/// # Errors
///
/// O primeiro erro do kernel; as raízes seguintes são tratadas assim mesmo.
pub fn revoke_instance<C: Caps>(broker: &mut Broker, id: u32, caps: &mut C) -> Result<(), KError> {
    let mut first = Ok(());
    for root in broker.retire(id) {
        let r = caps.revoke(root).and_then(|()| caps.delete(root));
        if first.is_ok() {
            first = r;
        }
    }
    first
}

#[cfg(test)]
mod tests;
