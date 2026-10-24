//! Processos e eventos de ciclo de vida (T-348; ADR 0035, itens 1 a 5).
//!
//! Para o kernel, **processo = `CapSpace`**: as threads que
//! `thread_configure` ligou à mesma tabela. O [`Process`] mora dentro do
//! `CapSpace`, sob a trava dele, e conta as threads vivas (de
//! `thread_start` até a morte), guarda o registro de morte do processo e a
//! ligação do evento (`obj_bind_notify`). O processo morre quando as vivas
//! voltam a zero depois de alguma ter rodado, ou já no encerramento, se
//! nenhuma rodava.
//!
//! Uma thread morre por `thread_exit`, por falta fatal ou por encerramento
//! ([`kill`]): neste caso ela é só marcada, e morre ela mesma no próximo
//! ponto de volta ao usuário (a IPI de reescalonar a traz ao kernel se ela
//! roda noutra CPU) ou ao tentar bloquear; se já esperava numa fila (IPC,
//! notificação ou futex), sai dela e acorda. Quem morre chama
//! [`thread_died`] com o registro dela já gravado: primeiro a conta do
//! processo (sob a trava do `CapSpace`), depois o evento da thread e, se
//! era a última, o evento do processo.
//! Assim o evento do processo só dispara quando a última thread deixou de
//! executar código de usuário (ADR 0035, item 4, invariante).
//!
//! Travas: o `CapSpace` (nível 2) com a do processo; a da thread
//! (`Thread.binding`, objeto) e a da notificação (objeto) uma de cada vez,
//! nunca juntas: os eventos são copiados sob a trava e sinalizados depois
//! (ADR 0035, item 3.4), e o despertar (a fila do escalonador) vem por
//! último.

#![forbid(unsafe_code)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use kabi::Error;
use kabi::exit::{CAUSE_EXITED, CAUSE_FAULTED, CAUSE_KILLED};

use crate::cap::{SharedCapSpace, xcdt};
use crate::sys::Env;
use crate::thread::{Event, Thread};

/// Capabilities apagadas entre dois pontos de preempção ao esvaziar a
/// tabela de um processo encerrado.
const EMPTY_SLICE: u32 = 32;

/// Registro de morte (ADR 0035, item 2): causa (`kabi::exit::CAUSE_*`, zero
/// = vivo), código e auxiliar.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// Causa.
    pub cause: u8,
    /// `Exited`: o código de `thread_exit`; `Faulted`: o vetor.
    pub code: u64,
    /// `Faulted`: o endereço que faltou.
    pub aux: u64,
}

impl Record {
    /// Saída normal com `code`.
    #[must_use]
    pub const fn exited(code: u64) -> Self {
        Self {
            cause: CAUSE_EXITED,
            code,
            aux: 0,
        }
    }

    /// Encerrado por outra thread.
    #[must_use]
    pub const fn killed() -> Self {
        Self {
            cause: CAUSE_KILLED,
            code: 0,
            aux: 0,
        }
    }

    /// Morte anormal (`Faulted` ou `Killed`).
    #[must_use]
    pub const fn abnormal(&self) -> bool {
        self.cause == CAUSE_FAULTED || self.cause == CAUSE_KILLED
    }

    /// Como `sys_info` (classe 2) o devolve.
    #[must_use]
    pub const fn values(&self) -> [u64; 3] {
        [self.cause as u64, self.code, self.aux]
    }
}

/// Fase do processo.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Life {
    /// Aceita threads novas.
    #[default]
    Alive,
    /// Encerrado: as threads que restam estão morrendo; nenhuma começa.
    Dying,
    /// Morto: o evento já disparou (ou dispara para quem ligar).
    Dead,
}

/// O estado de processo de um `CapSpace`.
#[derive(Default)]
pub struct Process {
    /// Threads iniciadas que ainda não morreram (`live_threads`).
    live: u32,
    /// Limite de [`live`](Self::live) (0 = sem limite; ADR 0035, item 5).
    limit: u32,
    life: Life,
    /// Alguma thread do processo já morreu.
    ran: bool,
    record: Record,
    /// O registro foi fixado por `EXIT_GROUP` ou `DESTROY` e nada o muda.
    fixed: bool,
    event: Option<Event>,
    /// As threads vivas, para o encerramento as achar (cada uma sai daqui
    /// ao morrer). Cresce no heap sem cobrança de cota, no máximo uma
    /// entrada por thread viva (as threads já são cobradas).
    threads: Vec<Arc<Thread>>,
}

impl fmt::Debug for Process {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Process({} vivas, {:?}, {:?})",
            self.live, self.life, self.record
        )
    }
}

impl Process {
    /// Threads vivas.
    #[must_use]
    pub const fn live(&self) -> u32 {
        self.live
    }

    /// Limite de threads vivas (0 = sem limite).
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Fixa o limite de threads vivas (`obj_create` do `CapSpace`).
    pub const fn set_limit(&mut self, limit: u32) {
        self.limit = limit;
    }

    /// O processo morreu.
    #[must_use]
    pub fn dead(&self) -> bool {
        self.life == Life::Dead
    }

    /// O registro de morte do processo; zeros enquanto vive (inclusive
    /// encerrado, com threads ainda morrendo).
    #[must_use]
    pub fn record(&self) -> Record {
        if self.dead() {
            self.record
        } else {
            Record::default()
        }
    }

    /// Passa a `Dead` e devolve o evento a sinalizar.
    fn die(&mut self) -> Option<Event> {
        self.life = Life::Dead;
        self.event.take()
    }
}

/// Sinaliza `event`, já sem trava nenhuma na mão, e acorda quem esperava.
fn signal(event: Option<Event>, env: &mut dyn Env) {
    if let Some((ntfy, bits)) = event
        && let Some((thread, word)) = ntfy.signal(bits)
    {
        env.wake(thread, word);
    }
}

/// `thread_start` (ADR 0035, itens 1 e 5): conta `t` nas vivas do processo
/// `space`.
///
/// # Errors
///
/// [`Error::PeerClosed`] se o processo foi encerrado ou já morreu;
/// [`Error::QuotaExceeded`] no limite de threads ou sem memória.
pub fn on_start(space: &SharedCapSpace, t: &Arc<Thread>) -> Result<(), Error> {
    let mut s = space.lock();
    let p = s.process_mut();
    if p.life != Life::Alive {
        return Err(Error::PeerClosed);
    }
    if p.limit != 0 && p.live >= p.limit {
        return Err(Error::QuotaExceeded);
    }
    p.threads.try_reserve(1).map_err(|_| Error::QuotaExceeded)?;
    p.threads.push(Arc::clone(t));
    p.live += 1;
    t.set_counted(true);
    Ok(())
}

/// Desfaz [`on_start`]: a partida de `t` falhou antes de ela rodar. Se era a
/// última viva de um processo encerrado ou em que outra já morreu, o
/// processo morre aqui.
pub fn undo_start(space: &SharedCapSpace, t: &Thread, env: &mut dyn Env) {
    let (gone, event) = {
        let mut s = space.lock();
        let p = s.process_mut();
        if !t.counted() {
            return;
        }
        t.set_counted(false);
        p.live -= 1;
        let gone = p
            .threads
            .iter()
            .position(|w| core::ptr::eq(Arc::as_ptr(w), t))
            .map(|i| p.threads.swap_remove(i));
        let event = (p.live == 0 && (p.life == Life::Dying || p.ran)).then(|| p.die());
        (gone, event.flatten())
    };
    drop(gone);
    signal(event, env);
}

/// A thread `t` morreu (o registro dela já gravado, ADR 0035, item 2): a
/// tira das vivas do processo, que morre se ela era a última, e sinaliza o
/// evento dela e depois o do processo. Chamada uma vez pela própria thread no caminho de saída
/// (ou por quem encerrou uma thread inativa); chamar de novo não faz nada.
pub fn thread_died(t: &Arc<Thread>, env: &mut dyn Env) {
    let Some(death) = t.mark_dead() else {
        return;
    };
    let Some(space) = death.cspace else {
        signal(death.event, env);
        return;
    };
    let record = t
        .death()
        .map_or(Record::default(), |(cause, code, aux)| Record {
            cause,
            code,
            aux,
        });
    // A conta desce antes do evento da thread: quem o recebe já pode
    // iniciar outra no lugar dela (o limite de threads, item 5).
    let (gone, event) = {
        let mut s = space.lock();
        let p = s.process_mut();
        if !t.counted() {
            drop(s);
            signal(death.event, env);
            return;
        }
        t.set_counted(false);
        p.live -= 1;
        p.ran = true;
        if !p.fixed && !p.record.abnormal() {
            p.record = record;
        }
        let gone = p
            .threads
            .iter()
            .position(|w| Arc::ptr_eq(w, t))
            .map(|i| p.threads.swap_remove(i));
        let event = (p.live == 0 && p.life != Life::Dead).then(|| p.die());
        (gone, event.flatten())
    };
    drop(gone);
    signal(death.event, env);
    signal(event, env);
}

/// `obj_bind_notify` sobre um `CapSpace` (ADR 0035, item 3): `event` passa
/// a ser a ligação do evento de morte do processo (`None` desliga). Morto o
/// processo, sinaliza já, sem guardar.
pub fn bind(space: &SharedCapSpace, event: Option<Event>, env: &mut dyn Env) {
    let (now, old) = {
        let mut s = space.lock();
        let p = s.process_mut();
        if p.dead() {
            (event, p.event.take())
        } else {
            (None, core::mem::replace(&mut p.event, event))
        }
    };
    drop(old);
    signal(now, env);
}

/// O registro de morte do processo de `space` (zeros enquanto vive).
#[must_use]
pub fn record(space: &SharedCapSpace) -> Record {
    space.lock().process().record()
}

/// Encerra a thread `t` (ADR 0035, item 4): ela morre como `Killed`. Inativa,
/// morre já; senão é marcada e morre ela mesma no próximo ponto de entrada
/// no kernel (a que roda noutra CPU recebe a IPI de reescalonar) ou ao
/// tentar bloquear, e a que já espera numa fila sai dela e acorda.
pub fn kill(t: &Arc<Thread>, env: &mut dyn Env) {
    if !t.request_kill() {
        return;
    }
    if t.kill_inactive() {
        t.record_death(CAUSE_KILLED, 0, 0);
        thread_died(t, env);
        return;
    }
    env.kick(t);
    if crate::ipc::cancel_any(t) {
        env.wake(Arc::clone(t), 0);
    }
}

/// Encerra o processo de `space` (`cap_delete(DESTROY)` com `record` =
/// `Killed`, ou `EXIT_GROUP` com `Exited` e o código, e `except` = quem
/// chama; ADR 0035, item 4): fixa o registro do processo (se ainda vive),
/// encerra todas as threads dele menos `except` e esvazia a tabela, o que
/// apaga as capabilities (os `Endpoint`s e os `Reply`s sem outra
/// referência morrem, e quem esperava neles recebe `PeerClosed`). Sem
/// thread viva, o processo morre já.
pub fn destroy(
    space: &Arc<SharedCapSpace>,
    record: Record,
    except: Option<&Thread>,
    env: &mut dyn Env,
) {
    let (threads, event) = {
        let mut s = space.lock();
        let p = s.process_mut();
        let event = match p.life {
            Life::Dead => None,
            life => {
                if !p.fixed {
                    p.record = record;
                    p.fixed = true;
                }
                if p.live == 0 {
                    p.die()
                } else {
                    if life == Life::Alive {
                        p.life = Life::Dying;
                    }
                    None
                }
            }
        };
        (core::mem::take(&mut p.threads), event)
    };
    signal(event, env);
    for t in &threads {
        if !except.is_some_and(|e| core::ptr::eq(e, Arc::as_ptr(t))) {
            kill(t, env);
        }
    }
    drop(threads);
    empty(space, env);
}

/// Apaga todas as capabilities de `space`, uma por vez pela árvore de
/// derivação, com um ponto de preempção a cada [`EMPTY_SLICE`]. As que não
/// saem (alvo de revogação em andamento) ficam para quando a tabela morrer.
fn empty(space: &Arc<SharedCapSpace>, env: &mut dyn Env) {
    let mut cursor = 1;
    let mut done = 0u32;
    loop {
        let next = space.lock().next_live(&mut cursor);
        let Some(h) = next else { return };
        let _ = xcdt::delete(space, h);
        done += 1;
        if done.is_multiple_of(EMPTY_SLICE) {
            env.preempt();
        }
    }
}

#[cfg(test)]
mod tests;
