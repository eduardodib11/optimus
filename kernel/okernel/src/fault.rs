//! Faltas e exceções de usuário (T-210; SDD v1.0, seção 6.4;
//! `kabi::fault`).
//!
//! O kernel não resolve faltas de usuário: a falta vira um `ipc_call`, em
//! nome da thread, no endpoint de exceções dela, e a thread espera a
//! resposta. [`handle`] diz ao kernel se ela volta à instrução que faltou
//! ou se é encerrada, e por quê; o encerramento e o registro ficam com o
//! kernel.

#![forbid(unsafe_code)]

use alloc::sync::Arc;
use core::fmt;

use kabi::fault::{self, REPLY_RESUME, WORDS};
use kabi::ipc::MsgInfo;
use kabi::{Error, MSG_REG_WORDS};

use crate::ipc::Message;
use crate::ipc::ops::kernel_call;
use crate::sys::Env;
use crate::thread::Thread;

/// Uma exceção vinda do anel 3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fault {
    /// Vetor (0 a 31).
    pub vector: u64,
    /// Código de erro empilhado pela CPU (0 se não houver).
    pub error: u64,
    /// Endereço que faltou (CR2 no #PF; 0 nas demais).
    pub addr: u64,
    /// Instrução que faltou.
    pub rip: u64,
    /// Pilha do usuário.
    pub rsp: u64,
    /// RFLAGS do usuário.
    pub rflags: u64,
}

impl Fault {
    /// A mensagem de `kabi::fault`.
    #[must_use]
    pub fn message(&self) -> Message {
        let mut words = [0; MSG_REG_WORDS];
        words[fault::WORD_ERROR] = self.error;
        words[fault::WORD_ADDR] = self.addr;
        words[fault::WORD_RIP] = self.rip;
        words[fault::WORD_RSP] = self.rsp;
        words[fault::WORD_RFLAGS] = self.rflags;
        Message {
            label: self.vector,
            info: MsgInfo::words(WORDS),
            words,
        }
    }
}

/// Por que a thread que faltou é encerrada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kill {
    /// Sem endpoint de exceções configurado.
    NoHandler,
    /// O handle do endpoint não resolve no `CapSpace` da thread, não é de
    /// endpoint ou não tem `SEND`.
    BadHandler(Error),
    /// A chamada falhou: endpoint ou `Reply` destruído antes da resposta.
    Unanswered(Error),
    /// O tratador respondeu com um rótulo que não retoma a thread.
    Refused(u64),
}

impl fmt::Display for Kill {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHandler => write!(f, "sem endpoint de exceções"),
            Self::BadHandler(e) => write!(f, "endpoint de exceções inválido ({e:?})"),
            Self::Unanswered(e) => write!(f, "ninguém atendeu ({e:?})"),
            Self::Refused(label) => write!(f, "o tratador recusou (rótulo {label:#x})"),
        }
    }
}

/// Entrega a falta de `me` (a thread atual) ao endpoint de exceções dela e
/// espera a resposta. `Ok` se ela deve voltar à instrução que faltou.
///
/// # Errors
///
/// O motivo do encerramento ([`Kill`]).
pub fn handle(me: &Arc<Thread>, fault: &Fault, env: &mut dyn Env) -> Result<(), Kill> {
    let h = me.exception_handler().ok_or(Kill::NoHandler)?;
    let space = me.cspace().ok_or(Kill::BadHandler(Error::InvalidHandle))?;
    let cap = space.lock().get(h).cloned().map_err(Kill::BadHandler)?;
    let reply = match kernel_call(me, cap, fault.message(), env) {
        Ok(reply) => reply,
        Err(e @ (Error::WrongType | Error::AccessDenied)) => return Err(Kill::BadHandler(e)),
        Err(e) => return Err(Kill::Unanswered(e)),
    };
    if reply.label == REPLY_RESUME {
        Ok(())
    } else {
        Err(Kill::Refused(reply.label))
    }
}

#[cfg(test)]
mod tests;
