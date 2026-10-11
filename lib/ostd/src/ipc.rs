//! IPC síncrono (SDD v1.0, seção 6.7; ADR 0027): invólucros de `ipc_call`,
//! `ipc_send`, `ipc_recv` e `ipc_reply_recv`.
//!
//! A mensagem vai em registradores: rótulo, [`MsgInfo`] e até seis
//! palavras. Capabilities e palavras longas vão pelo buffer de IPC que o
//! criador da thread registrou ([`kabi::ipc::IpcBuffer`]): quem envia põe os
//! handles em `caps` e as palavras em `words` e declara as contagens em
//! [`Message::info`]; quem recebe acha ali os handles novos. Prazos são
//! instantes absolutos do relógio monotônico ([`crate::time::now_ns`]); 0 é
//! sem prazo.

use kabi::ipc::{MsgInfo, recv_target};
use kabi::{Badge, Error, Handle, MSG_REG_WORDS, STATUS_OK, Syscall};

/// Rótulo, `info` e palavras em registradores.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Message {
    /// Rótulo de 64 bits (o significado é do protocolo).
    pub label: u64,
    /// Contagens (palavras, capabilities, palavras no buffer) e flags.
    pub info: MsgInfo,
    /// Palavras 0 a 5; só as `info.words` primeiras são enviadas.
    pub words: [u64; MSG_REG_WORDS],
}

impl Message {
    /// Mensagem com `label` e as primeiras seis de `words`.
    #[must_use]
    pub fn new(label: u64, words: &[u64]) -> Self {
        let n = words.len().min(MSG_REG_WORDS);
        let mut w = [0; MSG_REG_WORDS];
        w[..n].copy_from_slice(&words[..n]);
        #[allow(clippy::cast_possible_truncation, reason = "no máximo 6")]
        let info = MsgInfo::words(n as u8);
        Self {
            label,
            info,
            words: w,
        }
    }

    /// As palavras declaradas em `info`.
    #[must_use]
    pub fn payload(&self) -> &[u64] {
        &self.words[..usize::from(self.info.words).min(MSG_REG_WORDS)]
    }
}

/// Mensagem recebida e o badge de quem a enviou (zero numa resposta).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// Badge da capability do remetente.
    pub badge: Badge,
    /// A mensagem.
    pub msg: Message,
}

fn raw(h: Handle) -> u64 {
    u64::from(h.raw())
}

/// Faz a syscall de IPC `nr` com alvo `target`, mensagem `msg` e prazo.
fn ipc(nr: Syscall, target: u64, msg: &Message, deadline: u64) -> Result<Received, Error> {
    let w = msg.words;
    let regs = [
        target,
        msg.label,
        msg.info.to_raw(),
        deadline,
        w[0],
        w[1],
        w[2],
        w[3],
        w[4],
        w[5],
    ];
    let (status, out) = crate::arch::ipc(nr.to_raw(), regs);
    if status != STATUS_OK {
        return Err(Error::try_from(status).unwrap_or(Error::NotSupported));
    }
    let [badge, label, info, w0, w1, w2, w3, w4, w5] = out;
    Ok(Received {
        badge,
        msg: Message {
            label,
            info: MsgInfo::try_from(info).unwrap_or_default(),
            words: [w0, w1, w2, w3, w4, w5],
        },
    })
}

/// `ipc_call`: envia `msg` ao endpoint `ep` e espera a resposta.
///
/// # Errors
///
/// Os do kernel (`AccessDenied` sem `SEND`, ou com capabilities sem
/// `GRANT`; `TimedOut` no prazo; `WouldBlock` com `FLAG_NONBLOCK`).
pub fn call(ep: Handle, msg: &Message, deadline: u64) -> Result<Received, Error> {
    ipc(Syscall::IpcCall, raw(ep), msg, deadline)
}

/// `ipc_send`: envia `msg` ao endpoint `to` (espera um receptor) ou, se
/// `to` for um `Reply`, responde a quem chamou.
///
/// # Errors
///
/// Os do kernel; `PeerClosed` num `Reply` sem chamador.
pub fn send(to: Handle, msg: &Message, deadline: u64) -> Result<(), Error> {
    ipc(Syscall::IpcSend, raw(to), msg, deadline).map(drop)
}

/// `ipc_recv`: recebe do endpoint `ep`; uma chamada fica guardada em
/// `reply`, que precisa estar vazio.
///
/// # Errors
///
/// Os do kernel; `Busy` se `reply` ainda tem chamador.
pub fn recv(ep: Handle, reply: Handle, deadline: u64) -> Result<Received, Error> {
    ipc(
        Syscall::IpcRecv,
        recv_target(ep, reply),
        &Message::default(),
        deadline,
    )
}

/// `ipc_reply_recv`: responde `msg` pelo `reply` (se houver chamador) e
/// recebe a próxima mensagem de `ep` nele.
///
/// # Errors
///
/// Os do kernel.
pub fn reply_recv(
    ep: Handle,
    reply: Handle,
    msg: &Message,
    deadline: u64,
) -> Result<Received, Error> {
    ipc(Syscall::IpcReplyRecv, recv_target(ep, reply), msg, deadline)
}

/// Endereço sugerido para o buffer de IPC da thread inicial de um processo
/// (longe do executável em 2 MiB e da pilha no topo da metade de usuário).
pub const DEFAULT_BUFFER_VA: u64 = 0x1000_0000;

/// Buffer de IPC da thread: uma página do processo, mapeada no próprio
/// espaço e registrada com `thread_configure` (seção 6.7). No `Drop`, o
/// registro sai antes da página.
#[derive(Debug)]
pub struct Buffer {
    map: crate::vm::Mapping,
    thread: Handle,
}

impl Buffer {
    /// Cria a página na cota `quota`, mapeia em `va` no espaço `aspace` e
    /// a registra como buffer de IPC de `thread`.
    ///
    /// # Errors
    ///
    /// Os de `obj_create`, `vm_map` e `thread_configure`.
    pub fn new(quota: Handle, aspace: Handle, thread: Handle, va: u64) -> Result<Self, Error> {
        use kabi::vm::{PAGE_SIZE, WRITE};
        let page = crate::cap::create(quota, kabi::ObjectType::MemoryObject, PAGE_SIZE)?;
        let map = crate::vm::Mapping::new(aspace, page, va, PAGE_SIZE, WRITE);
        // A região guarda o objeto; a capability não faz mais falta.
        let _ = crate::cap::delete(page);
        let map = map?;
        crate::thread::set_ipc_buffer(thread, Some(va))?;
        Ok(Self { map, thread })
    }

    /// O conteúdo: handles de capabilities e palavras longas.
    pub fn get(&mut self) -> &mut kabi::ipc::IpcBuffer {
        crate::arch::mem::ipc_buffer(&mut self.map)
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let _ = crate::thread::set_ipc_buffer(self.thread, None);
    }
}
