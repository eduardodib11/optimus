//! `hello`: o primeiro serviço que o `root` carrega do bootfs (T-212).
//!
//! Registra o próprio buffer de IPC, cumprimenta o `root` com um texto
//! nas palavras do buffer, faz as idas e voltas de [`proto::PING`] pedidas
//! (só registradores, o caminho rápido da seção 6.7), conferindo cada
//! resposta, e se despede com o total e os erros. O protocolo está em
//! [`proto`].

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::ipc::{self, Buffer, Message};
use ostd::kabi::ipc::MsgInfo;
use ostd::kabi::{Error, Handle, IPC_BUFFER_WORDS, split_handle_pair};
use ostd::rt::Start;

mod proto;

ostd::entry!(main);

const GREETING: &str = "olá, root! aqui é o hello, pelo buffer de IPC";

/// Saudação pelo buffer de IPC.
fn greet(ep: Handle, buffer: &mut Buffer) -> Result<(), Error> {
    let bytes = GREETING.as_bytes();
    let words = bytes.len().div_ceil(8);
    let b = buffer.get();
    for (w, chunk) in b.words.iter_mut().zip(bytes.chunks(8)) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        *w = u64::from_le_bytes(word);
    }
    let mut msg = Message::new(proto::HELLO, &[bytes.len() as u64]);
    msg.info.buffer_words = u16::try_from(words.min(IPC_BUFFER_WORDS)).unwrap_or(0);
    let reply = ipc::call(ep, &msg, 0)?;
    if reply.msg.label == proto::HELLO {
        Ok(())
    } else {
        Err(Error::InvalidArgument)
    }
}

/// `rounds` idas e voltas; devolve quantas respostas não conferiram.
fn ping(ep: Handle, rounds: u64) -> Result<u64, Error> {
    let mut errors = 0;
    for i in 0..rounds {
        let mut words = [0; 6];
        for (k, w) in (0..).zip(words.iter_mut()) {
            *w = proto::word(i, k);
        }
        let reply = ipc::call(ep, &Message::new(proto::PING, &words), 0)?;
        let m = reply.msg;
        let ok = m.label == proto::PONG
            && m.info == MsgInfo::words(6)
            && (0..).zip(m.words).all(|(k, w)| w == proto::word(i, k) + 1);
        if !ok {
            errors += 1;
        }
    }
    Ok(errors)
}

fn main(start: Start) -> ! {
    let (ep, thread) = split_handle_pair(start.args[0]);
    let (aspace, quota) = split_handle_pair(start.args[1]);
    let rounds = start.args[2];
    ostd::debug::print("hello: iniciado pelo root");
    let result = Buffer::new(quota, aspace, thread, ipc::DEFAULT_BUFFER_VA).and_then(|mut b| {
        greet(ep, &mut b)?;
        let errors = ping(ep, rounds)?;
        ipc::call(ep, &Message::new(proto::BYE, &[rounds, errors]), 0)?;
        Ok(errors)
    });
    match result {
        Ok(0) => {}
        Ok(errors) => ostd::debug::print_fmt(format_args!("hello: {errors} respostas erradas")),
        Err(e) => ostd::debug::print_fmt(format_args!("hello: falhou: {e:?}")),
    }
    // A thread e a tabela dela se referem uma à outra; apagar a
    // capability da própria thread desfaz o ciclo.
    let _ = ostd::cap::delete(thread);
    ostd::thread::exit()
}
