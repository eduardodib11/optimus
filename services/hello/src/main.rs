//! `hello`: o primeiro serviço que o `root` carrega do bootfs (T-212).
//!
//! Registra o próprio buffer de IPC, cumprimenta o `root` com um texto,
//! faz as idas e voltas pedidas pelo `root`, conferindo cada resposta, e se
//! despede com o total e os erros. Desde a T-345 as chamadas passam pelo
//! cliente gerado do `idl/optimus/hello.oidl` ([`hello_cliente`]); o
//! [`proto`] fica só com a função de palavras e os badges.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::ipc::Buffer;
use ostd::kabi::{Error, Handle, split_handle_pair};
use ostd::rt::Start;

mod hello_cliente;
mod proto;

use hello_cliente::HelloCliente;

ostd::entry!(main);

const GREETING: &str = "olá, root! aqui é o hello, pelo buffer de IPC";

/// Saudação pelo cliente gerado.
fn greet(cli: &HelloCliente, buf: &mut Buffer) -> Result<(), Error> {
    match cli.saudacao(buf, GREETING)? {
        Ok(_) => Ok(()),
        Err(_) => Err(Error::InvalidArgument),
    }
}

/// `rounds` idas e voltas; devolve quantas respostas não conferiram.
fn ping(cli: &HelloCliente, buf: &mut Buffer, rounds: u64) -> Result<u64, Error> {
    let mut errors = 0;
    for i in 0..rounds {
        let w: [u64; 6] = core::array::from_fn(|k| proto::word(i, k as u64));
        let ok = match cli.ping(buf, w[0], w[1], w[2], w[3], w[4], w[5])? {
            Ok(r) => [r.w0, r.w1, r.w2, r.w3, r.w4, r.w5]
                .iter()
                .zip(w)
                .all(|(&got, sent)| got == sent.wrapping_add(1)),
            Err(_) => false,
        };
        if !ok {
            errors += 1;
        }
    }
    Ok(errors)
}

fn main(start: Start) -> ! {
    let (ep, thread) = split_handle_pair(start.args[0]);
    let (aspace, quota) = split_handle_pair(start.args[1]);
    // `args[2]`: a parte alta é o handle da `DebugLog` (ADR 0036, item 5) e a
    // baixa, as voltas.
    let log = Handle::from_raw((start.args[2] >> 32) as u32);
    let rounds = start.args[2] & 0xFFFF_FFFF;
    if log.raw() != 0 {
        ostd::debug::set_log(log);
    }
    ostd::rt::init(ostd::rt::Env { quota });
    ostd::debug::print("hello: iniciado pelo root");
    let cli = HelloCliente::new(ep);
    let result = ostd::ipc::Buffer::new(quota, aspace, thread, ostd::ipc::DEFAULT_BUFFER_VA)
        .and_then(|mut b| {
            greet(&cli, &mut b)?;
            let errors = ping(&cli, &mut b, rounds)?;
            match cli.bye(&mut b, rounds, errors)? {
                Ok(()) => Ok(errors),
                Err(_) => Err(Error::InvalidArgument),
            }
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
