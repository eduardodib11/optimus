//! `svcmgr`: o corretor de capabilities (ADR 0034). Criado pelo `root`
//! (T-351), que lhe entrega, nesta ordem em `rdi`, `rsi` e `rdx`:
//!
//! - `rdi`: o endpoint do `root` (badge 1) e a própria thread;
//! - `rsi`: o bootfs só de leitura e a cota de partida;
//! - `rdx`: a cota de partida e a tabela de handles de partida do kernel.
//!
//! Nesta versão ele só confere as capabilities recebidas e se anuncia;
//! manifestos, grafo e partida dos serviços vêm nas T-352 e T-353.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, split_handle_pair};
use ostd::rt::Start;

ostd::entry!(main);

/// Quanto o `svcmgr` espera a resposta do `root`, em ns.
const CALL_WAIT_NS: u64 = 15_000_000_000;
/// Rótulo do "olá" ao `root` (o `root` aceita só esse rótulo do badge 1).
const LABEL_OLA: u64 = 1;

/// Capabilities recebidas do `root`, já separadas.
#[derive(Clone, Copy)]
struct Boot {
    root_ep: Handle,
    thread: Handle,
    bootfs: Handle,
    quota: Handle,
}

fn main(start: Start) -> ! {
    let [a, b, c] = start.args;
    let (root_ep, thread) = split_handle_pair(a);
    let (bootfs, quota) = split_handle_pair(b);
    let boot = Boot {
        root_ep,
        thread,
        bootfs,
        quota,
    };
    let _ = c;
    ostd::rt::init(ostd::rt::Env { quota: boot.quota });
    ostd::debug::print("svcmgr: iniciado pelo root");
    ostd::debug::print_fmt(format_args!(
        "svcmgr: caps recebidas: root_ep={} thread={} bootfs={} quota={}",
        boot.root_ep.raw(),
        boot.thread.raw(),
        boot.bootfs.raw(),
        boot.quota.raw()
    ));
    // Prazo: se o `root` não responder, o `svcmgr` sai em vez de ficar preso
    // e segurar a cota de partida (ADR 0034, item 2).
    let deadline = ostd::time::now_ns() + CALL_WAIT_NS;
    match ipc::call(boot.root_ep, &Message::new(LABEL_OLA, &[]), deadline) {
        Ok(r) if r.msg.label == 0 => ostd::debug::print("svcmgr: o root aceitou o anúncio"),
        Ok(_) => ostd::debug::print("svcmgr: o root respondeu com erro"),
        Err(Error::AccessDenied) => ostd::debug::print("svcmgr: o root recusou o anúncio"),
        Err(_) => ostd::debug::print("svcmgr: falha ao falar com o root"),
    }
    ostd::thread::exit()
}
