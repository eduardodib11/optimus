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

use ostd::kabi::{Handle, split_handle_pair};
use ostd::rt::Start;

ostd::entry!(main);

/// Badge com que o `root` identifica o `svcmgr` no próprio endpoint.
pub const ROOT_BADGE: u64 = 1;

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
    ostd::thread::exit()
}
