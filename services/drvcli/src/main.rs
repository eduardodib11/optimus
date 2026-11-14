//! `drvcli` (T-514; ADR 0046, item 5): o cliente de teste dos contratos OIDL
//! dos drivers virtio. Sobe no boot, espera o `devmgr` partir cada driver,
//! conecta ao endpoint dele pelo `svcmgr` (`connect`) e faz uma chamada pelo
//! cliente gerado do `.oidl`. Cada contrato que responde vira uma linha
//! `drvcli: <contrato> ok`, que o `cargo xtask test` confere.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::kabi::{Error, Handle};
use ostd::rt::Start;
use ostd::svc::Session;

mod console_cliente;

use console_cliente::ConsoleCliente;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Quanto esperar cada driver partir e o intervalo entre as tentativas.
/// Nenhum `connect` passa de partida do `svcmgr` enquanto ele sobe os níveis,
/// então o prazo é longo; o serviço fica Running (`ready`) para não parar a
/// partida dos outros.
const WAIT_NS: u64 = 8_000_000_000;
const TRY_NS: u64 = 50_000_000;
/// Prazo de cada `connect`: curto, para sair logo se o `svcmgr` desligar.
const CALL_NS: u64 = 200_000_000;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// `interface_id(nome, 1)` (ADR 0033).
fn interface_id(name: &[u8]) -> u32 {
    let mut full = [0u8; 64];
    full[..name.len()].copy_from_slice(name);
    full[name.len()..name.len() + 2].copy_from_slice(b"@1");
    hash(&full[..name.len() + 2])
}

/// Pausa entre as tentativas: cede a vez até passar `TRY_NS`. Não usa
/// notificação nem timer: uma thread parada numa notificação da própria
/// tabela não morre no desligamento do `svcmgr` e prenderia a cota (ADR 0029).
fn pause() {
    let until = ostd::time::now_ns().saturating_add(TRY_NS);
    while ostd::time::now_ns() < until {
        ostd::thread::yield_now();
    }
}

/// Espera o driver partir: `connect` devolve `NotRunning` até ele chamar
/// `ready`.
fn connect(s: &mut Session, name: &[u8]) -> Option<Handle> {
    let iid = interface_id(name);
    let until = ostd::time::now_ns().saturating_add(WAIT_NS);
    while ostd::time::now_ns() < until {
        let call_until = ostd::time::now_ns().saturating_add(CALL_NS);
        match s.connect_svc_until(iid, 0, call_until) {
            Ok(Ok(h)) => return Some(h),
            // O `svcmgr` encerrou (canal de controle revogado): sair já, para
            // não prender a cota além do desligamento.
            Err(Error::TimedOut) | Ok(Err(_)) => {}
            Err(_) => return None,
        }
        pause();
    }
    None
}

fn console(s: &mut Session) {
    let Some(ep) = connect(s, b"optimus.console.Console") else {
        ostd::debug::print("drvcli: console: sem driver");
        return;
    };
    let text = "drvcli: ola pelo contrato Console\n";
    match ConsoleCliente::new(ep).write(&mut s.buffer, text) {
        Ok(Ok(n)) if n as usize == text.len() => ostd::debug::print("drvcli: console ok"),
        r => ostd::debug::print_fmt(format_args!("drvcli: console: falhou ({r:?})")),
    }
}

fn main(start: Start) -> ! {
    let mut s = match Session::start(start.args) {
        Ok(s) => s,
        Err(e) => {
            ostd::debug::print_fmt(format_args!("drvcli: Session::start {e:?}"));
            ostd::thread::exit()
        }
    };
    if let Some(c) = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_KERNEL && c.name_hash == hash(b"debug"))
    {
        ostd::debug::set_log(Handle::from_raw(c.handle));
    }
    let _ = s.ready();
    console(&mut s);
    ostd::thread::exit()
}
