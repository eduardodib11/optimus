//! `tlshost [--ip 127.0.0.1] [--base 47109]`: os servidores TLS de teste do
//! `xtask test virtio`, vistos pelo convidado em 10.0.2.2.
//!
//! - `base`: o bom (P-256, TLS 1.3, grupo híbrido);
//! - `base + 1`: só TLS 1.2 (o `tlsd` tem de recusar);
//! - `base + 2`: TLS 1.3 sem o grupo híbrido (o `tlsd` tem de recusar).
//!
//! Fica no ar até o processo ser morto.

use std::net::SocketAddr;

use tlshost::{Opts, Server};

fn main() -> Result<(), String> {
    let mut ip = "127.0.0.1".to_owned();
    let mut base = 47109u16;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match (a.as_str(), args.next()) {
            ("--ip", Some(v)) => ip = v,
            ("--base", Some(v)) => base = v.parse().map_err(|_| "porta inválida")?,
            _ => return Err("uso: tlshost [--ip ADDR] [--base PORTA]".into()),
        }
    }
    let at = |n: u16| -> Result<SocketAddr, String> {
        format!("{ip}:{}", base + n)
            .parse()
            .map_err(|_| "endereço inválido".to_owned())
    };
    let good = Server::start(at(0)?, &Opts::default()).map_err(|e| e.to_string())?;
    let old = Server::start(
        at(1)?,
        &Opts {
            tls12_only: true,
            ..Opts::default()
        },
    )
    .map_err(|e| e.to_string())?;
    let plain = Server::start(
        at(2)?,
        &Opts {
            hybrid: false,
            ..Opts::default()
        },
    )
    .map_err(|e| e.to_string())?;
    println!(
        "tlshost: bom {}, TLS 1.2 {}, sem híbrido {}",
        good.addr, old.addr, plain.addr
    );
    loop {
        std::thread::park();
    }
}
