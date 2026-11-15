//! `keyd` (T-518; ADR 0053 e 0054): o serviço que guarda as chaves do
//! sistema. Nesta etapa ele só monta a semente do gerador de bytes:
//!
//! 1. lê 72 bytes do kernel (três chamadas de `sys_info` de entropia), que
//!    são obrigatórios: sem eles o `keyd` não cria chave nenhuma (item 1);
//! 2. pede 64 bytes ao `EntropySource` do virtio-rng, se o driver existir e
//!    estiver saudável (itens 2, 3 e 5);
//! 3. mistura as duas fontes e a chave atual no [`Drbg`] (item 4).
//!
//! A imagem normal não registra nada da semente. A de teste (`xtask test`,
//! `OPTIMUS_KTEST_DEBUG`) registra impressões digitais de 64 bits
//! (BLAKE3 truncado) da contribuição virtio e da semente (item 6).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use optcrypt::drbg::Drbg;
use ostd::kabi::{Error, Handle};
use ostd::rt::Start;
use ostd::svc::Session;

mod entropy_cliente;

use entropy_cliente::EntropySourceCliente;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Imagem de teste: só ela mostra impressões digitais (ADR 0054, item 6).
const TESTE: bool = option_env!("OPTIMUS_KTEST_DEBUG").is_some();
/// Bytes do kernel na semente (três chamadas de 24 bytes).
const KERNEL_BYTES: usize = 72;
/// Bytes pedidos ao virtio-rng.
const VIRTIO_BYTES: u8 = 64;
/// Quanto esperar o driver partir. Sem o dispositivo o driver nunca parte.
const WAIT_NS: u64 = 2_000_000_000;
const TRY_NS: u64 = 10_000_000;
/// Prazo de cada `connect`: curto, para sair logo se o `svcmgr` desligar.
const CALL_NS: u64 = 100_000_000;

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

/// Cede a vez até passar `TRY_NS` (sem notificação nem timer: veja o `drvcli`).
fn pause() {
    let until = ostd::time::now_ns().saturating_add(TRY_NS);
    while ostd::time::now_ns() < until {
        ostd::thread::yield_now();
    }
}

/// Espera o driver partir: `connect` devolve `NotRunning` até ele chamar `ready`.
fn connect(s: &mut Session, name: &[u8]) -> Option<Handle> {
    let iid = interface_id(name);
    let until = ostd::time::now_ns().saturating_add(WAIT_NS);
    while ostd::time::now_ns() < until {
        let call_until = ostd::time::now_ns().saturating_add(CALL_NS);
        match s.connect_svc_until(iid, 0, call_until) {
            Ok(Ok(h)) => return Some(h),
            Err(Error::TimedOut) | Ok(Err(_)) => {}
            Err(_) => return None,
        }
        pause();
    }
    None
}

/// Os 64 bytes do virtio-rng; `None` se não há driver ou ele falhou.
fn virtio(s: &mut Session, out: &mut [u8; VIRTIO_BYTES as usize]) -> Option<usize> {
    let ep = connect(s, b"optimus.dev.EntropySource")?;
    match EntropySourceCliente::new(ep).read(&mut s.buffer, VIRTIO_BYTES) {
        Ok(Ok(bytes)) => {
            let b = bytes.as_slice();
            out[..b.len()].copy_from_slice(b);
            Some(b.len())
        }
        _ => None,
    }
}

/// Impressão digital de 64 bits (BLAKE3 truncado) para o log de teste.
fn fingerprint(data: &[u8]) -> u64 {
    let h = optcrypt::blake3::hash(data);
    u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
}

fn run(s: &mut Session) {
    let mut kernel = [0u8; KERNEL_BYTES];
    if ostd::rand::secure_fill(&mut kernel).is_err() {
        // Sem a fonte do kernel, nenhuma chave nasce (ADR 0054, item 1).
        ostd::debug::print("keyd: sem entropia do kernel; não cria chaves");
        return;
    }
    let mut dev = [0u8; VIRTIO_BYTES as usize];
    let got = virtio(s, &mut dev).unwrap_or(0);
    if got == 0 {
        ostd::debug::print("keyd: sem virtio-rng; semente só do kernel");
    }
    let mut drbg = Drbg::new();
    if drbg.reseed(&kernel, &dev[..got]).is_err() {
        ostd::debug::print("keyd: falha ao semear");
        return;
    }
    if TESTE {
        let mut seed = [0u8; 32];
        let _ = drbg.fill(&mut seed);
        ostd::debug::print_fmt(format_args!(
            "keyd: contribuição virtio={:016x}",
            fingerprint(&dev[..got])
        ));
        ostd::debug::print_fmt(format_args!("keyd: semente={:016x}", fingerprint(&seed)));
    }
    ostd::debug::print("keyd: gerador semeado");
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
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
    run(&mut s);
    ostd::thread::exit()
}
