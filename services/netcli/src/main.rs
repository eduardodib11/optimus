//! `netcli` (T-637; ADR 0068): cliente de teste dos sockets do `netd`, o
//! único com `NetAccess`. Prova, pelo contrato `socket.oidl`:
//!
//! 1. um destino fora da política é negado, sem tráfego;
//! 2. TCP ao eco do host (10.0.2.2:47108): conecta, manda uma carga maior que
//!    um MSS e confere o que volta;
//! 3. UDP ao eco do host (10.0.2.2:47107).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::ring::{Consumer, Producer};
use ostd::rt::Start;
use ostd::svc::Session;

mod socket_cliente;

use socket_cliente::SocketCliente;

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
const WAIT_NS: u64 = 8_000_000_000;
const TRY_NS: u64 = 50_000_000;
const CALL_NS: u64 = 200_000_000;
/// Quanto esperar um evento ou dado do `netd`.
const IO_NS: u64 = 5_000_000_000;

/// O servidor de eco do host, visto pelo roteador do QEMU.
const HOST: u32 = u32::from_be_bytes([10, 0, 2, 2]);
const UDP_ECHO_PORT: u16 = 47107;
const TCP_ECHO_PORT: u16 = 47108;

/// Anéis de dados (o contrato) e onde ficam mapeados.
const RING_BYTES: u32 = 8192;
const VA: u64 = 0x50_0000_0000;
const VA_STRIDE: u64 = 0x10_0000;
const RX_KIND: u16 = 0x0E11;
/// Registros do `rx` (o contrato).
const KIND_DATA: u16 = 1;
const KIND_EVENT: u16 = 2;
const EV_CONNECTED: u8 = 1;

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

/// Cede a vez até passar `ns` (sem `Notification` nem `Timer`: uma thread
/// parada numa notificação da própria tabela não morre no desligamento do
/// `svcmgr`; ADR 0029).
fn pause(ns: u64) {
    let until = ostd::time::now_ns().saturating_add(ns);
    while ostd::time::now_ns() < until {
        ostd::thread::yield_now();
    }
}

/// Espera o `netd` partir: `connect` devolve `NotRunning` até ele chamar `ready`.
fn connect(s: &mut Session) -> Option<Handle> {
    let iid = interface_id(b"optimus.net.Socket");
    let until = ostd::time::now_ns().saturating_add(WAIT_NS);
    while ostd::time::now_ns() < until {
        let call_until = ostd::time::now_ns().saturating_add(CALL_NS);
        match s.connect_svc_until(iid, 0, call_until) {
            Ok(Ok(h)) => return Some(h),
            Err(Error::TimedOut) | Ok(Err(_)) => {}
            Err(_) => return None,
        }
        pause(TRY_NS);
    }
    None
}

/// Um socket aberto: os anéis e o número.
struct Sock {
    id: u32,
    tx: Producer,
    rx: Consumer,
}

/// Abre um socket de `proto` (0 UDP, 1 TCP) na vaga de mapeamento `slot`.
fn open(
    cli: &SocketCliente,
    s: &mut Session,
    quota: Handle,
    proto: u8,
    slot: u64,
) -> Result<Sock, &'static str> {
    let buf = &mut s.buffer;
    let rx_obj = ostd::cap::create(
        quota,
        ObjectType::MemoryObject,
        ostd::ring::object_bytes(RING_BYTES),
    )
    .map_err(|_| "criar o anel")?;
    let ntfy = ostd::cap::create(quota, ObjectType::Notification, 0)
        .map_err(|_| "criar a Notification")?;
    let va = VA + slot * VA_STRIDE;
    let rx =
        Consumer::create(rx_obj, va, RING_BYTES, RX_KIND, ntfy).map_err(|_| "mapear o anel")?;
    let rx_rw = ostd::cap::mint(rx_obj, Rights::MAP | Rights::READ | Rights::WRITE, 0, None)
        .map_err(|_| "cunhar o anel")?;
    let wake =
        ostd::cap::mint(ntfy, Rights::SIGNAL, 0, None).map_err(|_| "cunhar a Notification")?;
    let id = match cli.open(buf, proto, rx_rw, wake) {
        Ok(Ok(id)) => id,
        Ok(Err(e)) => {
            ostd::debug::print_fmt(format_args!("netcli: open negado ({})", e.0));
            return Err("open");
        }
        Err(e) => {
            ostd::debug::print_fmt(format_args!("netcli: open: erro {e:?}"));
            return Err("open: IPC");
        }
    };
    let Ok(Ok(tx_obj)) = cli.tx_ring(buf, id) else {
        return Err("tx_ring");
    };
    let Ok(Ok(tx_sig)) = cli.tx_signal(buf, id) else {
        return Err("tx_signal");
    };
    let tx =
        Producer::open(tx_obj, va + 0x8_0000, RING_BYTES, tx_sig, 1).map_err(|_| "abrir o tx")?;
    Ok(Sock { id, tx, rx })
}

/// Espera um evento de `code` no `rx` até `IO_NS`.
fn wait_event(sock: &mut Sock, code: u8) -> bool {
    let until = ostd::time::now_ns().saturating_add(IO_NS);
    let mut b = [0u8; 4096];
    while ostd::time::now_ns() < until {
        match sock.rx.pop(&mut b) {
            Ok(Some((KIND_EVENT, 2))) => {
                if b[0] == code {
                    return true;
                }
                ostd::debug::print_fmt(format_args!("netcli: evento {} arg {}", b[0], b[1]));
                return false;
            }
            Ok(Some(_)) => {}
            Ok(None) => pause(1_000_000),
            Err(_) => return false,
        }
    }
    false
}

/// Carga do eco: passa de um MSS, para exercitar a segmentação.
fn byte(i: usize) -> u8 {
    u8::try_from((i * 13 + i / 5) % 251).unwrap_or(0)
}

/// Lê do `rx` até `want` bytes de dados, conferindo cada um (prazo `IO_NS`).
fn read_echo(sock: &mut Sock, want: usize) -> bool {
    read_echo_for(sock, want, IO_NS)
}

fn tcp(cli: &SocketCliente, s: &mut Session, quota: Handle) -> Result<(), &'static str> {
    let mut sock = open(cli, s, quota, 1, 0)?;
    // Fora da política: negado na hora, e o socket continua utilizável.
    match cli.connect(&mut s.buffer, sock.id, HOST, TCP_ECHO_PORT + 1) {
        Ok(Err(e)) if e == socket_cliente::SocketError::Denied => {
            ostd::debug::print("netcli: política: destino fora da lista negado");
        }
        _ => return Err("destino fora da política não foi negado"),
    }
    if !matches!(
        cli.connect(&mut s.buffer, sock.id, HOST, TCP_ECHO_PORT),
        Ok(Ok(()))
    ) {
        return Err("connect");
    }
    if !wait_event(&mut sock, EV_CONNECTED) {
        return Err("conexão não abriu");
    }
    let mut payload = [0u8; 4000];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = byte(i);
    }
    for chunk in payload.chunks(1000) {
        sock.tx.push(1, chunk).map_err(|_| "anel de transmissão")?;
    }
    if !read_echo(&mut sock, payload.len()) {
        return Err("eco com dado errado");
    }
    let _ = cli.close(&mut s.buffer, sock.id);
    ostd::debug::print("netcli: tcp: eco do host");
    Ok(())
}

fn udp(cli: &SocketCliente, s: &mut Session, quota: Handle) -> Result<(), &'static str> {
    let mut sock = open(cli, s, quota, 0, 1)?;
    if !matches!(
        cli.connect(&mut s.buffer, sock.id, HOST, UDP_ECHO_PORT),
        Ok(Ok(()))
    ) {
        return Err("connect udp");
    }
    let mut dgram = [0u8; 300];
    for (i, b) in dgram.iter_mut().enumerate() {
        *b = byte(i);
    }
    // O primeiro datagrama pode esperar o ARP; o UDP não retransmite, o
    // cliente é que tenta de novo se o eco não vier.
    for _ in 0..5 {
        sock.tx.push(1, &dgram).map_err(|_| "anel de transmissão")?;
        if read_echo_for(&mut sock, dgram.len(), 500_000_000) {
            let _ = cli.close(&mut s.buffer, sock.id);
            ostd::debug::print("netcli: udp: eco do host");
            return Ok(());
        }
    }
    Err("sem eco udp")
}

/// Como [`read_echo`], com prazo de `ns`.
fn read_echo_for(sock: &mut Sock, want: usize, ns: u64) -> bool {
    let until = ostd::time::now_ns().saturating_add(ns);
    let mut b = [0u8; 4096];
    let mut got = 0;
    while got < want && ostd::time::now_ns() < until {
        match sock.rx.pop(&mut b) {
            Ok(Some((KIND_DATA, n))) => {
                if (0..n).any(|k| b[k] != byte(got + k)) {
                    return false;
                }
                got += n;
            }
            Ok(Some(_)) => {}
            Ok(None) => pause(1_000_000),
            Err(_) => return false,
        }
    }
    got == want
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
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let Some(ep) = connect(&mut s) else {
        ostd::debug::print("netcli: sem serviço de sockets");
        ostd::thread::exit()
    };
    let cli = SocketCliente::new(ep);
    if let Err(e) = tcp(&cli, &mut s, quota) {
        ostd::debug::print_fmt(format_args!("netcli: tcp: falhou ({e})"));
    }
    if let Err(e) = udp(&cli, &mut s, quota) {
        ostd::debug::print_fmt(format_args!("netcli: udp: falhou ({e})"));
    }
    ostd::thread::exit()
}
