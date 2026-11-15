//! `drvcli` (T-514; ADR 0046, item 5): o cliente de teste dos contratos OIDL
//! dos drivers virtio. Sobe no boot, espera o `devmgr` partir cada driver,
//! conecta ao endpoint dele pelo `svcmgr` (`connect`) e faz uma chamada pelo
//! cliente gerado do `.oidl`. Cada contrato que responde vira uma linha
//! `drvcli: <contrato> ok`, que o `cargo xtask test` confere.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]

use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::ring::{Consumer, Producer};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::vm::{Mapping, SELF};

mod block_cliente;
mod console_cliente;
mod display_cliente;
mod entropy_cliente;
mod net_cliente;

use block_cliente::BlockDeviceCliente;
use console_cliente::ConsoleCliente;
use display_cliente::DisplayDeviceCliente;
use entropy_cliente::EntropySourceCliente;
use net_cliente::NetDeviceCliente;

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

fn display(s: &mut Session) {
    let Some(ep) = connect(s, b"optimus.display.DisplayDevice") else {
        ostd::debug::print("drvcli: display: sem driver");
        return;
    };
    let cli = DisplayDeviceCliente::new(ep);
    let buf = &mut s.buffer;
    let ok = matches!(cli.mode_count(buf), Ok(Ok(1)))
        && matches!(cli.mode(buf, 0), Ok(Ok(m)) if m.width == 64 && m.height == 64)
        && matches!(cli.mode(buf, 1), Ok(Err(e)) if e == display_cliente::DisplayError::BadMode)
        && matches!(cli.set_mode(buf, 0), Ok(Ok(())))
        && matches!(cli.present(buf, 0, 0, 64, 64), Ok(Ok(())))
        && matches!(cli.present(buf, 60, 0, 8, 8), Ok(Err(e)) if e == display_cliente::DisplayError::BadRect);
    if ok {
        ostd::debug::print("drvcli: display ok");
    } else {
        ostd::debug::print("drvcli: display: falhou");
    }
}

/// Onde os anéis e a região de dados do `BlockDevice` ficam mapeados.
const SUBMIT_VA: u64 = 0x30_0000_0000;
const DONE_VA: u64 = 0x30_0010_0000;
const DATA_VA: u64 = 0x30_0020_0000;
/// Mesmos valores que o driver informa em `info()`.
const RING_BYTES: u32 = 4096;
const PAGE: usize = 4096;
const WINDOW_NS: u64 = 2_000_000_000;

/// Espera a conclusão de `id` no anel de conclusões e devolve o status.
fn completion(done: &mut Consumer, id: u64) -> Option<u8> {
    let until = ostd::time::now_ns().saturating_add(WINDOW_NS);
    let mut rec = [0u8; 16];
    while ostd::time::now_ns() < until {
        match done.pop(&mut rec) {
            Ok(Some((_, 16))) if u64::from_le_bytes(rec[..8].try_into().ok()?) == id => {
                return Some(rec[8]);
            }
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) => ostd::thread::yield_now(),
        }
    }
    None
}

/// Um pedido de submissão (24 bytes de carga; ADR 0056, item 4).
fn submit(ring: &mut Producer, id: u64, op: u8, count: u16, sector: u64) -> bool {
    let mut b = [0u8; 24];
    b[..8].copy_from_slice(&id.to_le_bytes());
    b[8] = op;
    b[10..12].copy_from_slice(&count.to_le_bytes());
    b[16..24].copy_from_slice(&sector.to_le_bytes());
    ring.push(1, &b).is_ok()
}

/// Faz o papel do `storaged`: pega os anéis pelo contrato `BlockDevice`,
/// escreve, lê, esvazia e recusa pedidos ruins.
fn block_steps(s: &mut Session, ep: Handle, quota: Handle) -> Option<()> {
    let cli = BlockDeviceCliente::new(ep);
    let buf = &mut s.buffer;
    let info = cli.info(buf).ok()?.ok()?;
    if info.sectors != 2048
        || info.sector_size != 512
        || info.max_sectors != 8
        || info.depth != 4
        || info.data_bytes != 4 * PAGE as u32
        || info.ring_bytes != RING_BYTES
        || info.read_only
    {
        return None;
    }
    let session = BlockDeviceCliente::new(cli.session(buf).ok()?.ok()?);
    let submit_obj = session.submit_ring(buf).ok()?.ok()?;
    let submit_sig = session.submit_signal(buf).ok()?.ok()?;
    let data_obj = session.data_region(buf).ok()?.ok()?;
    // O anel de conclusões é do `storaged`: ele o cria e o dá ao driver.
    let done_obj = ostd::cap::create(
        quota,
        ObjectType::MemoryObject,
        ostd::ring::object_bytes(RING_BYTES),
    )
    .ok()?;
    let done_ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).ok()?;
    let mut done = Consumer::create(done_obj, DONE_VA, RING_BYTES, 0x0B02, done_ntfy).ok()?;
    let done_sig = ostd::cap::mint(done_ntfy, Rights::SIGNAL, 0, None).ok()?;
    let done_rw = ostd::cap::mint(
        done_obj,
        Rights::MAP | Rights::READ | Rights::WRITE,
        0,
        None,
    )
    .ok()?;
    session.attach_done(buf, done_rw, done_sig).ok()?.ok()?;
    // Uma segunda ligação é recusada.
    if !matches!(session.attach_done(buf, done_rw, done_sig), Ok(Err(_))) {
        return None;
    }
    let mut ring = Producer::open(submit_obj, SUBMIT_VA, RING_BYTES, submit_sig, 1).ok()?;
    let mut data = Mapping::new(
        SELF,
        data_obj,
        DATA_VA,
        4 * PAGE as u64,
        ostd::kabi::vm::WRITE,
    )
    .ok()?;
    let mut pattern = [0u8; PAGE];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7) ^ 0x5a;
    }
    data.bytes_mut()?[..PAGE].copy_from_slice(&pattern);
    // Escreve o setor 8 (4 KiB), esvazia o buffer e lê de volta.
    if !submit(&mut ring, 1, 1, 8, 8) || completion(&mut done, 1)? != 0 {
        return None;
    }
    data.bytes_mut()?[..PAGE].fill(0);
    if !submit(&mut ring, 2, 0, 8, 8) || completion(&mut done, 2)? != 0 {
        return None;
    }
    if data.bytes()[..PAGE] != pattern[..] {
        return None;
    }
    // FLUSH, e os pedidos ruins: fora do disco, operação desconhecida,
    // mais setores que o máximo e deslocamento desalinhado.
    if !submit(&mut ring, 3, 2, 0, 0) || completion(&mut done, 3)? != 0 {
        return None;
    }
    if !submit(&mut ring, 4, 0, 8, 2048) || completion(&mut done, 4)? != 1 {
        return None;
    }
    if !submit(&mut ring, 5, 9, 1, 0) || completion(&mut done, 5)? != 5 {
        return None;
    }
    if !submit(&mut ring, 6, 0, 9, 0) || completion(&mut done, 6)? != 5 {
        return None;
    }
    Some(())
}

fn block(s: &mut Session, quota: Handle) {
    let Some(ep) = connect(s, b"optimus.block.BlockDevice") else {
        ostd::debug::print("drvcli: block: sem driver");
        return;
    };
    if block_steps(s, ep, quota).is_some() {
        ostd::debug::print("drvcli: block ok");
    } else {
        ostd::debug::print("drvcli: block: falhou");
    }
}

/// Anéis do `NetDevice`: 16 KiB de dados cada (o que `info()` informa).
const NET_TX_VA: u64 = 0x30_0100_0000;
const NET_RX_VA: u64 = 0x30_0200_0000;
const NET_RING_BYTES: u32 = 16384;

/// Faz o papel do futuro `netd`: liga os anéis pelo contrato `NetDevice`,
/// manda um ARP para o gateway e espera a resposta pelo anel de recepção.
fn net_steps(s: &mut Session, ep: Handle, quota: Handle) -> Option<()> {
    let cli = NetDeviceCliente::new(ep);
    let buf = &mut s.buffer;
    let info = cli.info(buf).ok()?.ok()?;
    if info.mac == 0
        || info.ring_bytes != NET_RING_BYTES
        || info.max_frame != 1514
        || info.mtu != 1500
    {
        return None;
    }
    let mac = &info.mac.to_le_bytes()[..6];
    let session = NetDeviceCliente::new(cli.session(buf).ok()?.ok()?);
    let tx_obj = session.tx_ring(buf).ok()?.ok()?;
    let tx_sig = session.tx_signal(buf).ok()?.ok()?;
    let rx_obj = ostd::cap::create(
        quota,
        ObjectType::MemoryObject,
        ostd::ring::object_bytes(NET_RING_BYTES),
    )
    .ok()?;
    let rx_ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).ok()?;
    let mut rx = Consumer::create(rx_obj, NET_RX_VA, NET_RING_BYTES, 0x0E02, rx_ntfy).ok()?;
    let rx_sig = ostd::cap::mint(rx_ntfy, Rights::SIGNAL, 0, None).ok()?;
    let rx_rw =
        ostd::cap::mint(rx_obj, Rights::MAP | Rights::READ | Rights::WRITE, 0, None).ok()?;
    session.attach_rx(buf, rx_rw, rx_sig).ok()?.ok()?;
    if !matches!(session.attach_rx(buf, rx_rw, rx_sig), Ok(Err(_))) {
        return None;
    }
    let mut tx = Producer::open(tx_obj, NET_TX_VA, NET_RING_BYTES, tx_sig, 1).ok()?;
    // ARP "quem tem 10.0.2.2", de 10.0.2.15.
    let mut f = [0u8; 42];
    f[0..6].fill(0xff);
    f[6..12].copy_from_slice(mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f[22..28].copy_from_slice(mac);
    f[28..32].copy_from_slice(&[10, 0, 2, 15]);
    f[38..42].copy_from_slice(&[10, 0, 2, 2]);
    tx.push(1, &f).ok()?;
    let until = ostd::time::now_ns().saturating_add(WINDOW_NS);
    let mut rec = [0u8; 2048];
    while ostd::time::now_ns() < until {
        match rx.pop(&mut rec) {
            Ok(Some((1, n)))
                if n >= 42
                    && rec[12..14] == [0x08, 0x06]
                    && rec[20..22] == [0, 2]
                    && rec[28..32] == [10, 0, 2, 2]
                    && rec[32..38] == *mac =>
            {
                return Some(());
            }
            Ok(Some(_)) => {}
            Ok(None) => ostd::thread::yield_now(),
            Err(_) => return None,
        }
    }
    None
}

fn net(s: &mut Session, quota: Handle) {
    let Some(ep) = connect(s, b"optimus.net.NetDevice") else {
        ostd::debug::print("drvcli: net: sem driver");
        return;
    };
    if net_steps(s, ep, quota).is_some() {
        ostd::debug::print("drvcli: net ok");
    } else {
        ostd::debug::print("drvcli: net: falhou");
    }
}

fn entropy(s: &mut Session) {
    let Some(ep) = connect(s, b"optimus.dev.EntropySource") else {
        ostd::debug::print("drvcli: entropy: sem driver");
        return;
    };
    let cli = EntropySourceCliente::new(ep);
    let first = cli.read(&mut s.buffer, 32);
    let second = cli.read(&mut s.buffer, 32);
    // Dois blocos de 32 bytes que diferem entre si, pelo contrato gerado.
    let ok = matches!((&first, &second), (Ok(Ok(one)), Ok(Ok(two)))
        if one.as_slice().len() == 32 && two.as_slice().len() == 32 && one.as_slice() != two.as_slice());
    if ok {
        ostd::debug::print("drvcli: entropy ok");
    } else {
        ostd::debug::print("drvcli: entropy: falhou");
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
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    console(&mut s);
    display(&mut s);
    block(&mut s, quota);
    net(&mut s, quota);
    entropy(&mut s);
    ostd::thread::exit()
}
