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

mod console_cliente;
mod display_cliente;
mod entropy_cliente;
mod input_cliente;
mod net_cliente;
mod optfs_step;
mod storage_cliente;

use console_cliente::ConsoleCliente;
use display_cliente::DisplayDeviceCliente;
use entropy_cliente::EntropySourceCliente;
use input_cliente::InputDeviceCliente;
use net_cliente::NetDeviceCliente;
use storage_cliente::{BlockStoreCliente, StorageCliente};

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

/// Onde os anéis e a área do `BlockStore` ficam mapeados.
const SUBMIT_VA: u64 = 0x30_0000_0000;
const DONE_VA: u64 = 0x30_0010_0000;
const DATA_VA: u64 = 0x30_0020_0000;
const RING_BYTES: u32 = 4096;
const PAGE: usize = 4096;
/// Blocos da região de dados da fila de teste.
const DATA_BLOCKS: u16 = 8;
const WINDOW_NS: u64 = 2_000_000_000;
/// Blocos da partição `data` do disco de teste (`xtask`: 14303 setores).
const DATA_PART_BLOCKS: u64 = 1787;

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
fn submit(
    ring: &mut Producer,
    id: u64,
    op: u8,
    flags: u8,
    count: u16,
    offset: u32,
    block: u64,
) -> bool {
    let mut b = [0u8; 24];
    b[..8].copy_from_slice(&id.to_le_bytes());
    b[8] = op;
    b[9] = flags;
    b[10..12].copy_from_slice(&count.to_le_bytes());
    b[12..16].copy_from_slice(&offset.to_le_bytes());
    b[16..24].copy_from_slice(&block.to_le_bytes());
    ring.push(1, &b).is_ok()
}

/// Uma fila aberta num `BlockStore`: o cliente do contrato.
struct Fila {
    store: BlockStoreCliente,
    id: u32,
    ring: Producer,
    done: Consumer,
    data: Mapping,
}

/// Abre uma fila no `BlockStore` `ep` (a área é do cliente: anel de
/// conclusões e região de dados).
fn open_fila(buf: &mut ostd::ipc::Buffer, quota: Handle, ep: Handle) -> Option<Fila> {
    let store = BlockStoreCliente::new(ep);
    let bytes = ostd::ring::object_bytes(RING_BYTES) + u64::from(DATA_BLOCKS) * PAGE as u64;
    let area = ostd::cap::create(quota, ObjectType::MemoryObject, bytes).ok()?;
    let ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).ok()?;
    let done = Consumer::create(area, DONE_VA, RING_BYTES, 0x0B02, ntfy).ok()?;
    let area_rw =
        ostd::cap::mint(area, Rights::MAP | Rights::READ | Rights::WRITE, 0, None).ok()?;
    let sig = ostd::cap::mint(ntfy, Rights::SIGNAL, 0, None).ok()?;
    let id = store
        .open_queue(buf, area_rw, sig, 4, 1, DATA_BLOCKS)
        .ok()?
        .ok()?;
    let submit_obj = store.submit_ring(buf, id).ok()?.ok()?;
    let kick = store.kick(buf, id).ok()?.ok()?;
    let ring = Producer::open(submit_obj, SUBMIT_VA, RING_BYTES, kick, 1).ok()?;
    let data = Mapping::new_at(
        SELF,
        area,
        DATA_VA,
        ostd::ring::object_bytes(RING_BYTES),
        u64::from(DATA_BLOCKS) * PAGE as u64,
        ostd::kabi::vm::WRITE,
    )
    .ok()?;
    Some(Fila {
        store,
        id,
        ring,
        done,
        data,
    })
}

/// Pedidos de bloco na partição `data`, num quadro de pilha próprio (o
/// padrão de 8 KiB não fica vivo durante o `OptFS`).
#[inline(never)]
fn block_steps(buf: &mut ostd::ipc::Buffer, quota: Handle, data: Handle) -> Option<()> {
    let mut f = open_fila(buf, quota, data)?;
    let mut pattern = [0u8; 2 * PAGE];
    for (i, b) in pattern.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13) ^ 0x3c;
    }
    f.data.bytes_mut()?[..2 * PAGE].copy_from_slice(&pattern);
    // Escreve 2 blocos com FUA no bloco 3, zera o buffer e lê de volta.
    if !submit(&mut f.ring, 1, 1, 1, 2, 0, 3) || completion(&mut f.done, 1)? != 0 {
        return None;
    }
    f.data.bytes_mut()?[..2 * PAGE].fill(0);
    if !submit(&mut f.ring, 2, 0, 0, 2, 0, 3) || completion(&mut f.done, 2)? != 0 {
        return None;
    }
    if optcrypt::blake3::hash(&f.data.bytes()[..2 * PAGE]) != optcrypt::blake3::hash(&pattern) {
        return None;
    }
    // O último bloco da partição lê, e um além dele não.
    if !submit(&mut f.ring, 3, 0, 0, 1, 0, DATA_PART_BLOCKS - 1) || completion(&mut f.done, 3)? != 0
    {
        return None;
    }
    if !submit(&mut f.ring, 4, 0, 0, 1, 0, DATA_PART_BLOCKS) || completion(&mut f.done, 4)? != 1 {
        return None;
    }
    // FLUSH; operação desconhecida; mais blocos que o máximo; deslocamento
    // desalinhado; região de dados estourada.
    if !submit(&mut f.ring, 5, 2, 0, 0, 0, 0) || completion(&mut f.done, 5)? != 0 {
        return None;
    }
    if !submit(&mut f.ring, 6, 9, 0, 1, 0, 0) || completion(&mut f.done, 6)? != 5 {
        return None;
    }
    if !submit(&mut f.ring, 7, 0, 0, 33, 0, 0) || completion(&mut f.done, 7)? != 5 {
        return None;
    }
    if !submit(&mut f.ring, 8, 0, 0, 1, 1, 0) || completion(&mut f.done, 8)? != 5 {
        return None;
    }
    if !submit(
        &mut f.ring,
        9,
        0,
        0,
        2,
        (u32::from(DATA_BLOCKS) - 1) * PAGE as u32,
        0,
    ) || completion(&mut f.done, 9)? != 5
    {
        return None;
    }
    if !matches!(f.store.close_queue(buf, f.id), Ok(Ok(()))) {
        return None;
    }
    // Solta os mapeamentos: a próxima fila usa os mesmos endereços.
    drop(f);
    Some(())
}

/// Faz o papel de um cliente do `storaged` (T-520): lê e escreve blocos da
/// partição `data` com checksum igual, recusa pedidos ruins e confere que a
/// `sys-a` é só de leitura.
fn storage_steps(s: &mut Session, ep: Handle, quota: Handle) -> Option<()> {
    let storage = StorageCliente::new(ep);
    let buf = &mut s.buffer;
    // Partição que não existe.
    if !matches!(storage.open(buf, "nada"), Ok(Err(_))) {
        return None;
    }
    let data = storage.open(buf, "data").ok()?.ok()?;
    let info = BlockStoreCliente::new(data).info(buf).ok()?.ok()?;
    if info.blocks != DATA_PART_BLOCKS || info.read_only || info.max_blocks != 32 {
        return None;
    }
    block_steps(buf, quota, data)?;
    // O `OptFS` sobre a mesma partição (T-522).
    let mut o = open_fila(buf, quota, data)?;
    optfs_step::run(&mut o, info.blocks)?;
    ostd::debug::print("drvcli: optfs ok");
    if !matches!(o.store.close_queue(buf, o.id), Ok(Ok(()))) {
        return None;
    }
    drop(o);
    // A `sys-a` é só de leitura no M5: a escrita volta `ReadOnly` e a
    // leitura funciona.
    let sys = storage.open(buf, "sys-a").ok()?.ok()?;
    if !BlockStoreCliente::new(sys).info(buf).ok()?.ok()?.read_only {
        return None;
    }
    let mut g = open_fila(buf, quota, sys)?;
    if !submit(&mut g.ring, 1, 1, 0, 1, 0, 0) || completion(&mut g.done, 1)? != 2 {
        return None;
    }
    if !submit(&mut g.ring, 2, 0, 0, 1, 0, 0) || completion(&mut g.done, 2)? != 0 {
        return None;
    }
    if !matches!(g.store.release(buf), Ok(Ok(()))) {
        return None;
    }
    Some(())
}

fn storage(s: &mut Session, quota: Handle) {
    let Some(ep) = connect(s, b"optimus.storage.Storage") else {
        ostd::debug::print("drvcli: storage: sem serviço");
        return;
    };
    if storage_steps(s, ep, quota).is_some() {
        ostd::debug::print("drvcli: storage ok");
    } else {
        ostd::debug::print("drvcli: storage: falhou");
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

/// Anel de eventos do `InputDevice`: 4 KiB de dados (o que `info()` informa).
const INPUT_VA: u64 = 0x30_0300_0000;
const INPUT_RING_BYTES: u32 = 4096;
/// Quanto esperar a tecla que o xtask injeta.
const KEY_WAIT_NS: u64 = 4_000_000_000;

/// Faz o papel do `inputd`: liga o anel de eventos pelo contrato e
/// espera a tecla `a` (evdev 30) que o xtask injeta pelo monitor.
fn input_steps(s: &mut Session, ep: Handle, quota: Handle) -> Option<Consumer> {
    let cli = InputDeviceCliente::new(ep);
    let buf = &mut s.buffer;
    let info = cli.info(buf).ok()?.ok()?;
    if info.ring_bytes != INPUT_RING_BYTES {
        return None;
    }
    let session = InputDeviceCliente::new(cli.session(buf).ok()?.ok()?);
    let obj = ostd::cap::create(
        quota,
        ObjectType::MemoryObject,
        ostd::ring::object_bytes(INPUT_RING_BYTES),
    )
    .ok()?;
    let ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).ok()?;
    let ring = Consumer::create(obj, INPUT_VA, INPUT_RING_BYTES, 0x1502, ntfy).ok()?;
    let sig = ostd::cap::mint(ntfy, Rights::SIGNAL, 0, None).ok()?;
    let rw = ostd::cap::mint(obj, Rights::MAP | Rights::READ | Rights::WRITE, 0, None).ok()?;
    session.attach_events(buf, rw, sig).ok()?.ok()?;
    if !matches!(session.attach_events(buf, rw, sig), Ok(Err(_))) {
        return None;
    }
    Some(ring)
}

fn input(s: &mut Session, quota: Handle) {
    let Some(ep) = connect(s, b"optimus.input.InputDevice") else {
        ostd::debug::print("drvcli: input: sem driver");
        return;
    };
    let Some(mut ring) = input_steps(s, ep, quota) else {
        ostd::debug::print("drvcli: input: falhou");
        return;
    };
    ostd::debug::print("drvcli: input ok");
    let until = ostd::time::now_ns().saturating_add(KEY_WAIT_NS);
    let mut rec = [0u8; 8];
    while ostd::time::now_ns() < until {
        match ring.pop(&mut rec) {
            Ok(Some((1, 8))) if rec[0..2] == [1, 0] && rec[2..4] == [30, 0] => {
                ostd::debug::print("drvcli: input evento 0x1e");
                return;
            }
            Ok(Some(_)) => {}
            Ok(None) => ostd::thread::yield_now(),
            Err(_) => return,
        }
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
    storage(&mut s, quota);
    net(&mut s, quota);
    entropy(&mut s);
    input(&mut s, quota);
    ostd::thread::exit()
}
