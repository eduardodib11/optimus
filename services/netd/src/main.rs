//! `netd` (T-630 a T-632; ADR 0017, 0064, 0068 e 0069): a pilha IP em
//! espaço de usuário. É o único cliente do `NetDevice` do driver de rede:
//! pega a sessão, liga o anel de recepção que ele consome e escreve no anel
//! de transmissão que o driver consome (ADR 0064). Os protocolos moram em
//! `onet` e se testam no host; aqui ficam só a cola com os anéis e o relógio.
//! O laço dorme na `Notification` do anel de recepção, que um `Timer`
//! periódico também sinaliza, e a cada volta esvazia o anel e dá a vez ao
//! relógio da pilha.
//!
//! Se o `netd` morre, o `svcmgr` o reinicia e o driver aceita o anel de
//! recepção do processo novo (ADR 0068, item 6).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::ring::{Consumer, Producer};
use ostd::rt::Start;
use ostd::svc::Session;

mod net_cliente;

use net_cliente::NetDeviceCliente;
use onet::eth::{self, Mac};
use onet::ip4::Config;
use onet::stack::{Event, Link, Stack};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Quanto esperar o driver partir e o intervalo entre as tentativas.
const WAIT_NS: u64 = 8_000_000_000;
const TRY_NS: u64 = 50_000_000;
/// Prazo de cada `connect`: curto, para sair logo se o `svcmgr` desligar.
const CALL_NS: u64 = 200_000_000;
/// Anéis do `NetDevice`: 16 KiB de dados cada (o que `info()` informa).
const RING_BYTES: u32 = 16384;
/// Onde os anéis ficam mapeados.
const TX_VA: u64 = 0x30_0100_0000;
const RX_VA: u64 = 0x30_0200_0000;
/// `kind` do registro de quadro nos dois anéis (ADR 0064).
const FRAME_KIND: u16 = 1;
/// Bits da `Notification` do `netd`: o anel de recepção e o relógio.
const RX_BIT: u64 = 1;
const TIMER_BIT: u64 = 2;
/// Período do relógio da pilha (ARP, e depois TCP e DHCP).
const TICK_NS: u64 = 50_000_000;
/// Endereço e roteador da rede de usuário do QEMU, até o DHCP (T-633).
const STATIC: Config = Config {
    ip: [10, 0, 2, 15],
    mask: [255, 255, 255, 0],
    gateway: [10, 0, 2, 2],
};
/// Imagem de teste (`xtask test`, `OPTIMUS_KTEST_DEBUG`): só ela faz as
/// provas ao roteador do QEMU e as registra; a imagem normal não gera tráfego
/// que ninguém pediu.
const TESTE: bool = option_env!("OPTIMUS_KTEST_DEBUG").is_some();
/// Intervalo entre os `ping` de prova ao roteador (ns) e o identificador.
const PING_NS: u64 = 500_000_000;
const PING_ID: u16 = 0x6e64;

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

/// Espera por `ntfy` até `TRY_NS` passarem, sem `thread_local!` (o `sleep` do
/// `ostd` aloca no heap, e a cota do `netd` não paga o segmento de 2 MiB) e
/// sem ceder a vez em laço: o `netd` tem prioridade 150, acima da do driver
/// (120), que ficaria sem CPU.
fn pause(timer: Handle, ntfy: Handle) {
    let _ = ostd::cap::ntfy_poll(ntfy);
    let armed = ostd::cap::arm_timer(
        timer,
        ntfy,
        TIMER_BIT,
        TRY_NS,
        0,
        ostd::kabi::timer::RELATIVE,
    );
    if armed.is_ok() {
        let _ = ostd::cap::ntfy_wait(ntfy);
    }
}

/// Espera o driver partir: `connect` devolve `NotRunning` até ele chamar `ready`.
fn connect(s: &mut Session, name: &[u8], timer: Handle, ntfy: Handle) -> Option<Handle> {
    let iid = interface_id(name);
    let until = ostd::time::now_ns().saturating_add(WAIT_NS);
    while ostd::time::now_ns() < until {
        let call_until = ostd::time::now_ns().saturating_add(CALL_NS);
        match s.connect_svc_until(iid, 0, call_until) {
            Ok(Ok(h)) => return Some(h),
            // O `svcmgr` encerrou: sair já.
            Err(Error::TimedOut) | Ok(Err(_)) => {}
            Err(_) => return None,
        }
        pause(timer, ntfy);
    }
    None
}

/// A interface de rede: MAC e os dois anéis do `NetDevice`.
struct Nic {
    mac: Mac,
    tx: Producer,
    rx: Consumer,
}

/// Os quadros da pilha saem pelo anel de transmissão.
struct TxLink<'a>(&'a mut Producer);

impl Link for TxLink<'_> {
    fn send(&mut self, frame: &[u8]) -> bool {
        self.0.push(FRAME_KIND, frame).is_ok()
    }
}

impl Nic {
    /// Liga ao driver pelo contrato (ADR 0064): `info`, a sessão, o anel de
    /// transmissão do driver e o anel de recepção que o `netd` cria.
    fn attach(s: &mut Session, ep: Handle, quota: Handle, ntfy: Handle) -> Option<Self> {
        let cli = NetDeviceCliente::new(ep);
        let buf = &mut s.buffer;
        let info = cli.info(buf).ok()?.ok()?;
        if info.mac == 0
            || info.ring_bytes != RING_BYTES
            || usize::from(info.max_frame) != eth::MAX_FRAME
            || usize::from(info.mtu) != eth::MTU
        {
            return None;
        }
        let session = NetDeviceCliente::new(cli.session(buf).ok()?.ok()?);
        let tx_obj = session.tx_ring(buf).ok()?.ok()?;
        let tx_sig = session.tx_signal(buf).ok()?.ok()?;
        let rx_obj = ostd::cap::create(
            quota,
            ObjectType::MemoryObject,
            ostd::ring::object_bytes(RING_BYTES),
        )
        .ok()?;
        let rx = Consumer::create(rx_obj, RX_VA, RING_BYTES, 0x0E02, ntfy).ok()?;
        let rx_sig = ostd::cap::mint(ntfy, Rights::SIGNAL, 0, None).ok()?;
        let rx_rw =
            ostd::cap::mint(rx_obj, Rights::MAP | Rights::READ | Rights::WRITE, 0, None).ok()?;
        session.attach_rx(buf, rx_rw, rx_sig).ok()?.ok()?;
        let tx = Producer::open(tx_obj, TX_VA, RING_BYTES, tx_sig, RX_BIT).ok()?;
        Some(Self {
            mac: Mac::from_u64(info.mac),
            tx,
            rx,
        })
    }
}

/// Laço da pilha: dorme até chegar quadro ou vencer o relógio, esvazia o
/// anel de recepção e dá a vez ao relógio.
fn run(s: &mut Session, quota: Handle) -> Result<(), &'static str> {
    let timer = ostd::cap::create(quota, ObjectType::Timer, 0).map_err(|_| "criar o Timer")?;
    let ntfy = ostd::cap::create(quota, ObjectType::Notification, 0)
        .map_err(|_| "criar a Notification")?;
    let ep = connect(s, b"optimus.net.NetDevice", timer, ntfy).ok_or("sem driver de rede")?;
    let mut nic = Nic::attach(s, ep, quota, ntfy).ok_or("ligar ao NetDevice")?;
    // Relógio da pilha: o `Timer` periódico sinaliza a mesma `Notification`
    // do anel de recepção.
    ostd::cap::arm_timer(
        timer,
        ntfy,
        TIMER_BIT,
        TICK_NS,
        TICK_NS,
        ostd::kabi::timer::RELATIVE,
    )
    .map_err(|_| "armar o Timer")?;
    let mut stack = Stack::new(nic.mac);
    stack.set_config(&mut TxLink(&mut nic.tx), STATIC);
    let mut frame = [0u8; eth::MAX_FRAME];
    let (mut gateway_seen, mut ping_ok) = (false, false);
    let (mut seq, mut next_ping) = (0u16, 0u64);
    loop {
        let now = ostd::time::now_ns();
        loop {
            match nic.rx.pop(&mut frame) {
                Ok(Some((FRAME_KIND, n))) => {
                    let ev = stack.input(&mut TxLink(&mut nic.tx), &frame[..n], now);
                    if let Some(Event::EchoReply { src, id, .. }) = ev
                        && src == STATIC.gateway
                        && id == PING_ID
                        && !ping_ok
                    {
                        ping_ok = true;
                        ostd::debug::print("netd: icmp: roteador 10.0.2.2 respondeu ao eco");
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return Err("anel de recepção corrompido"),
            }
        }
        stack.tick(now);
        let link = &mut TxLink(&mut nic.tx);
        if stack.neighbor(link, STATIC.gateway, now).is_some() {
            if TESTE && !gateway_seen {
                gateway_seen = true;
                ostd::debug::print("netd: arp: roteador 10.0.2.2 resolvido");
            }
            // Prova da camada IP: eco ao roteador até ele responder.
            if TESTE && !ping_ok && now >= next_ping {
                seq = seq.wrapping_add(1);
                let _ = stack.ping(link, STATIC.gateway, PING_ID, seq, b"optimus", now);
                next_ping = now.saturating_add(PING_NS);
            }
        }
        if nic.rx.wait().is_err() {
            return Err("espera no anel de recepção");
        }
    }
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
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let _ = s.ready();
    if let Err(e) = run(&mut s, quota) {
        ostd::debug::print_fmt(format_args!("netd: falhou: {e}"));
    }
    ostd::thread::exit()
}
