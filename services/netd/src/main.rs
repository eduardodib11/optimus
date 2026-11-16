//! `netd` (T-630; ADR 0017, 0064, 0068 e 0069): a pilha IP em espaço de
//! usuário. É o único cliente do `NetDevice` do driver de rede: pega a
//! sessão, liga o anel de recepção que ele consome e escreve no anel de
//! transmissão que o driver consome (os dois pelo contrato, como a ADR 0064
//! manda). Nesta tarefa o laço só prova o caminho dos quadros: manda um ARP
//! ao roteador do QEMU e espera a resposta pelo anel de recepção. Os
//! protocolos (ARP, IPv4, ICMP, DHCP, UDP, TCP) entram nas tarefas
//! seguintes (T-631 em diante) sobre este laço.
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
use onet::eth::{self, Header, Mac};

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
/// Bit do anel de recepção na `Notification` do `netd`.
const RX_BIT: u64 = 1;

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

/// Dorme `TRY_NS` entre as tentativas. Não pode ceder a vez em laço: o
/// `netd` tem prioridade 150, acima da do driver (120), que ficaria sem CPU.
fn pause() {
    ostd::time::sleep(ostd::time::Duration::from_nanos(TRY_NS));
}

/// Espera o driver partir: `connect` devolve `NotRunning` até ele chamar `ready`.
fn connect(s: &mut Session, name: &[u8]) -> Option<Handle> {
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
        pause();
    }
    None
}

/// A interface de rede: MAC e os dois anéis do `NetDevice`.
struct Nic {
    mac: Mac,
    tx: Producer,
    rx: Consumer,
}

impl Nic {
    /// Liga ao driver pelo contrato (ADR 0064): `info`, a sessão, o anel de
    /// transmissão do driver e o anel de recepção que o `netd` cria.
    fn attach(s: &mut Session, ep: Handle, quota: Handle) -> Option<Self> {
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
        let rx_ntfy = ostd::cap::create(quota, ObjectType::Notification, 0).ok()?;
        let rx = Consumer::create(rx_obj, RX_VA, RING_BYTES, 0x0E02, rx_ntfy).ok()?;
        let rx_sig = ostd::cap::mint(rx_ntfy, Rights::SIGNAL, 0, None).ok()?;
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

    /// Manda um quadro; `false` se o anel está cheio.
    fn send(&mut self, frame: &[u8]) -> bool {
        self.tx.push(FRAME_KIND, frame).is_ok()
    }
}

/// ARP "quem tem 10.0.2.2", de 10.0.2.15, em difusão.
fn probe(mac: Mac, out: &mut [u8]) -> Option<usize> {
    let mut arp = [0u8; 28];
    arp[0..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    arp[8..14].copy_from_slice(&mac.0);
    arp[14..18].copy_from_slice(&[10, 0, 2, 15]);
    arp[24..28].copy_from_slice(&[10, 0, 2, 2]);
    let h = Header {
        dst: Mac::BROADCAST,
        src: mac,
        ethertype: eth::ETHERTYPE_ARP,
    };
    eth::build(&h, &arp, out)
}

/// É a resposta do roteador ao `probe`?
fn is_probe_reply(frame: &[u8], ours: Mac) -> bool {
    let Some((h, p)) = eth::parse(frame) else {
        return false;
    };
    h.ethertype == eth::ETHERTYPE_ARP
        && h.dst == ours
        && p.len() >= 28
        && p[6..8] == [0, 2]
        && p[14..18] == [10, 0, 2, 2]
        && p[18..24] == ours.0
}

/// Laço de recepção: o `netd` dorme no anel e trata cada quadro que chega.
fn run(s: &mut Session, quota: Handle) -> Result<(), &'static str> {
    let ep = connect(s, b"optimus.net.NetDevice").ok_or("sem driver de rede")?;
    let mut nic = Nic::attach(s, ep, quota).ok_or("ligar ao NetDevice")?;
    let mut frame = [0u8; eth::MAX_FRAME];
    let n = probe(nic.mac, &mut frame).ok_or("montar o ARP")?;
    if !nic.send(&frame[..n]) {
        return Err("anel de transmissão cheio");
    }
    let mut proved = false;
    loop {
        match nic.rx.pop(&mut frame) {
            Ok(Some((FRAME_KIND, n))) => {
                if !proved && is_probe_reply(&frame[..n], nic.mac) {
                    proved = true;
                    ostd::debug::print("netd: quadro enviado e recebido");
                }
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                if nic.rx.wait().is_err() {
                    return Err("espera no anel de recepção");
                }
            }
            Err(_) => return Err("anel de recepção corrompido"),
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
