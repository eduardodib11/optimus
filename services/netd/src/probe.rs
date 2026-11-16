//! Provas da imagem de teste contra o roteador e o host do QEMU (ADR 0069,
//! item 8): ARP, eco ICMP, eco UDP e, depois, TCP. A imagem normal não gera
//! tráfego que ninguém pediu (veja `TESTE` em `main.rs`); o `xtask` põe no
//! host os servidores de eco que o roteador do QEMU (10.0.2.2) alcança.

use onet::arp::Ip4;
use onet::ports::Ephemeral;
use onet::stack::{Event, Link, Stack, Upper};

/// O roteador do QEMU e, por ele, o host.
pub const GATEWAY: Ip4 = [10, 0, 2, 2];
/// Porta UDP do servidor de eco do host (`xtask`).
pub const UDP_ECHO_PORT: u16 = 47107;
/// Intervalo entre as tentativas de cada prova (ns).
const RETRY_NS: u64 = 500_000_000;
/// Identificador do eco ICMP.
const PING_ID: u16 = 0x6e64;
/// Carga do eco UDP.
const UDP_PAYLOAD: &[u8] = b"optimus-udp";

/// Estado das provas.
pub struct Probes {
    ping_ok: bool,
    ping_seq: u16,
    ping_next: u64,
    udp_ok: bool,
    udp_port: Option<u16>,
    udp_next: u64,
    gateway_seen: bool,
    ports: Ephemeral,
}

impl Probes {
    /// Provas ainda não feitas.
    pub const fn new() -> Self {
        Self {
            ping_ok: false,
            ping_seq: 0,
            ping_next: 0,
            udp_ok: false,
            udp_port: None,
            udp_next: 0,
            gateway_seen: false,
            ports: Ephemeral::new(),
        }
    }

    /// Trata um evento da pilha.
    pub fn event(&mut self, ev: Option<Event>) {
        if let Some(Event::EchoReply { src, id, .. }) = ev
            && src == GATEWAY
            && id == PING_ID
            && !self.ping_ok
        {
            self.ping_ok = true;
            ostd::debug::print("netd: icmp: roteador 10.0.2.2 respondeu ao eco");
        }
    }

    /// A porta efêmera da prova UDP, sorteada na primeira vez.
    fn port(&mut self) -> Option<u16> {
        if self.udp_port.is_none() {
            let mut r = [0u8; 4];
            let _ = ostd::rand::secure_fill(&mut r);
            self.udp_port = self.ports.alloc(u32::from_le_bytes(r));
        }
        self.udp_port
    }

    /// Um passo das provas, a cada volta do laço.
    pub fn step<L: Link>(&mut self, stack: &mut Stack, link: &mut L, now: u64) {
        if stack.neighbor(link, GATEWAY, now).is_none() {
            return;
        }
        if !self.gateway_seen {
            self.gateway_seen = true;
            ostd::debug::print("netd: arp: roteador 10.0.2.2 resolvido");
        }
        if !self.ping_ok && now >= self.ping_next {
            self.ping_seq = self.ping_seq.wrapping_add(1);
            let _ = stack.ping(link, GATEWAY, PING_ID, self.ping_seq, b"optimus", now);
            self.ping_next = now.saturating_add(RETRY_NS);
        }
        if self.ping_ok && !self.udp_ok && now >= self.udp_next {
            let Some(port) = self.port() else { return };
            let _ = stack.send_udp(link, port, GATEWAY, UDP_ECHO_PORT, UDP_PAYLOAD, now);
            self.udp_next = now.saturating_add(RETRY_NS);
        }
    }
}

impl Upper for Probes {
    fn udp(&mut self, src: Ip4, sport: u16, dport: u16, data: &[u8]) -> bool {
        if Some(dport) != self.udp_port {
            return false;
        }
        if src == GATEWAY && sport == UDP_ECHO_PORT && data == UDP_PAYLOAD && !self.udp_ok {
            self.udp_ok = true;
            ostd::debug::print("netd: udp: eco do host");
        }
        true
    }
}
