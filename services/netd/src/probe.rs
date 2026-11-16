//! Provas da imagem de teste contra o roteador e o host do QEMU (ADR 0069,
//! item 8): ARP, eco ICMP, eco UDP e, depois, TCP. A imagem normal não gera
//! tráfego que ninguém pediu (veja `TESTE` em `main.rs`); o `xtask` põe no
//! host os servidores de eco que o roteador do QEMU (10.0.2.2) alcança.

use onet::arp::Ip4;
use onet::ports::Ephemeral;
use onet::stack::{Event, Link, Stack, Upper};
use onet::tcp::{ConnId, Read, State};

/// O roteador do QEMU e, por ele, o host.
pub const GATEWAY: Ip4 = [10, 0, 2, 2];
/// Porta UDP do servidor de eco do host (`xtask`).
pub const UDP_ECHO_PORT: u16 = 47107;
/// Porta TCP do servidor de eco do host (`xtask`).
pub const TCP_ECHO_PORT: u16 = 47108;
/// Intervalo entre as tentativas de cada prova (ns).
const RETRY_NS: u64 = 500_000_000;
/// Identificador do eco ICMP.
const PING_ID: u16 = 0x6e64;
/// Carga do eco UDP.
const UDP_PAYLOAD: &[u8] = b"optimus-udp";
/// Carga do eco TCP: passa de uma volta do buffer de 1 MSS, para exercitar a
/// segmentação.
const TCP_PAYLOAD_LEN: usize = 4000;

/// Estado das provas.
#[allow(clippy::struct_excessive_bools, reason = "uma marca por prova")]
pub struct Probes {
    ping_ok: bool,
    ping_seq: u16,
    ping_next: u64,
    udp_ok: bool,
    udp_port: Option<u16>,
    udp_next: u64,
    gateway_seen: bool,
    tcp: Option<ConnId>,
    tcp_sent: usize,
    tcp_got: usize,
    tcp_ok: bool,
    tcp_next: u64,
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
            tcp: None,
            tcp_sent: 0,
            tcp_got: 0,
            tcp_ok: false,
            tcp_next: 0,
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
        if self.udp_ok && !self.tcp_ok {
            self.tcp_step(stack, now);
            stack.flush_tcp(link, now);
        }
    }

    /// Byte `i` da carga do eco TCP.
    fn tcp_byte(i: usize) -> u8 {
        u8::try_from((i * 31 + i / 7) % 251).unwrap_or(0)
    }

    /// Prova do TCP: abre a conexão ao eco do host, manda a carga, confere o
    /// que volta byte a byte e fecha.
    fn tcp_step(&mut self, stack: &mut Stack, now: u64) {
        let Some(id) = self.tcp else {
            if now >= self.tcp_next {
                let mut r = [0u8; 4];
                let _ = ostd::rand::secure_fill(&mut r);
                self.tcp = stack
                    .tcp
                    .connect(GATEWAY, TCP_ECHO_PORT, now, u32::from_le_bytes(r))
                    .ok();
                self.tcp_sent = 0;
                self.tcp_got = 0;
                self.tcp_next = now.saturating_add(RETRY_NS);
            }
            return;
        };
        match stack.tcp.state(id) {
            Some(State::Established | State::CloseWait) => {}
            Some(State::SynSent | State::SynRcvd) => return,
            // Recusada ou esgotada: solta e tenta de novo daqui a pouco.
            _ => {
                stack.tcp.abort(id);
                self.tcp = None;
                return;
            }
        }
        let mut chunk = [0u8; 512];
        while self.tcp_sent < TCP_PAYLOAD_LEN {
            let n = chunk.len().min(TCP_PAYLOAD_LEN - self.tcp_sent);
            for (k, b) in chunk[..n].iter_mut().enumerate() {
                *b = Self::tcp_byte(self.tcp_sent + k);
            }
            match stack.tcp.write(id, &chunk[..n], now) {
                Ok(0) | Err(_) => break,
                Ok(w) => self.tcp_sent += w,
            }
        }
        while let Ok(Read::Data(n)) = stack.tcp.read(id, &mut chunk) {
            for (k, b) in chunk[..n].iter().enumerate() {
                if *b != Self::tcp_byte(self.tcp_got + k) {
                    ostd::debug::print("netd: tcp: eco com dado errado");
                    stack.tcp.abort(id);
                    self.tcp = None;
                    return;
                }
            }
            self.tcp_got += n;
        }
        if self.tcp_got == TCP_PAYLOAD_LEN {
            self.tcp_ok = true;
            stack.tcp.close(id, now);
            ostd::debug::print("netd: tcp: eco do host");
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
