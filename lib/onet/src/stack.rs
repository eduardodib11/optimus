//! O estado da pilha de uma interface e o laço de entrada de quadros. O
//! `netd` só liga isto aos anéis do `NetDevice` e ao relógio, por isso tudo
//! se testa no host com um [`Link`] de mentira.

use crate::arp::{self, Cache, Ip4, Local, Resolve};
use crate::eth::{self, Header, Mac};
use crate::frag::{self, Reassembler};
use crate::icmp::{self, Echo};
use crate::ip4::{self, Config};

/// Por onde a pilha manda quadros.
pub trait Link {
    /// Manda um quadro Ethernet inteiro; `false` se não coube (anel cheio).
    fn send(&mut self, frame: &[u8]) -> bool;
}

/// O que um quadro recebido avisa a quem usa a pilha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Chegou a resposta de um eco que a pilha mandou.
    EchoReply {
        /// Quem respondeu.
        src: Ip4,
        /// Identificador do pedido.
        id: u16,
        /// Sequência do pedido.
        seq: u16,
        /// Bytes de dados.
        len: usize,
    },
}

/// Por que um pacote não saiu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// Sem endereço ou sem rota para o destino.
    NoRoute,
    /// Maior que o MTU: não há fragmentação de saída (ADR 0069, item 4).
    TooBig,
    /// O MAC do próximo salto ainda não se sabe; a pergunta ARP já saiu e o
    /// chamador tenta de novo (o TCP e o DNS retransmitem).
    Pending,
    /// O anel de transmissão está cheio.
    Busy,
}

/// A pilha de uma interface.
#[derive(Debug)]
pub struct Stack {
    local: Local,
    arp: Cache,
    cfg: Config,
    frags: Reassembler,
    ip_id: u16,
}

impl Stack {
    /// Pilha para a interface de MAC `mac`, ainda sem endereço IP.
    #[must_use]
    pub const fn new(mac: Mac) -> Self {
        Self {
            local: Local { mac, ip: [0; 4] },
            arp: Cache::new(),
            cfg: Config {
                ip: [0; 4],
                mask: [0; 4],
                gateway: [0; 4],
            },
            frags: Reassembler::new(),
            ip_id: 0,
        }
    }

    /// O MAC da interface.
    #[must_use]
    pub const fn mac(&self) -> Mac {
        self.local.mac
    }

    /// O IP da interface (zero antes de configurado).
    #[must_use]
    pub const fn ip(&self) -> Ip4 {
        self.local.ip
    }

    /// A configuração de rede.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.cfg
    }

    /// Define endereço, máscara e roteador e anuncia o endereço (ARP
    /// gratuito). Com `ip` zero a interface fica sem endereço.
    pub fn set_config<L: Link>(&mut self, link: &mut L, cfg: Config) {
        self.cfg = cfg;
        self.local.ip = cfg.ip;
        if cfg.ip != [0; 4] {
            let g = self.local.gratuitous();
            self.send_arp(link, Mac::BROADCAST, &g);
        }
    }

    /// Relógio da pilha: descarta o que passou do prazo.
    pub fn tick(&mut self, now: u64) {
        self.frags.expire(now);
    }

    /// Manda um pacote IPv4 com `payload` de `proto` para `dst`.
    ///
    /// # Errors
    ///
    /// [`SendError`].
    pub fn send_ip<L: Link>(
        &mut self,
        link: &mut L,
        dst: Ip4,
        proto: u8,
        payload: &[u8],
        now: u64,
    ) -> Result<(), SendError> {
        if payload.len() + ip4::HEADER_LEN > eth::MTU {
            return Err(SendError::TooBig);
        }
        // O broadcast limitado sai sem endereço, para o DHCP (T-633).
        let broadcast = dst == ip4::LIMITED_BROADCAST || dst == self.cfg.broadcast();
        let mac = if dst == ip4::LIMITED_BROADCAST || (self.cfg.ip != [0; 4] && broadcast) {
            Mac::BROADCAST
        } else {
            let hop = self.cfg.next_hop(dst).ok_or(SendError::NoRoute)?;
            self.neighbor(link, hop, now).ok_or(SendError::Pending)?
        };
        self.ip_id = self.ip_id.wrapping_add(1);
        let h = ip4::Header {
            id: self.ip_id,
            dont_fragment: true,
            more_fragments: false,
            frag_offset: 0,
            ttl: ip4::DEFAULT_TTL,
            proto,
            src: self.cfg.ip,
            dst,
        };
        let mut pkt = [0u8; eth::MTU];
        let n = ip4::build(&h, payload, &mut pkt).ok_or(SendError::TooBig)?;
        let mut out = [0u8; eth::MAX_FRAME];
        let eh = Header {
            dst: mac,
            src: self.local.mac,
            ethertype: eth::ETHERTYPE_IPV4,
        };
        let len = eth::build(&eh, &pkt[..n], &mut out).ok_or(SendError::TooBig)?;
        if link.send(&out[..len]) {
            Ok(())
        } else {
            Err(SendError::Busy)
        }
    }

    /// Manda um pedido de eco (`ping`).
    ///
    /// # Errors
    ///
    /// [`SendError`].
    pub fn ping<L: Link>(
        &mut self,
        link: &mut L,
        dst: Ip4,
        id: u16,
        seq: u16,
        data: &[u8],
        now: u64,
    ) -> Result<(), SendError> {
        let mut msg = [0u8; eth::MTU];
        let echo = Echo {
            kind: icmp::ECHO_REQUEST,
            id,
            seq,
            data,
        };
        let n = icmp::build_echo(&echo, &mut msg).ok_or(SendError::TooBig)?;
        self.send_ip(link, dst, ip4::PROTO_ICMP, &msg[..n], now)
    }

    fn send_arp<L: Link>(&self, link: &mut L, dst: Mac, p: &arp::Packet) {
        let mut out = [0u8; eth::HEADER_LEN + arp::PACKET_LEN];
        let h = Header {
            dst,
            src: self.local.mac,
            ethertype: eth::ETHERTYPE_ARP,
        };
        if let Some(n) = eth::build(&h, &p.build(), &mut out) {
            let _ = link.send(&out[..n]);
        }
    }

    /// MAC do vizinho `ip` se já se sabe; senão manda a pergunta quando é a
    /// hora (as tentativas e o intervalo são do cache) e devolve `None`.
    pub fn neighbor<L: Link>(&mut self, link: &mut L, ip: Ip4, now: u64) -> Option<Mac> {
        match self.arp.resolve(ip, now) {
            Resolve::Hit(m) => Some(m),
            Resolve::Ask => {
                let p = self.local.request(ip);
                self.send_arp(link, Mac::BROADCAST, &p);
                None
            }
            Resolve::Wait | Resolve::Failed => None,
        }
    }

    /// Trata um quadro recebido. Quadro curto, de outro destino ou de
    /// protocolo que a pilha ainda não conhece é descartado.
    pub fn input<L: Link>(&mut self, link: &mut L, frame: &[u8], now: u64) -> Option<Event> {
        let (h, payload) = eth::parse(frame)?;
        if !eth::for_us(&h, self.local.mac) || h.src == self.local.mac {
            return None;
        }
        match h.ethertype {
            eth::ETHERTYPE_ARP => {
                let p = arp::Packet::parse(payload)?;
                let reply = self.arp.input(&self.local, &p, now)?;
                self.send_arp(link, p.sha, &reply);
                None
            }
            eth::ETHERTYPE_IPV4 => self.input_ip4(link, payload, now),
            _ => None,
        }
    }

    fn input_ip4<L: Link>(&mut self, link: &mut L, pkt: &[u8], now: u64) -> Option<Event> {
        let (h, payload) = ip4::parse(pkt)?;
        if !self.cfg.is_local(h.dst) || h.ttl == 0 {
            return None;
        }
        // Origem de grupo ou de difusão não existe; a zero só vale para quem
        // ainda não tem endereço (DHCP).
        if h.src[0] >= 224 || h.src == ip4::LIMITED_BROADCAST || h.src == self.cfg.broadcast() {
            return None;
        }
        if h.is_fragment() {
            let mut buf = [0u8; frag::MAX_DATAGRAM];
            let (h, n) = self.frags.add(&h, payload, now, &mut buf)?;
            return self.input_proto(link, &h, &buf[..n], now);
        }
        self.input_proto(link, &h, payload, now)
    }

    fn input_proto<L: Link>(
        &mut self,
        link: &mut L,
        h: &ip4::Header,
        payload: &[u8],
        now: u64,
    ) -> Option<Event> {
        match h.proto {
            ip4::PROTO_ICMP => self.input_icmp(link, h, payload, now),
            _ => None,
        }
    }

    fn input_icmp<L: Link>(
        &mut self,
        link: &mut L,
        h: &ip4::Header,
        payload: &[u8],
        now: u64,
    ) -> Option<Event> {
        let e = icmp::parse_echo(payload)?;
        match e.kind {
            // Só responde a eco dirigido a nós (nada de difusão: evita ser
            // amplificador, RFC 1122 3.2.2.6 permite recusar).
            icmp::ECHO_REQUEST if h.dst == self.cfg.ip && h.src != [0; 4] => {
                let mut msg = [0u8; eth::MTU];
                let r = Echo {
                    kind: icmp::ECHO_REPLY,
                    ..e
                };
                let n = icmp::build_echo(&r, &mut msg)?;
                let _ = self.send_ip(link, h.src, ip4::PROTO_ICMP, &msg[..n], now);
                None
            }
            icmp::ECHO_REPLY => Some(Event::EchoReply {
                src: h.src,
                id: e.id,
                seq: e.seq,
                len: e.data.len(),
            }),
            _ => None,
        }
    }
}
