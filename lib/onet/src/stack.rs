//! O estado da pilha de uma interface e o laço de entrada de quadros. O
//! `netd` só liga isto aos anéis do `NetDevice` e ao relógio, por isso tudo
//! se testa no host com um [`Link`] de mentira.

use crate::arp::{self, Cache, Ip4, Local, Resolve};
use crate::dhcp::{self, Lease, Outcome};
use crate::eth::{self, Header, Mac};
use crate::frag::{self, Reassembler};
use crate::icmp::{self, Echo};
use crate::icmp6::{self, Msg};
use crate::ip4::{self, Config};
use crate::ip6::{self, Ip6};
use crate::nd;
use crate::slaac::{Slaac, Tx};
use crate::tcp::Tcp;
use crate::udp;

/// Quem recebe o que a pilha entrega acima do IP.
pub trait Upper {
    /// Entrega um datagrama UDP para a porta `dport`. `false` se ninguém a
    /// escuta: a pilha responde com "porta inalcançável".
    fn udp(&mut self, src: Ip4, sport: u16, dport: u16, data: &[u8]) -> bool;
}

/// Sem ninguém acima: toda porta é inalcançável.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoUpper;

impl Upper for NoUpper {
    fn udp(&mut self, _: Ip4, _: u16, _: u16, _: &[u8]) -> bool {
        false
    }
}

/// Intervalo mínimo entre mensagens de erro ICMP (ns), RFC 1812 4.3.2.8.
const ICMP_ERROR_NS: u64 = 100_000_000;

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
    /// O DHCP concedeu (ou renovou) a configuração, já aplicada à pilha.
    Lease(Lease),
    /// Chegou a resposta de um eco IPv6 que a pilha mandou.
    EchoReply6 {
        /// Quem respondeu.
        src: Ip6,
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
    /// Quando o próximo erro ICMP pode sair.
    icmp_error_at: u64,
    /// O TCP: o `netd` abre, escuta, lê e escreve por aqui.
    pub tcp: Tcp,
    dhcp: dhcp::Client,
    dhcp_on: bool,
    /// Gerador (xorshift64*) dos `xid` do DHCP; o `netd` o semeia do DRBG.
    rng: u64,
    v6: Slaac,
    nd: nd::Cache,
    v6_on: bool,
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
            icmp_error_at: 0,
            tcp: Tcp::new([0; 16]),
            dhcp: dhcp::Client::new(mac),
            dhcp_on: false,
            rng: 0x9e37_79b9_7f4a_7c15,
            v6: Slaac::new(mac),
            nd: nd::Cache::new(),
            v6_on: false,
        }
    }

    /// Semeia o que precisa ser imprevisível: o segredo do ISN do TCP e os
    /// `xid` do DHCP. Vem do DRBG do kernel (ADR 0069, item 7).
    pub fn seed(&mut self, bytes: [u8; 16]) {
        self.tcp.set_secret(bytes);
        let mut w = [0u8; 8];
        w.copy_from_slice(&bytes[..8]);
        self.rng ^= u64::from_le_bytes(w) | 1;
        let h = optcrypt::blake3::hash(&bytes);
        let mut k = [0u8; 16];
        k.copy_from_slice(&h[..16]);
        self.v6.seed(k);
    }

    fn next_random(&mut self) -> u32 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        u32::try_from(x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32).unwrap_or(0)
    }

    /// Liga o cliente DHCP: a configuração passa a vir da concessão.
    pub fn start_dhcp(&mut self) {
        self.dhcp_on = true;
    }

    /// Liga o IPv6: endereço local do enlace, DAD, solicitação de roteador e
    /// SLAAC com endereços temporários (RFC 4862, 7217 e 8981).
    pub fn start_ipv6(&mut self) {
        self.v6_on = true;
    }

    /// A configuração automática do IPv6.
    #[must_use]
    pub const fn slaac(&self) -> &Slaac {
        &self.v6
    }

    /// O cliente DHCP (estado e concessão).
    #[must_use]
    pub const fn dhcp(&self) -> &dhcp::Client {
        &self.dhcp
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
        self.tcp.set_ip(cfg.ip);
        if cfg.ip != [0; 4] {
            let g = self.local.gratuitous();
            self.send_arp(link, Mac::BROADCAST, &g);
        }
    }

    /// Relógio da pilha: descarta o que passou do prazo, roda as
    /// retransmissões do TCP e manda o que ele tem na fila.
    pub fn tick<L: Link>(&mut self, link: &mut L, now: u64) {
        self.frags.expire(now);
        self.dhcp_step(link, now);
        self.v6_step(link, now);
        self.tcp.poll(now);
        self.flush_tcp(link, now);
    }

    /// Passo do cliente DHCP: concessão vencida tira o endereço; mensagem
    /// pronta sai pela difusão ou pelo servidor.
    fn dhcp_step<L: Link>(&mut self, link: &mut L, now: u64) {
        if !self.dhcp_on {
            return;
        }
        if self.dhcp.take_expired() {
            self.set_config(link, Config::default());
        }
        let r = self.next_random();
        if let Some(p) = self.dhcp.poll(now, r) {
            let _ = self.send_udp(
                link,
                dhcp::CLIENT_PORT,
                p.dst,
                dhcp::SERVER_PORT,
                p.bytes(),
                now,
            );
        }
    }

    /// Passo do IPv6: DAD e solicitação de roteador que o SLAAC pede.
    fn v6_step<L: Link>(&mut self, link: &mut L, now: u64) {
        if !self.v6_on {
            return;
        }
        self.v6.start();
        for _ in 0..=crate::slaac::MAX_ADDRS {
            let r = self.next_random();
            match self.v6.poll(now, r) {
                Some(Tx::Dad(t)) => {
                    let _ =
                        self.send_ns(link, &ip6::UNSPECIFIED, &ip6::solicited_node(&t), &t, false);
                }
                Some(Tx::RouterSolicit(src)) => {
                    let mut m = [0u8; 16];
                    if let Some(n) =
                        icmp6::build_rs(&src, &ip6::ALL_ROUTERS, Some(self.local.mac), &mut m)
                    {
                        let _ = self.emit6(
                            link,
                            ip6::multicast_mac(&ip6::ALL_ROUTERS),
                            &src,
                            &ip6::ALL_ROUTERS,
                            255,
                            &m[..n],
                        );
                    }
                }
                None => break,
            }
        }
    }

    /// Monta e manda um pacote ICMPv6 já pronto (`payload`) no quadro para `mac`.
    fn emit6<L: Link>(
        &self,
        link: &mut L,
        mac: Mac,
        src: &Ip6,
        dst: &Ip6,
        hop_limit: u8,
        payload: &[u8],
    ) -> Result<(), SendError> {
        self.emit6_proto(link, mac, src, dst, ip6::PROTO_ICMP6, hop_limit, payload)
    }

    #[allow(clippy::too_many_arguments, reason = "um quadro IPv6 tem esses campos")]
    fn emit6_proto<L: Link>(
        &self,
        link: &mut L,
        mac: Mac,
        src: &Ip6,
        dst: &Ip6,
        next: u8,
        hop_limit: u8,
        payload: &[u8],
    ) -> Result<(), SendError> {
        let h = ip6::Header {
            traffic_class: 0,
            flow_label: 0,
            next,
            hop_limit,
            src: *src,
            dst: *dst,
            frag: None,
        };
        let mut pkt = [0u8; eth::MTU];
        let n = ip6::build(&h, payload, &mut pkt).ok_or(SendError::TooBig)?;
        let mut out = [0u8; eth::MAX_FRAME];
        let eh = Header {
            dst: mac,
            src: self.local.mac,
            ethertype: eth::ETHERTYPE_IPV6,
        };
        let len = eth::build(&eh, &pkt[..n], &mut out).ok_or(SendError::TooBig)?;
        if link.send(&out[..len]) {
            Ok(())
        } else {
            Err(SendError::Busy)
        }
    }

    /// Solicitação de vizinho para `target`, no enlace do nó solicitado.
    fn send_ns<L: Link>(
        &self,
        link: &mut L,
        src: &Ip6,
        dst: &Ip6,
        target: &Ip6,
        slla: bool,
    ) -> Result<(), SendError> {
        let mut m = [0u8; 32];
        let n = icmp6::build_ns(src, dst, target, slla.then_some(self.local.mac), &mut m)
            .ok_or(SendError::TooBig)?;
        self.emit6(link, ip6::multicast_mac(dst), src, dst, 255, &m[..n])
    }

    /// Manda um pacote IPv6 com `payload` de `next` para `dst`, com a origem
    /// que o SLAAC escolhe.
    ///
    /// # Errors
    ///
    /// [`SendError`].
    pub fn send_ip6<L: Link>(
        &mut self,
        link: &mut L,
        dst: Ip6,
        next: u8,
        payload: &[u8],
        now: u64,
    ) -> Result<(), SendError> {
        let src = self.v6.source_for(&dst, now).ok_or(SendError::NoRoute)?;
        self.send_ip6_from(link, src, dst, next, payload, now)
    }

    fn send_ip6_from<L: Link>(
        &mut self,
        link: &mut L,
        src: Ip6,
        dst: Ip6,
        next: u8,
        payload: &[u8],
        now: u64,
    ) -> Result<(), SendError> {
        if payload.len() + ip6::HEADER_LEN > eth::MTU {
            return Err(SendError::TooBig);
        }
        let hop = self.v6.next_hop(&dst, now).ok_or(SendError::NoRoute)?;
        let mac = self
            .neighbor6(link, &hop, &src, now)
            .ok_or(SendError::Pending)?;
        self.emit6_proto(link, mac, &src, &dst, next, ip6::HOP_LIMIT, payload)
    }

    /// MAC do vizinho IPv6 `ip` se se sabe; senão manda a solicitação (a
    /// cada tentativa que o cache permite) e devolve `None`.
    pub fn neighbor6<L: Link>(
        &mut self,
        link: &mut L,
        ip: &Ip6,
        src: &Ip6,
        now: u64,
    ) -> Option<Mac> {
        if ip6::is_multicast(ip) {
            return Some(ip6::multicast_mac(ip));
        }
        match self.nd.resolve(*ip, now) {
            Resolve::Hit(m) => Some(m),
            Resolve::Ask => {
                let _ = self.send_ns(link, src, &ip6::solicited_node(ip), ip, true);
                None
            }
            Resolve::Wait | Resolve::Failed => None,
        }
    }

    /// Manda um pedido de eco ICMPv6.
    ///
    /// # Errors
    ///
    /// [`SendError`].
    pub fn ping6<L: Link>(
        &mut self,
        link: &mut L,
        dst: Ip6,
        id: u16,
        seq: u16,
        data: &[u8],
        now: u64,
    ) -> Result<(), SendError> {
        let src = self.v6.source_for(&dst, now).ok_or(SendError::NoRoute)?;
        let mut msg = [0u8; eth::MTU];
        let n = icmp6::build_echo(&src, &dst, icmp6::ECHO_REQUEST, id, seq, data, &mut msg)
            .ok_or(SendError::TooBig)?;
        self.send_ip6_from(link, src, dst, ip6::PROTO_ICMP6, &msg[..n], now)
    }

    /// Leva ao IP os segmentos que o TCP enfileirou. O que não saiu por falta
    /// de MAC ou de vaga no anel volta para a frente da fila (o relógio do
    /// TCP retransmite o que se perder); o que não tem rota é descartado.
    pub fn flush_tcp<L: Link>(&mut self, link: &mut L, now: u64) {
        while let Some(o) = self.tcp.pop_out() {
            match self.send_ip(link, o.dst, ip4::PROTO_TCP, &o.data, now) {
                Err(SendError::Pending | SendError::Busy) => {
                    self.tcp.push_front_out(o);
                    break;
                }
                Ok(()) | Err(SendError::NoRoute | SendError::TooBig) => {}
            }
        }
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

    /// Manda um datagrama UDP de `sport` para `dst:dport`.
    ///
    /// # Errors
    ///
    /// [`SendError`].
    pub fn send_udp<L: Link>(
        &mut self,
        link: &mut L,
        sport: u16,
        dst: Ip4,
        dport: u16,
        data: &[u8],
        now: u64,
    ) -> Result<(), SendError> {
        let mut seg = [0u8; eth::MTU];
        let n =
            udp::build(self.cfg.ip, dst, sport, dport, data, &mut seg).ok_or(SendError::TooBig)?;
        self.send_ip(link, dst, ip4::PROTO_UDP, &seg[..n], now)
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
    pub fn input<L: Link, U: Upper>(
        &mut self,
        link: &mut L,
        up: &mut U,
        frame: &[u8],
        now: u64,
    ) -> Option<Event> {
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
            eth::ETHERTYPE_IPV4 => self.input_ip4(link, up, payload, now),
            eth::ETHERTYPE_IPV6 => self.input_ip6(link, h.src, payload, now),
            _ => None,
        }
    }

    fn input_ip4<L: Link, U: Upper>(
        &mut self,
        link: &mut L,
        up: &mut U,
        pkt: &[u8],
        now: u64,
    ) -> Option<Event> {
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
            return self.input_proto(link, up, &h, &buf[..n], None, now);
        }
        self.input_proto(link, up, &h, payload, Some(pkt), now)
    }

    fn input_proto<L: Link, U: Upper>(
        &mut self,
        link: &mut L,
        up: &mut U,
        h: &ip4::Header,
        payload: &[u8],
        orig: Option<&[u8]>,
        now: u64,
    ) -> Option<Event> {
        match h.proto {
            ip4::PROTO_ICMP => self.input_icmp(link, h, payload, now),
            ip4::PROTO_UDP => {
                let d = udp::parse(h.src, h.dst, payload)?;
                if self.dhcp_on && d.dport == dhcp::CLIENT_PORT && d.sport == dhcp::SERVER_PORT {
                    return self.input_dhcp(link, d.data, now);
                }
                let unicast = h.dst == self.cfg.ip;
                if !up.udp(h.src, d.sport, d.dport, d.data) && unicast {
                    self.port_unreachable(link, h.src, orig, now);
                }
                None
            }
            ip4::PROTO_TCP => {
                // Só unicast para nós: TCP não existe em difusão.
                if h.dst == self.cfg.ip {
                    self.tcp.input(h.src, h.dst, payload, now);
                    self.flush_tcp(link, now);
                }
                None
            }
            _ => None,
        }
    }

    fn input_dhcp<L: Link>(&mut self, link: &mut L, msg: &[u8], now: u64) -> Option<Event> {
        match self.dhcp.input(msg, now) {
            Outcome::Bound(lease) => {
                if lease.config != self.cfg {
                    self.set_config(link, lease.config);
                }
                Some(Event::Lease(lease))
            }
            Outcome::Offered => {
                self.dhcp_step(link, now);
                None
            }
            Outcome::Nak => {
                self.set_config(link, Config::default());
                None
            }
            Outcome::None => None,
        }
    }

    /// "Porta inalcançável" para `to`, citando o pacote original, no máximo
    /// um a cada [`ICMP_ERROR_NS`].
    fn port_unreachable<L: Link>(&mut self, link: &mut L, to: Ip4, orig: Option<&[u8]>, now: u64) {
        let Some(orig) = orig else { return };
        if now < self.icmp_error_at {
            return;
        }
        let mut msg = [0u8; icmp::ECHO_HEADER + ip4::HEADER_LEN + 60 + 8];
        if let Some(n) = icmp::build_unreachable(icmp::PORT_UNREACHABLE, orig, &mut msg) {
            self.icmp_error_at = now.saturating_add(ICMP_ERROR_NS);
            let _ = self.send_ip(link, to, ip4::PROTO_ICMP, &msg[..n], now);
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

    fn input_ip6<L: Link>(
        &mut self,
        link: &mut L,
        from: Mac,
        pkt: &[u8],
        now: u64,
    ) -> Option<Event> {
        if !self.v6_on {
            return None;
        }
        let (h, payload) = ip6::parse(pkt)?;
        if ip6::is_multicast(&h.src)
            || !(self.v6.owns_ready(&h.dst, now) || self.v6.listens(&h.dst))
        {
            return None;
        }
        let Some(f) = h.frag else {
            return self.input_proto6(link, from, &h, payload, now);
        };
        let key = frag::Key {
            src: h.src,
            dst: h.dst,
            id: f.id,
            proto: h.next,
            v6: true,
        };
        let piece = frag::Piece {
            offset: usize::from(f.offset),
            more: f.more,
        };
        let mut buf = [0u8; frag::MAX_DATAGRAM];
        let n = self.frags.add_piece(&key, piece, payload, now, &mut buf)?;
        let whole = ip6::Header { frag: None, ..h };
        self.input_proto6(link, from, &whole, &buf[..n], now)
    }

    fn input_proto6<L: Link>(
        &mut self,
        link: &mut L,
        from: Mac,
        h: &ip6::Header,
        payload: &[u8],
        now: u64,
    ) -> Option<Event> {
        // TCP e UDP sobre IPv6 chegam com os soquetes (T-637); hoje só ICMPv6.
        if h.next != ip6::PROTO_ICMP6 {
            return None;
        }
        match icmp6::parse(h, payload)? {
            Msg::Echo {
                kind: icmp6::ECHO_REQUEST,
                id,
                seq,
                data,
            } => {
                if self.v6.owns_ready(&h.dst, now) && h.src != ip6::UNSPECIFIED {
                    let mut msg = [0u8; eth::MTU];
                    let n = icmp6::build_echo(
                        &h.dst,
                        &h.src,
                        icmp6::ECHO_REPLY,
                        id,
                        seq,
                        data,
                        &mut msg,
                    )?;
                    let _ =
                        self.send_ip6_from(link, h.dst, h.src, ip6::PROTO_ICMP6, &msg[..n], now);
                }
                None
            }
            Msg::Echo {
                kind: icmp6::ECHO_REPLY,
                id,
                seq,
                data,
            } => Some(Event::EchoReply6 {
                src: h.src,
                id,
                seq,
                len: data.len(),
            }),
            Msg::Echo { .. } | Msg::RouterSolicit => None,
            Msg::NeighborSolicit { target, slla } => {
                self.input_ns(link, from, h, &target, slla, now);
                None
            }
            Msg::NeighborAdvert { target, tlla, .. } => {
                if self.v6.owns(&target) {
                    self.v6.conflict(&target);
                } else {
                    self.nd.learn(target, tlla.unwrap_or(from), now, true);
                }
                None
            }
            Msg::RouterAdvert {
                lifetime,
                prefixes,
                slla,
            } => {
                let r = (u64::from(self.next_random()) << 32) | u64::from(self.next_random());
                if self.v6.input_ra(&h.src, lifetime, &prefixes, now, r) {
                    self.nd.learn(h.src, slla.unwrap_or(from), now, false);
                }
                None
            }
        }
    }

    /// Solicitação de vizinho: DAD alheia (origem `::`) ou pergunta pelo
    /// nosso endereço, que se responde com um anúncio.
    fn input_ns<L: Link>(
        &mut self,
        link: &mut L,
        from: Mac,
        h: &ip6::Header,
        target: &Ip6,
        slla: Option<Mac>,
        now: u64,
    ) {
        let mut m = [0u8; 32];
        if h.src == ip6::UNSPECIFIED {
            if self.v6.owns_ready(target, now) {
                // Defende o endereço: anúncio para todos os nós.
                if let Some(n) = icmp6::build_na(
                    target,
                    &ip6::ALL_NODES,
                    icmp6::NA_OVERRIDE,
                    target,
                    self.local.mac,
                    &mut m,
                ) {
                    let _ = self.emit6(
                        link,
                        ip6::multicast_mac(&ip6::ALL_NODES),
                        target,
                        &ip6::ALL_NODES,
                        255,
                        &m[..n],
                    );
                }
            } else {
                self.v6.conflict(target);
            }
        } else if self.v6.owns_ready(target, now) {
            if let Some(mac) = slla {
                self.nd.learn(h.src, mac, now, false);
            }
            let flags = icmp6::NA_SOLICITED | icmp6::NA_OVERRIDE;
            if let Some(n) = icmp6::build_na(target, &h.src, flags, target, self.local.mac, &mut m)
            {
                let _ = self.emit6(link, slla.unwrap_or(from), target, &h.src, 255, &m[..n]);
            }
        }
    }
}
