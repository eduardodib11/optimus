//! O estado da pilha de uma interface e o laço de entrada de quadros. O
//! `netd` só liga isto aos anéis do `NetDevice` e ao relógio, por isso tudo
//! se testa no host com um [`Link`] de mentira.

use crate::arp::{self, Cache, Ip4, Local, Resolve};
use crate::eth::{self, Header, Mac};

/// Por onde a pilha manda quadros.
pub trait Link {
    /// Manda um quadro Ethernet inteiro; `false` se não coube (anel cheio).
    fn send(&mut self, frame: &[u8]) -> bool;
}

/// A pilha de uma interface.
#[derive(Debug)]
pub struct Stack {
    local: Local,
    arp: Cache,
}

impl Stack {
    /// Pilha para a interface de MAC `mac`, ainda sem endereço IP.
    #[must_use]
    pub const fn new(mac: Mac) -> Self {
        Self {
            local: Local { mac, ip: [0; 4] },
            arp: Cache::new(),
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

    /// Define o IP da interface e anuncia-o (ARP gratuito).
    pub fn set_ip<L: Link>(&mut self, link: &mut L, ip: Ip4) {
        self.local.ip = ip;
        if ip != [0; 4] {
            let g = self.local.gratuitous();
            self.send_arp(link, Mac::BROADCAST, &g);
        }
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
    pub fn input<L: Link>(&mut self, link: &mut L, frame: &[u8], now: u64) {
        let Some((h, payload)) = eth::parse(frame) else {
            return;
        };
        if !eth::for_us(&h, self.local.mac) || h.src == self.local.mac {
            return;
        }
        if h.ethertype == eth::ETHERTYPE_ARP
            && let Some(p) = arp::Packet::parse(payload)
            && let Some(reply) = self.arp.input(&self.local, &p, now)
        {
            self.send_arp(link, p.sha, &reply);
        }
    }
}
