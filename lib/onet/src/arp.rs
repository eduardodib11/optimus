//! ARP sobre Ethernet e IPv4 (RFC 826): pacote, cache com expiração e a
//! decisão de responder, aprender e perguntar. Sem relógio próprio: o
//! chamador passa `now` em nanossegundos.

use crate::eth::Mac;

/// Endereço IPv4.
pub type Ip4 = [u8; 4];

/// Tamanho do pacote ARP de Ethernet e IPv4.
pub const PACKET_LEN: usize = 28;
/// Entradas do cache.
pub const CAP: usize = 16;
/// Quanto uma resolução vale (ns).
pub const TTL_NS: u64 = 60_000_000_000;
/// Intervalo entre perguntas da mesma resolução (ns).
pub const RETRY_NS: u64 = 1_000_000_000;
/// Perguntas por resolução antes de desistir.
pub const MAX_TRIES: u8 = 3;
/// Quanto uma resolução que falhou fica lembrada (ns), para não perguntar em laço.
pub const NEGATIVE_NS: u64 = 3_000_000_000;

/// Operação do pacote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Pedido (1).
    Request,
    /// Resposta (2).
    Reply,
}

/// Um pacote ARP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Operação.
    pub op: Op,
    /// MAC de quem manda.
    pub sha: Mac,
    /// IP de quem manda.
    pub spa: Ip4,
    /// MAC do alvo (zero no pedido).
    pub tha: Mac,
    /// IP do alvo.
    pub tpa: Ip4,
}

impl Packet {
    /// Lê um pacote; `None` se não for Ethernet/IPv4 ou se for curto.
    /// Bytes além dos 28 (o preenchimento do quadro) são ignorados.
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Packet> {
        if b.len() < PACKET_LEN || b[0..6] != [0, 1, 8, 0, 6, 4] {
            return None;
        }
        let op = match u16::from_be_bytes([b[6], b[7]]) {
            1 => Op::Request,
            2 => Op::Reply,
            _ => return None,
        };
        let mac = |at: usize| Mac([b[at], b[at + 1], b[at + 2], b[at + 3], b[at + 4], b[at + 5]]);
        Some(Packet {
            op,
            sha: mac(8),
            spa: [b[14], b[15], b[16], b[17]],
            tha: mac(18),
            tpa: [b[24], b[25], b[26], b[27]],
        })
    }

    /// Serializa o pacote.
    #[must_use]
    pub fn build(&self) -> [u8; PACKET_LEN] {
        let mut b = [0u8; PACKET_LEN];
        b[0..6].copy_from_slice(&[0, 1, 8, 0, 6, 4]);
        let op: u16 = if self.op == Op::Request { 1 } else { 2 };
        b[6..8].copy_from_slice(&op.to_be_bytes());
        b[8..14].copy_from_slice(&self.sha.0);
        b[14..18].copy_from_slice(&self.spa);
        b[18..24].copy_from_slice(&self.tha.0);
        b[24..28].copy_from_slice(&self.tpa);
        b
    }
}

/// A interface local.
#[derive(Clone, Copy, Debug)]
pub struct Local {
    /// MAC.
    pub mac: Mac,
    /// IP (zero antes do DHCP: então a interface não responde a ninguém).
    pub ip: Ip4,
}

impl Local {
    /// Pedido "quem tem `target`".
    #[must_use]
    pub fn request(&self, target: Ip4) -> Packet {
        Packet {
            op: Op::Request,
            sha: self.mac,
            spa: self.ip,
            tha: Mac([0; 6]),
            tpa: target,
        }
    }

    /// Anúncio gratuito: pedido do próprio IP, em difusão, para os vizinhos
    /// atualizarem o cache (RFC 5227, anúncio).
    #[must_use]
    pub fn gratuitous(&self) -> Packet {
        Packet {
            op: Op::Request,
            sha: self.mac,
            spa: self.ip,
            tha: Mac([0; 6]),
            tpa: self.ip,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum State {
    Free,
    Pending { tries: u8, next_at: u64 },
    Resolved { mac: Mac, until: u64 },
    Failed { until: u64 },
}

#[derive(Clone, Copy, Debug)]
struct Entry<const N: usize> {
    ip: [u8; N],
    state: State,
    /// Última vez que a entrada foi tocada, para escolher a vítima.
    touched: u64,
}

/// O que fazer para falar com um IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolve {
    /// Já se sabe o MAC.
    Hit(Mac),
    /// Mande um pedido agora e espere.
    Ask,
    /// Já há pedido em andamento; espere.
    Wait,
    /// Ninguém respondeu: desista por enquanto.
    Failed,
}

/// Cache de vizinhos de endereços de `N` bytes: 4 para o ARP, 16 para o ND
/// do IPv6 (`nd`).
#[derive(Debug)]
pub struct Table<const N: usize> {
    entries: [Entry<N>; CAP],
}

/// Cache do ARP.
pub type Cache = Table<4>;

impl<const N: usize> Default for Table<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Table<N> {
    /// Cache vazio.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [Entry {
                ip: [0; N],
                state: State::Free,
                touched: 0,
            }; CAP],
        }
    }

    fn find(&self, ip: [u8; N]) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| !matches!(e.state, State::Free) && e.ip == ip)
    }

    /// A entrada para `ip`, criando-a se faltar: usa uma livre ou expirada e,
    /// sem nenhuma, a menos recente.
    fn slot(&mut self, ip: [u8; N], now: u64) -> usize {
        if let Some(i) = self.find(ip) {
            return i;
        }
        let expired = |e: &Entry<N>| match e.state {
            State::Free => true,
            State::Resolved { until, .. } | State::Failed { until } => now >= until,
            State::Pending { .. } => false,
        };
        let i = self.entries.iter().position(expired).unwrap_or_else(|| {
            self.entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.touched)
                .map_or(0, |(i, _)| i)
        });
        self.entries[i] = Entry {
            ip,
            state: State::Free,
            touched: now,
        };
        i
    }

    /// MAC de `ip` se a resolução ainda vale.
    #[must_use]
    pub fn lookup(&self, ip: [u8; N], now: u64) -> Option<Mac> {
        match self.find(ip).map(|i| self.entries[i].state) {
            Some(State::Resolved { mac, until }) if now < until => Some(mac),
            _ => None,
        }
    }

    /// Resolve `ip`: dá o MAC, manda perguntar (no máximo [`MAX_TRIES`] vezes,
    /// uma por [`RETRY_NS`]), manda esperar ou desiste.
    pub fn resolve(&mut self, ip: [u8; N], now: u64) -> Resolve {
        if let Some(mac) = self.lookup(ip, now) {
            if let Some(i) = self.find(ip) {
                self.entries[i].touched = now;
            }
            return Resolve::Hit(mac);
        }
        let i = self.slot(ip, now);
        self.entries[i].touched = now;
        match self.entries[i].state {
            State::Failed { until } if now < until => Resolve::Failed,
            State::Pending { tries, next_at } if now < next_at || tries >= MAX_TRIES => {
                if tries >= MAX_TRIES && now >= next_at {
                    self.entries[i].state = State::Failed {
                        until: now.saturating_add(NEGATIVE_NS),
                    };
                    Resolve::Failed
                } else {
                    Resolve::Wait
                }
            }
            State::Pending { tries, .. } => {
                self.entries[i].state = State::Pending {
                    tries: tries + 1,
                    next_at: now.saturating_add(RETRY_NS),
                };
                Resolve::Ask
            }
            _ => {
                self.entries[i].state = State::Pending {
                    tries: 1,
                    next_at: now.saturating_add(RETRY_NS),
                };
                Resolve::Ask
            }
        }
    }

    /// Guarda `ip -> mac`. `only_known` limita o aprendizado a quem já está
    /// no cache (pendente ou resolvido): uma resposta que ninguém pediu não
    /// cria entrada, para não deixar um vizinho encher o cache.
    pub fn learn(&mut self, ip: [u8; N], mac: Mac, now: u64, only_known: bool) {
        if ip == [0; N] || mac.is_group() {
            return;
        }
        if only_known && self.find(ip).is_none() {
            return;
        }
        let i = self.slot(ip, now);
        self.entries[i].touched = now;
        self.entries[i].state = State::Resolved {
            mac,
            until: now.saturating_add(TTL_NS),
        };
    }
}

impl Table<4> {
    /// Trata um pacote recebido. Devolve a resposta quando é um pedido para o
    /// IP da interface. Aprende o remetente de um pedido para nós (vamos
    /// precisar falar com ele) e de uma resposta que esperávamos ou que
    /// atualiza uma entrada existente.
    pub fn input(&mut self, local: &Local, p: &Packet, now: u64) -> Option<Packet> {
        if local.ip == [0; 4] || p.sha == local.mac {
            return None;
        }
        match p.op {
            Op::Request if p.tpa == local.ip => {
                self.learn(p.spa, p.sha, now, false);
                Some(Packet {
                    op: Op::Reply,
                    sha: local.mac,
                    spa: local.ip,
                    tha: p.sha,
                    tpa: p.spa,
                })
            }
            Op::Request => {
                // Pedido para outro (ou anúncio gratuito): só atualiza.
                self.learn(p.spa, p.sha, now, true);
                None
            }
            Op::Reply => {
                if p.tha == local.mac {
                    self.learn(p.spa, p.sha, now, true);
                }
                None
            }
        }
    }
}
