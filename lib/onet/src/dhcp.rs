//! Cliente `DHCPv4` (RFC 2131, T-633): `DISCOVER`, `OFFER`, `REQUEST`, `ACK`,
//! renovação em T1 (unicast ao servidor), reassociação em T2 (difusão) e
//! volta ao início quando a concessão vence. A máquina é pura: recebe bytes
//! e o relógio e devolve mensagens prontas para o UDP (porta 68 para a 67);
//! a [`crate::stack::Stack`] as leva à rede e aplica a [`Lease`].
//!
//! A resposta é hostil: só vale com `op` 2, `xid` e MAC do cliente certos,
//! cookie mágico, identificador do servidor e, no `ACK`, prazo e máscara
//! contígua. O que não bate é ignorado.

use crate::arp::Ip4;
use crate::eth::Mac;
use crate::ip4::{self, Config};

/// Porta do servidor.
pub const SERVER_PORT: u16 = 67;
/// Porta do cliente.
pub const CLIENT_PORT: u16 = 68;
/// Tamanho do cabeçalho BOOTP com o cookie.
const FIXED: usize = 240;
/// Maior mensagem que o cliente monta.
pub const MAX_MSG: usize = 320;
/// Servidores DNS guardados.
pub const MAX_DNS: usize = 3;

const OP_REQUEST: u8 = 1;
const OP_REPLY: u8 = 2;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Difusão pedida na resposta: o cliente ainda não tem endereço.
const FLAG_BROADCAST: u16 = 0x8000;

const OPT_PAD: u8 = 0;
const OPT_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE: u8 = 51;
const OPT_TYPE: u8 = 53;
const OPT_SERVER: u8 = 54;
const OPT_PARAMS: u8 = 55;
const OPT_T1: u8 = 58;
const OPT_T2: u8 = 59;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;

const SEC: u64 = 1_000_000_000;
/// Espera pela primeira resposta; dobra a cada tentativa até [`MAX_WAIT`].
const FIRST_WAIT: u64 = 2 * SEC;
const MAX_WAIT: u64 = 64 * SEC;
/// Tentativas de `REQUEST` antes de recomeçar.
const REQUEST_TRIES: u8 = 4;
/// Pausa depois de um `NAK` ou de uma concessão perdida, antes de recomeçar.
const RESTART_WAIT: u64 = SEC;

/// O que o servidor concedeu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    /// Endereço, máscara e roteador (zero se o servidor não deu um alcançável).
    pub config: Config,
    /// Servidores DNS, em ordem; só os `dns_count` primeiros valem.
    pub dns: [Ip4; MAX_DNS],
    /// Quantos DNS vieram.
    pub dns_count: usize,
    /// Quem concedeu.
    pub server: Ip4,
    /// Duração da concessão em segundos (`u32::MAX` é eterna).
    pub lease_secs: u32,
}

/// Em que ponto do protocolo o cliente está.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Sem endereço: manda `DISCOVER`.
    Init,
    /// `DISCOVER` mandado, esperando ofertas.
    Selecting,
    /// `REQUEST` mandado, esperando o `ACK`.
    Requesting,
    /// Com endereço.
    Bound,
    /// Passou T1: renova com o servidor.
    Renewing,
    /// Passou T2: pede a qualquer servidor.
    Rebinding,
}

/// Uma mensagem pronta para o UDP.
#[derive(Clone, Copy, Debug)]
pub struct Packet {
    /// Destino: a difusão limitada, ou o servidor ao renovar.
    pub dst: Ip4,
    /// Bytes válidos de `buf`.
    pub len: usize,
    /// A mensagem.
    pub buf: [u8; MAX_MSG],
}

impl Packet {
    /// Os bytes da mensagem.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Resultado de tratar uma mensagem do servidor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nada a fazer.
    None,
    /// Concessão nova ou renovada: aplicar.
    Bound(Lease),
    /// Chegou uma oferta: o `REQUEST` sai no próximo [`Client::poll`].
    Offered,
    /// O servidor recusou; começa de novo.
    Nak,
}

/// O cliente.
#[derive(Debug)]
pub struct Client {
    mac: Mac,
    state: State,
    xid: u32,
    /// Quando agir de novo (retransmitir ou mudar de estado).
    next_at: u64,
    wait: u64,
    tries: u8,
    /// Oferta escolhida ou concessão em uso.
    lease: Option<Lease>,
    /// Instante em que a concessão foi obtida.
    bound_at: u64,
    t1: u64,
    t2: u64,
    expired: bool,
    /// Há mensagem para mandar já (resposta a uma oferta).
    send_now: bool,
}

impl Client {
    /// Cliente novo, sem concessão: o primeiro `poll` manda o `DISCOVER`.
    #[must_use]
    pub const fn new(mac: Mac) -> Self {
        Self {
            mac,
            state: State::Init,
            xid: 0,
            next_at: 0,
            wait: FIRST_WAIT,
            tries: 0,
            lease: None,
            bound_at: 0,
            t1: 0,
            t2: 0,
            expired: false,
            send_now: false,
        }
    }

    /// O estado.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// A concessão em uso.
    #[must_use]
    pub fn lease(&self) -> Option<&Lease> {
        match self.state {
            State::Bound | State::Renewing | State::Rebinding => self.lease.as_ref(),
            _ => None,
        }
    }

    /// `true` uma vez depois que a concessão venceu: quem usa a pilha tira
    /// o endereço.
    pub fn take_expired(&mut self) -> bool {
        core::mem::take(&mut self.expired)
    }

    /// Relógio: devolve a mensagem que deve sair agora, se houver. `random`
    /// escolhe o `xid` de cada transação nova.
    pub fn poll(&mut self, now: u64, random: u32) -> Option<Packet> {
        match self.state {
            State::Init => {
                if now < self.next_at {
                    return None;
                }
                self.xid = random;
                self.state = State::Selecting;
                self.wait = FIRST_WAIT;
                self.next_at = now.saturating_add(self.wait);
                Some(self.build(DISCOVER, None, [0; 4], ip4::LIMITED_BROADCAST))
            }
            State::Selecting => {
                if self.send_now {
                    self.send_now = false;
                    let offer = self.lease?;
                    self.state = State::Requesting;
                    self.tries = 1;
                    self.wait = FIRST_WAIT;
                    self.next_at = now.saturating_add(self.wait);
                    return Some(self.build(
                        REQUEST,
                        Some((offer.config.ip, offer.server)),
                        [0; 4],
                        ip4::LIMITED_BROADCAST,
                    ));
                }
                if now < self.next_at {
                    return None;
                }
                // Sem oferta: repete o `DISCOVER`, esperando cada vez mais.
                self.wait = self.wait.saturating_mul(2).min(MAX_WAIT);
                self.next_at = now.saturating_add(self.wait);
                Some(self.build(DISCOVER, None, [0; 4], ip4::LIMITED_BROADCAST))
            }
            State::Requesting => {
                if now < self.next_at {
                    return None;
                }
                if self.tries >= REQUEST_TRIES {
                    self.restart(now);
                    return None;
                }
                self.tries += 1;
                self.wait = self.wait.saturating_mul(2).min(MAX_WAIT);
                self.next_at = now.saturating_add(self.wait);
                let offer = self.lease?;
                Some(self.build(
                    REQUEST,
                    Some((offer.config.ip, offer.server)),
                    [0; 4],
                    ip4::LIMITED_BROADCAST,
                ))
            }
            State::Bound | State::Renewing | State::Rebinding => self.poll_bound(now),
        }
    }

    fn poll_bound(&mut self, now: u64) -> Option<Packet> {
        let lease = self.lease?;
        let age = now.saturating_sub(self.bound_at);
        if lease.lease_secs != u32::MAX && age >= u64::from(lease.lease_secs).saturating_mul(SEC) {
            self.lease = None;
            self.expired = true;
            self.restart(now);
            return None;
        }
        if lease.lease_secs == u32::MAX {
            return None;
        }
        let ip = lease.config.ip;
        if age >= self.t2 {
            if self.state != State::Rebinding {
                self.state = State::Rebinding;
                self.next_at = 0;
            }
            if now >= self.next_at {
                self.next_at = now.saturating_add(self.retry(self.bound_at, now, lease));
                return Some(self.build(REQUEST, None, ip, ip4::LIMITED_BROADCAST));
            }
        } else if age >= self.t1 {
            if self.state != State::Renewing {
                self.state = State::Renewing;
                self.next_at = 0;
            }
            if now >= self.next_at {
                self.next_at = now.saturating_add(self.retry(self.bound_at, now, lease));
                return Some(self.build(REQUEST, None, ip, lease.server));
            }
        }
        None
    }

    /// Intervalo até a próxima tentativa de renovação: metade do que falta
    /// para o próximo prazo (T2 ou o fim), no mínimo um segundo (RFC 2131 4.4.5).
    fn retry(&self, bound_at: u64, now: u64, lease: Lease) -> u64 {
        let end = if self.state == State::Rebinding {
            u64::from(lease.lease_secs).saturating_mul(SEC)
        } else {
            self.t2
        };
        let left = end.saturating_sub(now.saturating_sub(bound_at));
        (left / 2).max(SEC)
    }

    fn restart(&mut self, now: u64) {
        self.state = State::Init;
        self.next_at = now.saturating_add(RESTART_WAIT);
        self.send_now = false;
    }

    /// Trata uma mensagem DHCP recebida (o corpo do datagrama UDP).
    pub fn input(&mut self, msg: &[u8], now: u64) -> Outcome {
        let Some(m) = parse(msg) else {
            return Outcome::None;
        };
        if m.xid != self.xid || m.chaddr != self.mac.0 {
            return Outcome::None;
        }
        match (self.state, m.kind) {
            (State::Selecting, OFFER) => {
                let Some(lease) = m.lease(false) else {
                    return Outcome::None;
                };
                self.lease = Some(lease);
                self.send_now = true;
                Outcome::Offered
            }
            (State::Requesting | State::Renewing | State::Rebinding, ACK) => {
                let Some(lease) = m.lease(true) else {
                    return Outcome::None;
                };
                self.t1 = m.t1.map_or(u64::from(lease.lease_secs) / 2, u64::from) * SEC;
                self.t2 = m.t2.map_or(u64::from(lease.lease_secs) / 8 * 7, u64::from) * SEC;
                // Prazos incoerentes viram os padrões da RFC.
                if self.t1 >= self.t2 || self.t2 >= u64::from(lease.lease_secs) * SEC {
                    self.t1 = u64::from(lease.lease_secs) / 2 * SEC;
                    self.t2 = u64::from(lease.lease_secs) / 8 * 7 * SEC;
                }
                self.lease = Some(lease);
                self.bound_at = now;
                self.state = State::Bound;
                self.expired = false;
                Outcome::Bound(lease)
            }
            (State::Requesting | State::Renewing | State::Rebinding, NAK) => {
                self.lease = None;
                if self.state != State::Requesting {
                    self.expired = true;
                }
                self.restart(now);
                Outcome::Nak
            }
            _ => Outcome::None,
        }
    }

    fn build(&self, kind: u8, request: Option<(Ip4, Ip4)>, ciaddr: Ip4, dst: Ip4) -> Packet {
        let mut p = Packet {
            dst,
            len: 0,
            buf: [0; MAX_MSG],
        };
        let b = &mut p.buf;
        b[0] = OP_REQUEST;
        b[1] = 1;
        b[2] = 6;
        b[4..8].copy_from_slice(&self.xid.to_be_bytes());
        // Só a difusão do servidor chega a quem ainda não tem endereço.
        if ciaddr == [0; 4] {
            b[10..12].copy_from_slice(&FLAG_BROADCAST.to_be_bytes());
        }
        b[12..16].copy_from_slice(&ciaddr);
        b[28..34].copy_from_slice(&self.mac.0);
        b[236..240].copy_from_slice(&COOKIE);
        let mut n = FIXED;
        let mut put = |data: &[u8]| {
            b[n..n + data.len()].copy_from_slice(data);
            n += data.len();
        };
        put(&[OPT_TYPE, 1, kind]);
        if let Some((ip, server)) = request {
            put(&[OPT_REQUESTED_IP, 4]);
            put(&ip);
            put(&[OPT_SERVER, 4]);
            put(&server);
        }
        put(&[OPT_CLIENT_ID, 7, 1]);
        put(&self.mac.0);
        put(&[
            OPT_PARAMS, 6, OPT_MASK, OPT_ROUTER, OPT_DNS, OPT_LEASE, OPT_T1, OPT_T2,
        ]);
        put(&[OPT_END]);
        p.len = n;
        p
    }
}

/// Mensagem do servidor depois de conferida.
struct Msg {
    kind: u8,
    xid: u32,
    chaddr: [u8; 6],
    yiaddr: Ip4,
    server: Option<Ip4>,
    mask: Option<Ip4>,
    router: Option<Ip4>,
    dns: [Ip4; MAX_DNS],
    dns_count: usize,
    lease_secs: Option<u32>,
    t1: Option<u32>,
    t2: Option<u32>,
}

impl Msg {
    /// A concessão que a mensagem descreve; `None` se faltar o que a RFC
    /// exige (servidor, máscara; prazo no `ACK`) ou o endereço não for de
    /// máquina.
    fn lease(&self, need_time: bool) -> Option<Lease> {
        let server = self.server?;
        let mask = self.mask?;
        let ip = self.yiaddr;
        let m = u32::from_be_bytes(mask);
        // Máscara contígua e que deixa ao menos dois bits de máquina.
        if m == 0 || m.leading_ones() + m.trailing_zeros() != 32 || m.trailing_zeros() < 2 {
            return None;
        }
        if ip == [0; 4] || ip[0] >= 224 || ip[0] == 127 {
            return None;
        }
        let lease_secs = match self.lease_secs {
            Some(0) => return None,
            Some(s) => s,
            None if need_time => return None,
            None => 0,
        };
        let mut config = Config {
            ip,
            mask,
            gateway: [0; 4],
        };
        // Roteador fora da rede não se alcança sem rota: ignorado.
        if let Some(r) = self.router
            && config.same_net(ip, r)
            && r != ip
        {
            config.gateway = r;
        }
        Some(Lease {
            config,
            dns: self.dns,
            dns_count: self.dns_count,
            server,
            lease_secs,
        })
    }
}

fn parse(m: &[u8]) -> Option<Msg> {
    if m.len() < FIXED || m[0] != OP_REPLY || m[1] != 1 || m[2] != 6 || m[236..240] != COOKIE {
        return None;
    }
    let mut out = Msg {
        kind: 0,
        xid: u32::from_be_bytes(m[4..8].try_into().ok()?),
        chaddr: m[28..34].try_into().ok()?,
        yiaddr: m[16..20].try_into().ok()?,
        server: None,
        mask: None,
        router: None,
        dns: [[0; 4]; MAX_DNS],
        dns_count: 0,
        lease_secs: None,
        t1: None,
        t2: None,
    };
    let mut o = &m[FIXED..];
    while let Some(&code) = o.first() {
        match code {
            OPT_PAD => o = &o[1..],
            OPT_END => break,
            _ => {
                let len = usize::from(*o.get(1)?);
                let v = o.get(2..2 + len)?;
                o = &o[2 + len..];
                option(&mut out, code, v);
            }
        }
    }
    (out.kind != 0).then_some(out)
}

fn ip_of(v: &[u8]) -> Option<Ip4> {
    v.get(..4)?.try_into().ok()
}

fn secs_of(v: &[u8]) -> Option<u32> {
    (v.len() == 4).then(|| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

fn option(out: &mut Msg, code: u8, v: &[u8]) {
    match code {
        OPT_TYPE if v.len() == 1 => out.kind = v[0],
        OPT_SERVER if v.len() == 4 => out.server = ip_of(v),
        OPT_MASK if v.len() == 4 => out.mask = ip_of(v),
        OPT_ROUTER if v.len() >= 4 && v.len().is_multiple_of(4) => out.router = ip_of(v),
        OPT_DNS if v.len() >= 4 && v.len().is_multiple_of(4) => {
            for c in v.chunks_exact(4) {
                if let (Some(ip), true) = (ip_of(c), out.dns_count < MAX_DNS) {
                    out.dns[out.dns_count] = ip;
                    out.dns_count += 1;
                }
            }
        }
        OPT_LEASE => out.lease_secs = secs_of(v),
        OPT_T1 => out.t1 = secs_of(v),
        OPT_T2 => out.t2 = secs_of(v),
        _ => {}
    }
}
