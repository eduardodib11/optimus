//! Configuração automática de endereços IPv6 (RFC 4862) com identificadores
//! opacos estáveis (RFC 7217) e endereços temporários de privacidade
//! (RFC 8981): endereço local do enlace, detecção de duplicidade (DAD, uma
//! tentativa), solicitação de roteador e o que se aprende dos anúncios.
//! Sem relógio nem I/O: o chamador passa `now` (ns) e manda o que `poll`
//! devolve.

use crate::eth::Mac;
use crate::icmp6::Prefix;
use crate::ip6::{self, Ip6};

/// Endereços que a interface guarda: local do enlace, estável e temporário
/// (mais um de folga na troca do temporário).
pub const MAX_ADDRS: usize = 4;
/// Prefixos no enlace guardados.
pub const MAX_PREFIXES: usize = 2;
/// Espera da DAD (`RetransTimer`, RFC 4861) em ns.
pub const DAD_NS: u64 = 1_000_000_000;
/// Intervalo entre solicitações de roteador em ns.
pub const RS_INTERVAL_NS: u64 = 4_000_000_000;
/// Solicitações de roteador antes de desistir.
pub const MAX_RS: u8 = 3;
/// Vida preferida máxima de um endereço temporário (s), RFC 8981.
pub const TEMP_PREFERRED_S: u32 = 86_400;
/// Vida válida máxima de um endereço temporário (s): 7 dias.
pub const TEMP_VALID_S: u32 = 604_800;
/// Tentativas de identificador depois de um conflito na DAD (RFC 7217).
const MAX_DAD_RETRIES: u8 = 3;

const NS_PER_S: u64 = 1_000_000_000;

/// Como o endereço foi formado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `fe80::/64`.
    LinkLocal,
    /// Global com identificador opaco estável.
    Stable,
    /// Global temporário (muda a cada vida preferida).
    Temporary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Em DAD: `sent` diz se a pergunta já saiu; vale a partir de `until`.
    Tentative {
        sent: bool,
        until: u64,
    },
    Preferred,
}

/// Um endereço da interface.
#[derive(Clone, Copy, Debug)]
pub struct Addr {
    /// O endereço.
    pub ip: Ip6,
    /// Como foi formado.
    pub kind: Kind,
    state: State,
    /// Fim da vida válida e da preferida (ns).
    valid_until: u64,
    preferred_until: u64,
}

impl Addr {
    /// Pode ser origem de pacotes (DAD concluída e preferida).
    #[must_use]
    pub const fn usable(&self, now: u64) -> bool {
        matches!(self.state, State::Preferred) && now < self.preferred_until
    }
}

/// O roteador padrão aprendido de um anúncio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Router {
    /// Endereço local do enlace dele.
    pub ip: Ip6,
    until: u64,
}

/// Prefixo no enlace.
#[derive(Clone, Copy, Debug)]
struct OnLink {
    prefix: Ip6,
    len: u8,
    until: u64,
}

/// O que mandar agora.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx {
    /// Solicitação de vizinho da DAD para `target` (origem `::`, destino o nó
    /// solicitado de `target`).
    Dad(Ip6),
    /// Solicitação de roteador a partir do endereço local do enlace `src`.
    RouterSolicit(Ip6),
}

/// Estado da configuração automática.
#[derive(Debug)]
pub struct Slaac {
    mac: Mac,
    secret: [u8; 16],
    addrs: [Option<Addr>; MAX_ADDRS],
    router: Option<Router>,
    onlink: [Option<OnLink>; MAX_PREFIXES],
    dad_retries: u8,
    rs_sent: u8,
    rs_at: u64,
    started: bool,
}

/// Parte de 64 bits do identificador opaco (RFC 7217) para `prefix`.
fn opaque_iid(secret: &[u8; 16], prefix: &[u8], mac: Mac, counter: u8) -> [u8; 8] {
    let mut m = [0u8; 16 + 8 + 6 + 1];
    m[..16].copy_from_slice(secret);
    m[16..16 + prefix.len().min(8)].copy_from_slice(&prefix[..prefix.len().min(8)]);
    m[24..30].copy_from_slice(&mac.0);
    m[30] = counter;
    let h = optcrypt::blake3::hash(&m);
    let mut iid = [0u8; 8];
    iid.copy_from_slice(&h[..8]);
    iid
}

fn with_prefix(prefix: &Ip6, iid: [u8; 8]) -> Ip6 {
    let mut a = [0u8; 16];
    a[..8].copy_from_slice(&prefix[..8]);
    a[8..].copy_from_slice(&iid);
    a
}

fn secs(s: u32) -> u64 {
    u64::from(s) * NS_PER_S
}

impl Slaac {
    /// Estado inicial: nada configurado.
    #[must_use]
    pub const fn new(mac: Mac) -> Self {
        Self {
            mac,
            secret: [0; 16],
            addrs: [None; MAX_ADDRS],
            router: None,
            onlink: [None; MAX_PREFIXES],
            dad_retries: 0,
            rs_sent: 0,
            rs_at: 0,
            started: false,
        }
    }

    /// Semeia o segredo dos identificadores (DRBG do kernel).
    pub fn seed(&mut self, secret: [u8; 16]) {
        self.secret = secret;
    }

    /// Começa a configuração: cria o endereço local do enlace.
    pub fn start(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        self.add_link_local();
    }

    fn add_link_local(&mut self) {
        let mut p = [0u8; 16];
        p[0] = 0xfe;
        p[1] = 0x80;
        let iid = opaque_iid(&self.secret, &p[..8], self.mac, self.dad_retries);
        let ip = with_prefix(&p, iid);
        self.insert(Addr {
            ip,
            kind: Kind::LinkLocal,
            state: State::Tentative {
                sent: false,
                until: 0,
            },
            valid_until: u64::MAX,
            preferred_until: u64::MAX,
        });
    }

    fn insert(&mut self, a: Addr) -> bool {
        match self.addrs.iter_mut().find(|s| s.is_none()) {
            Some(s) => {
                *s = Some(a);
                true
            }
            None => false,
        }
    }

    /// Os endereços da interface.
    pub fn addrs(&self) -> impl Iterator<Item = &Addr> {
        self.addrs.iter().flatten()
    }

    /// O roteador padrão, se o anúncio ainda vale.
    #[must_use]
    pub fn router(&self, now: u64) -> Option<Ip6> {
        self.router.filter(|r| now < r.until).map(|r| r.ip)
    }

    /// O endereço é nosso (inclui os em DAD, para detectar conflito).
    #[must_use]
    pub fn owns(&self, ip: &Ip6) -> bool {
        self.addrs().any(|a| a.ip == *ip)
    }

    /// O endereço é nosso e já vale como destino.
    #[must_use]
    pub fn owns_ready(&self, ip: &Ip6, now: u64) -> bool {
        self.addrs()
            .any(|a| a.ip == *ip && matches!(a.state, State::Preferred) && now < a.valid_until)
    }

    /// O destino é de grupo que a interface escuta: todos os nós e o nó
    /// solicitado de cada endereço.
    #[must_use]
    pub fn listens(&self, ip: &Ip6) -> bool {
        *ip == ip6::ALL_NODES || self.addrs().any(|a| ip6::solicited_node(&a.ip) == *ip)
    }

    /// O endereço local do enlace pronto, se houver.
    #[must_use]
    pub fn link_local(&self, now: u64) -> Option<Ip6> {
        self.addrs()
            .find(|a| a.kind == Kind::LinkLocal && a.usable(now))
            .map(|a| a.ip)
    }

    /// O melhor endereço global pronto: o temporário, senão o estável
    /// (RFC 8981, 3.3.7: temporários são preferidos).
    #[must_use]
    pub fn global(&self, now: u64) -> Option<Ip6> {
        let pick = |k| self.addrs().find(|a| a.kind == k && a.usable(now));
        pick(Kind::Temporary)
            .or_else(|| pick(Kind::Stable))
            .map(|a| a.ip)
    }

    /// Origem para falar com `dst`: o local do enlace para destino local do
    /// enlace, senão o melhor global (ou o local do enlace sem global).
    #[must_use]
    pub fn source_for(&self, dst: &Ip6, now: u64) -> Option<Ip6> {
        if ip6::is_link_local(dst) || (ip6::is_multicast(dst) && dst[1] & 0x0f == 2) {
            return self.link_local(now);
        }
        self.global(now).or_else(|| self.link_local(now))
    }

    /// O destino está no enlace: local do enlace ou dentro de um prefixo
    /// anunciado como no enlace.
    #[must_use]
    pub fn on_link(&self, dst: &Ip6, now: u64) -> bool {
        ip6::is_link_local(dst)
            || self
                .onlink
                .iter()
                .flatten()
                .any(|o| now < o.until && same_prefix(&o.prefix, dst, o.len))
    }

    /// Próximo salto para `dst`: o próprio destino no enlace, senão o
    /// roteador padrão.
    #[must_use]
    pub fn next_hop(&self, dst: &Ip6, now: u64) -> Option<Ip6> {
        if ip6::is_multicast(dst) || self.on_link(dst, now) {
            Some(*dst)
        } else {
            self.router(now)
        }
    }

    /// Passo do relógio: expira endereços, conclui DAD e devolve a próxima
    /// mensagem a mandar (chame de novo até `None`).
    pub fn poll(&mut self, now: u64, rand: u32) -> Option<Tx> {
        if !self.started {
            return None;
        }
        for s in &mut self.addrs {
            if s.is_some_and(|a| now >= a.valid_until) {
                *s = None;
            }
        }
        for a in self.addrs.iter_mut().flatten() {
            if let State::Tentative { sent, until } = a.state {
                if !sent {
                    a.state = State::Tentative {
                        sent: true,
                        until: now.saturating_add(DAD_NS),
                    };
                    return Some(Tx::Dad(a.ip));
                }
                if now >= until {
                    a.state = State::Preferred;
                }
            }
        }
        // Solicita roteador depois que o endereço local do enlace está pronto.
        if self.router.is_none() && self.rs_sent < MAX_RS {
            let src = self.link_local(now)?;
            if self.rs_at == 0 {
                // Atraso aleatório de até 1 s antes da primeira (RFC 4861 6.3.7).
                self.rs_at = now.saturating_add(u64::from(rand % 1000) * 1_000_000);
            }
            if now >= self.rs_at {
                self.rs_sent += 1;
                self.rs_at = now.saturating_add(RS_INTERVAL_NS);
                return Some(Tx::RouterSolicit(src));
            }
        }
        None
    }

    /// Anúncio de roteador `src` (já validado: limite de saltos 255).
    /// Devolve `true` se mudou algo que pede ao chamador aprender o MAC do
    /// roteador.
    pub fn input_ra(
        &mut self,
        src: &Ip6,
        lifetime: u16,
        prefixes: &[Option<Prefix>],
        now: u64,
        rand: u64,
    ) -> bool {
        if !ip6::is_link_local(src) {
            return false;
        }
        self.router = if lifetime == 0 {
            None
        } else {
            Some(Router {
                ip: *src,
                until: now.saturating_add(secs(u32::from(lifetime))),
            })
        };
        for p in prefixes.iter().flatten() {
            if p.preferred > p.valid
                || ip6::is_link_local(&p.prefix)
                || ip6::is_multicast(&p.prefix)
            {
                continue;
            }
            if p.onlink {
                self.add_onlink(p, now);
            }
            if p.autonomous && p.len == 64 && p.valid > 0 {
                self.autoconf(p, now, rand);
            }
        }
        true
    }

    fn add_onlink(&mut self, p: &Prefix, now: u64) {
        let until = now.saturating_add(secs(p.valid));
        let same = |o: &Option<OnLink>| {
            o.is_some_and(|o| o.len == p.len && same_prefix(&o.prefix, &p.prefix, p.len))
        };
        let slot = self
            .onlink
            .iter()
            .position(same)
            .or_else(|| self.onlink.iter().position(Option::is_none));
        if let Some(i) = slot {
            self.onlink[i] = Some(OnLink {
                prefix: p.prefix,
                len: p.len,
                until,
            });
        }
    }

    /// Forma ou renova os endereços estável e temporário do prefixo.
    fn autoconf(&mut self, p: &Prefix, now: u64, rand: u64) {
        let valid = now.saturating_add(secs(p.valid));
        let pref = now.saturating_add(secs(p.preferred));
        let in_prefix = |a: &Addr| a.kind != Kind::LinkLocal && a.ip[..8] == p.prefix[..8];
        // Estável.
        let iid = opaque_iid(&self.secret, &p.prefix[..8], self.mac, self.dad_retries);
        let stable = with_prefix(&p.prefix, iid);
        if let Some(a) = self.addrs.iter_mut().flatten().find(|a| a.ip == stable) {
            a.valid_until = valid;
            a.preferred_until = pref;
        } else {
            let _ = self.insert(Addr {
                ip: stable,
                kind: Kind::Stable,
                state: State::Tentative {
                    sent: false,
                    until: 0,
                },
                valid_until: valid,
                preferred_until: pref,
            });
        }
        // Temporário: troca quando o preferido venceu (RFC 8981).
        let temp_valid = valid.min(now.saturating_add(secs(TEMP_VALID_S)));
        let temp_pref = pref.min(now.saturating_add(secs(TEMP_PREFERRED_S)));
        let live = self
            .addrs()
            .any(|a| in_prefix(a) && a.kind == Kind::Temporary && now < a.preferred_until);
        if !live && temp_pref > now {
            // Identificador aleatório, com o bit "universal/local" apagado.
            let mut iid = opaque_iid(&self.secret, &rand.to_le_bytes(), self.mac, 0xa5);
            iid[0] &= !0x02;
            let _ = self.insert(Addr {
                ip: with_prefix(&p.prefix, iid),
                kind: Kind::Temporary,
                state: State::Tentative {
                    sent: false,
                    until: 0,
                },
                valid_until: temp_valid,
                preferred_until: temp_pref,
            });
        }
    }

    /// Alguém usa um endereço nosso em DAD (anúncio de vizinho para ele ou
    /// solicitação da origem `::` com ele como alvo): o endereço é removido.
    /// Um conflito no local do enlace refaz o endereço com outro
    /// identificador, até [`MAX_DAD_RETRIES`] vezes.
    pub fn conflict(&mut self, ip: &Ip6) {
        let Some(s) = self
            .addrs
            .iter_mut()
            .find(|s| s.is_some_and(|a| a.ip == *ip && matches!(a.state, State::Tentative { .. })))
        else {
            return;
        };
        let kind = s.map(|a| a.kind);
        *s = None;
        if kind == Some(Kind::LinkLocal) && self.dad_retries < MAX_DAD_RETRIES {
            self.dad_retries += 1;
            self.add_link_local();
        }
    }
}

fn same_prefix(a: &Ip6, b: &Ip6, len: u8) -> bool {
    let full = usize::from(len / 8);
    let rem = len % 8;
    if full > 16 || a[..full] != b[..full] {
        return false;
    }
    rem == 0 || full >= 16 || (a[full] ^ b[full]) >> (8 - rem) == 0
}
