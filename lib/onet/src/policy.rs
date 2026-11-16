//! A política de rede de um cliente (`NetAccess`, ADR 0068, item 2): o texto
//! da necessidade `net:access:` do manifesto vira esta estrutura, que o
//! `netd` consulta em cada `connect`, `listen` e resolução de nome. Sem
//! política, nada é permitido (item 3).
//!
//! Formato do texto: itens separados por `;`, sem espaços.
//!
//! - `connect=<proto>:<destino>:<portas>`: `proto` é `tcp` ou `udp`;
//!   `destino` é um IPv4 (`10.0.2.2`), uma faixa (`10.0.2.0/24`), `*`
//!   (qualquer endereço), um nome (`exemplo.com`) ou um sufixo
//!   (`*.exemplo.com`, só os subdomínios); `portas` é `80`, `1-1024` ou `*`.
//! - `listen=tcp:<portas>`: portas em que o cliente pode escutar (SDD 10.2:
//!   entrada só para serviço aprovado).
//! - `conns=N`: sockets abertos ao mesmo tempo (padrão [`DEFAULT_CONNS`]).
//! - `rate=N`: novas conexões por segundo (padrão [`DEFAULT_RATE`]).
//!
//! O parser trata o texto como entrada não confiável: nunca entra em pânico
//! e recusa o que passa dos tetos.

/// Regras `connect` por política.
pub const MAX_CONNECT: usize = 8;
/// Regras `listen` por política.
pub const MAX_LISTEN: usize = 4;
/// Maior nome (ou sufixo) numa regra.
pub const MAX_NAME: usize = 64;
/// Sockets abertos ao mesmo tempo, quando a política não diz.
pub const DEFAULT_CONNS: u16 = 8;
/// Novas conexões por segundo, quando a política não diz.
pub const DEFAULT_RATE: u16 = 10;
/// Tetos de `conns` e `rate`.
pub const MAX_CONNS: u16 = 256;
/// Teto de `rate`.
pub const MAX_RATE: u16 = 1000;

/// Protocolo de transporte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
}

/// Por que um texto de política não vale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Item, protocolo, endereço, nome ou porta fora do formato.
    Syntax,
    /// Regras demais, ou valor acima dos tetos.
    Limit,
}

/// Faixa de portas, fechada nos dois lados.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ports {
    lo: u16,
    hi: u16,
}

impl Ports {
    const ANY: Self = Self { lo: 0, hi: 65535 };

    fn parse(s: &str) -> Result<Self, ParseError> {
        if s == "*" {
            return Ok(Self::ANY);
        }
        let (lo, hi) = if let Some((a, b)) = s.split_once('-') {
            (port(a)?, port(b)?)
        } else {
            let p = port(s)?;
            (p, p)
        };
        if lo > hi {
            return Err(ParseError::Syntax);
        }
        Ok(Self { lo, hi })
    }

    /// A porta `p` está na faixa.
    #[must_use]
    pub const fn contains(&self, p: u16) -> bool {
        self.lo <= p && p <= self.hi
    }
}

fn port(s: &str) -> Result<u16, ParseError> {
    match s.parse::<u16>() {
        Ok(0) | Err(_) => Err(ParseError::Syntax),
        Ok(p) => Ok(p),
    }
}

/// Um nome em minúsculas, de até [`MAX_NAME`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Name {
    buf: [u8; MAX_NAME],
    len: usize,
}

impl Name {
    const EMPTY: Self = Self {
        buf: [0; MAX_NAME],
        len: 0,
    };

    /// Nome válido: rótulos de letras, dígitos, `-` e `_` separados por `.`.
    fn parse(s: &str) -> Result<Self, ParseError> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > MAX_NAME {
            return Err(ParseError::Limit);
        }
        let ok = b
            .split(|&c| c == b'.')
            .all(|l| !l.is_empty() && l.iter().all(|&c| valid_label_byte(c)));
        if !ok {
            return Err(ParseError::Syntax);
        }
        let mut out = Self::EMPTY;
        for (d, s) in out.buf.iter_mut().zip(b) {
            *d = s.to_ascii_lowercase();
        }
        out.len = b.len();
        Ok(out)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

const fn valid_label_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// Para onde a regra deixa ir.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// Qualquer endereço IPv4.
    Any,
    /// Uma faixa IPv4 (`/32` para um endereço só).
    Net {
        /// Endereço de rede.
        ip: [u8; 4],
        /// Bits da máscara, 0 a 32.
        bits: u8,
    },
    /// Exatamente este nome.
    Name(Name),
    /// Qualquer subdomínio deste sufixo (`*.exemplo.com`), nunca o próprio.
    Suffix(Name),
}

impl Dest {
    fn parse(s: &str) -> Result<Self, ParseError> {
        if s == "*" {
            return Ok(Self::Any);
        }
        if let Some(rest) = s.strip_prefix("*.") {
            return Ok(Self::Suffix(Name::parse(rest)?));
        }
        // Começa por dígito e tem só dígitos, pontos e `/`: é endereço.
        if s.bytes()
            .all(|c| c.is_ascii_digit() || c == b'.' || c == b'/')
        {
            let (a, bits) = match s.split_once('/') {
                Some((a, m)) => (a, m.parse::<u8>().map_err(|_| ParseError::Syntax)?),
                None => (s, 32),
            };
            if bits > 32 {
                return Err(ParseError::Syntax);
            }
            let ip = ipv4(a)?;
            return Ok(Self::Net { ip, bits });
        }
        Ok(Self::Name(Name::parse(s)?))
    }

    fn contains_ip(&self, ip: [u8; 4]) -> bool {
        match self {
            Self::Any => true,
            Self::Net { ip: net, bits } => {
                let m = if *bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(*bits))
                };
                u32::from_be_bytes(ip) & m == u32::from_be_bytes(*net) & m
            }
            Self::Name(_) | Self::Suffix(_) => false,
        }
    }

    fn contains_name(&self, name: &[u8]) -> bool {
        match self {
            Self::Any => true,
            Self::Net { .. } => false,
            Self::Name(n) => eq_ignore_case(n.as_bytes(), name),
            Self::Suffix(n) => {
                let suf = n.as_bytes();
                // `x.sufixo`: o nome termina em `.sufixo` e tem rótulo antes.
                name.len() > suf.len() + 1
                    && name[name.len() - suf.len() - 1] == b'.'
                    && eq_ignore_case(suf, &name[name.len() - suf.len()..])
            }
        }
    }
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn ipv4(s: &str) -> Result<[u8; 4], ParseError> {
    let mut out = [0u8; 4];
    let mut it = s.split('.');
    for o in &mut out {
        *o = it
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or(ParseError::Syntax)?;
    }
    if it.next().is_some() {
        return Err(ParseError::Syntax);
    }
    Ok(out)
}

/// Uma regra `connect`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectRule {
    proto: Proto,
    dest: Dest,
    ports: Ports,
}

/// Uma regra `listen`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenRule {
    ports: Ports,
}

/// A política de um cliente.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    connect: [ConnectRule; MAX_CONNECT],
    n_connect: usize,
    listen: [ListenRule; MAX_LISTEN],
    n_listen: usize,
    conns: u16,
    rate: u16,
}

impl Policy {
    /// Sem `NetAccess`: nada é permitido e nenhum socket abre.
    pub const DENY: Self = Self {
        connect: [ConnectRule {
            proto: Proto::Tcp,
            dest: Dest::Any,
            ports: Ports::ANY,
        }; MAX_CONNECT],
        n_connect: 0,
        listen: [ListenRule { ports: Ports::ANY }; MAX_LISTEN],
        n_listen: 0,
        conns: 0,
        rate: 0,
    };

    /// Lê o texto da necessidade `net:access:` (sem o prefixo).
    ///
    /// # Errors
    ///
    /// [`ParseError`] para texto fora do formato ou acima dos tetos.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut p = Self::DENY;
        p.conns = DEFAULT_CONNS;
        p.rate = DEFAULT_RATE;
        for item in text.split(';').filter(|i| !i.is_empty()) {
            let (key, value) = item.split_once('=').ok_or(ParseError::Syntax)?;
            match key {
                "connect" => {
                    let rule = parse_connect(value)?;
                    *p.connect.get_mut(p.n_connect).ok_or(ParseError::Limit)? = rule;
                    p.n_connect += 1;
                }
                "listen" => {
                    let ports = value.strip_prefix("tcp:").ok_or(ParseError::Syntax)?;
                    let rule = ListenRule {
                        ports: Ports::parse(ports)?,
                    };
                    *p.listen.get_mut(p.n_listen).ok_or(ParseError::Limit)? = rule;
                    p.n_listen += 1;
                }
                "conns" => p.conns = number(value, MAX_CONNS)?,
                "rate" => p.rate = number(value, MAX_RATE)?,
                _ => return Err(ParseError::Syntax),
            }
        }
        Ok(p)
    }

    /// Sockets abertos ao mesmo tempo.
    #[must_use]
    pub const fn max_sockets(&self) -> u16 {
        self.conns
    }

    /// Novas conexões por segundo.
    #[must_use]
    pub const fn max_rate(&self) -> u16 {
        self.rate
    }

    fn connect_rules(&self) -> &[ConnectRule] {
        &self.connect[..self.n_connect]
    }

    /// `connect` a `ip:port` por `proto` é permitido por uma regra de
    /// endereço (nome não vale aqui: o endereço de um nome só entra pela
    /// resolução, ADR 0068, item 3).
    #[must_use]
    pub fn allows_ip(&self, proto: Proto, ip: [u8; 4], port: u16) -> bool {
        self.connect_rules()
            .iter()
            .any(|r| r.proto == proto && r.ports.contains(port) && r.dest.contains_ip(ip))
    }

    /// Resolver `name` e usar o resultado em `proto:port` é permitido.
    #[must_use]
    pub fn allows_name(&self, proto: Proto, name: &[u8], port: u16) -> bool {
        self.connect_rules()
            .iter()
            .any(|r| r.proto == proto && r.ports.contains(port) && r.dest.contains_name(name))
    }

    /// Alguma regra deixa usar `name` em qualquer porta de `proto`, o que
    /// basta para o `netd` resolver o nome (a porta se confere no `connect`).
    #[must_use]
    pub fn mentions_name(&self, name: &[u8]) -> bool {
        self.connect_rules().iter().any(|r| {
            matches!(r.dest, Dest::Name(_) | Dest::Suffix(_)) && r.dest.contains_name(name)
        })
    }

    /// `listen` em `port` é permitido.
    #[must_use]
    pub fn allows_listen(&self, port: u16) -> bool {
        self.listen[..self.n_listen]
            .iter()
            .any(|r| r.ports.contains(port))
    }
}

fn number(s: &str, max: u16) -> Result<u16, ParseError> {
    match s.parse::<u16>() {
        Ok(n) if n <= max => Ok(n),
        Ok(_) => Err(ParseError::Limit),
        Err(_) => Err(ParseError::Syntax),
    }
}

fn parse_connect(v: &str) -> Result<ConnectRule, ParseError> {
    let mut it = v.splitn(3, ':');
    let proto = match it.next() {
        Some("tcp") => Proto::Tcp,
        Some("udp") => Proto::Udp,
        _ => return Err(ParseError::Syntax),
    };
    let dest = Dest::parse(it.next().ok_or(ParseError::Syntax)?)?;
    let ports = Ports::parse(it.next().ok_or(ParseError::Syntax)?)?;
    Ok(ConnectRule { proto, dest, ports })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW: [u8; 4] = [10, 0, 2, 2];

    #[test]
    fn sem_politica_nega_tudo() {
        let p = Policy::DENY;
        assert!(!p.allows_ip(Proto::Tcp, GW, 80));
        assert!(!p.allows_name(Proto::Tcp, b"exemplo.com", 80));
        assert!(!p.allows_listen(80));
        assert_eq!(p.max_sockets(), 0);
    }

    #[test]
    fn regras_de_endereco_e_porta() {
        let p =
            Policy::parse("connect=tcp:10.0.2.2:47108;connect=udp:10.0.2.0/24:53;conns=4;rate=2")
                .unwrap();
        assert!(p.allows_ip(Proto::Tcp, GW, 47108));
        assert!(!p.allows_ip(Proto::Tcp, GW, 47109));
        assert!(!p.allows_ip(Proto::Udp, GW, 47108));
        assert!(p.allows_ip(Proto::Udp, [10, 0, 2, 3], 53));
        assert!(!p.allows_ip(Proto::Udp, [10, 0, 3, 3], 53));
        assert_eq!((p.max_sockets(), p.max_rate()), (4, 2));
    }

    #[test]
    fn padroes_de_limite() {
        let p = Policy::parse("connect=tcp:*:1-1024").unwrap();
        assert_eq!(
            (p.max_sockets(), p.max_rate()),
            (DEFAULT_CONNS, DEFAULT_RATE)
        );
        assert!(p.allows_ip(Proto::Tcp, [8, 8, 8, 8], 443));
        assert!(!p.allows_ip(Proto::Tcp, [8, 8, 8, 8], 8080));
    }

    #[test]
    fn nomes_exatos_e_sufixos() {
        let p = Policy::parse("connect=tcp:Exemplo.com:443;connect=tcp:*.svc.test:*").unwrap();
        assert!(p.allows_name(Proto::Tcp, b"EXEMPLO.com", 443));
        assert!(!p.allows_name(Proto::Tcp, b"www.exemplo.com", 443));
        assert!(!p.allows_name(Proto::Tcp, b"exemplo.com", 80));
        assert!(p.allows_name(Proto::Tcp, b"a.svc.test", 22));
        assert!(!p.allows_name(Proto::Tcp, b"svc.test", 22));
        assert!(!p.allows_name(Proto::Tcp, b"xsvc.test", 22));
        assert!(p.mentions_name(b"a.b.svc.test"));
        assert!(!p.mentions_name(b"outro.com"));
        // Nome não dá acesso a endereço, nem o contrário.
        assert!(!p.allows_ip(Proto::Tcp, GW, 443));
    }

    #[test]
    fn listen_so_o_que_a_politica_diz() {
        let p = Policy::parse("listen=tcp:8080;listen=tcp:9000-9010").unwrap();
        assert!(p.allows_listen(8080) && p.allows_listen(9005));
        assert!(!p.allows_listen(22) && !p.allows_listen(9011));
        assert!(Policy::parse("connect=tcp:*:*").is_ok_and(|p| !p.allows_listen(80)));
    }

    #[test]
    fn recusa_texto_fora_do_formato() {
        for ruim in [
            "connect",
            "connect=tcp",
            "connect=tcp:10.0.2.2",
            "connect=icmp:10.0.2.2:1",
            "connect=tcp:10.0.2:80",
            "connect=tcp:10.0.2.256:80",
            "connect=tcp:10.0.2.0/33:80",
            "connect=tcp:10.0.2.2:0",
            "connect=tcp:10.0.2.2:70000",
            "connect=tcp:10.0.2.2:90-80",
            "connect=tcp:a..b:80",
            "connect=tcp:a b:80",
            "listen=udp:53",
            "conns=abc",
            "outra=1",
        ] {
            assert_eq!(Policy::parse(ruim), Err(ParseError::Syntax), "{ruim}");
        }
        assert_eq!(Policy::parse("conns=257"), Err(ParseError::Limit));
        assert_eq!(Policy::parse("rate=1001"), Err(ParseError::Limit));
    }

    #[test]
    fn recusa_acima_dos_tetos() {
        let nove = "connect=tcp:*:1;".repeat(MAX_CONNECT + 1);
        assert_eq!(Policy::parse(&nove), Err(ParseError::Limit));
        assert!(Policy::parse(&nove[..nove.len() - "connect=tcp:*:1;".len()]).is_ok());
        let longo = alloc::format!("connect=tcp:{}:80", "a".repeat(MAX_NAME + 1));
        assert_eq!(Policy::parse(&longo), Err(ParseError::Limit));
    }

    #[test]
    fn faixa_de_zero_bits_vale_para_todos() {
        let p = Policy::parse("connect=udp:0.0.0.0/0:53").unwrap();
        assert!(p.allows_ip(Proto::Udp, [1, 2, 3, 4], 53));
    }
}
