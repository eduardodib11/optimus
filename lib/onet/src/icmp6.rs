//! ICMPv6 (RFC 4443) e Descoberta de Vizinhos (RFC 4861): eco, solicitação
//! e anúncio de vizinho, solicitação e anúncio de roteador. As mensagens de ND
//! só valem com limite de saltos 255 (quem as manda está no enlace) e
//! checksum certo; o resto é ignorado.

use crate::eth::Mac;
use crate::ip4;
use crate::ip6::{self, Ip6};

/// Tipos.
pub const ECHO_REQUEST: u8 = 128;
/// Resposta de eco.
pub const ECHO_REPLY: u8 = 129;
const ROUTER_SOLICIT: u8 = 133;
const ROUTER_ADVERT: u8 = 134;
const NEIGHBOR_SOLICIT: u8 = 135;
const NEIGHBOR_ADVERT: u8 = 136;
/// Opções de ND.
const OPT_SLLA: u8 = 1;
const OPT_TLLA: u8 = 2;
const OPT_PREFIX: u8 = 3;
/// Flags do NA.
pub const NA_ROUTER: u8 = 0x80;
/// Solicitado.
pub const NA_SOLICITED: u8 = 0x40;
/// Sobrescreve.
pub const NA_OVERRIDE: u8 = 0x20;
/// Flags do prefixo do RA: no enlace e autônomo (SLAAC).
const PREFIX_ONLINK: u8 = 0x80;
const PREFIX_AUTO: u8 = 0x40;
/// Prefixos que se guardam de um RA.
pub const MAX_PREFIXES: usize = 2;

/// Prefixo anunciado num RA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    /// O prefixo (primeiros `len` bits).
    pub prefix: Ip6,
    /// Comprimento em bits.
    pub len: u8,
    /// Está no enlace.
    pub onlink: bool,
    /// Serve para SLAAC.
    pub autonomous: bool,
    /// Tempo de vida válido (s).
    pub valid: u32,
    /// Tempo de vida preferido (s).
    pub preferred: u32,
}

/// Uma mensagem ICMPv6 entendida.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg<'a> {
    /// Eco (pedido ou resposta).
    Echo {
        /// 128 ou 129.
        kind: u8,
        /// Identificador.
        id: u16,
        /// Sequência.
        seq: u16,
        /// Dados.
        data: &'a [u8],
    },
    /// Solicitação de roteador.
    RouterSolicit,
    /// Anúncio de roteador.
    RouterAdvert {
        /// Tempo de vida do roteador padrão (s); zero = não é padrão.
        lifetime: u16,
        /// Prefixos (só os `nprefix` primeiros valem).
        prefixes: [Option<Prefix>; MAX_PREFIXES],
        /// MAC de quem anunciou.
        slla: Option<Mac>,
    },
    /// Solicitação de vizinho.
    NeighborSolicit {
        /// O endereço procurado.
        target: Ip6,
        /// MAC de quem pergunta.
        slla: Option<Mac>,
    },
    /// Anúncio de vizinho.
    NeighborAdvert {
        /// Flags (`NA_*`).
        flags: u8,
        /// O endereço anunciado.
        target: Ip6,
        /// MAC do dono.
        tlla: Option<Mac>,
    },
}

/// Lê uma mensagem; confere checksum e, para o ND, o limite de saltos.
#[must_use]
pub fn parse<'a>(h: &ip6::Header, p: &'a [u8]) -> Option<Msg<'a>> {
    if p.len() < 4 {
        return None;
    }
    let sum = ip4::sum(
        p,
        ip6::pseudo_sum(&h.src, &h.dst, ip6::PROTO_ICMP6, p.len()),
    );
    if ip4::fold(sum) != 0 {
        return None;
    }
    let kind = p[0];
    if p[1] != 0 {
        return None;
    }
    match kind {
        ECHO_REQUEST | ECHO_REPLY if p.len() >= 8 => Some(Msg::Echo {
            kind,
            id: u16::from_be_bytes([p[4], p[5]]),
            seq: u16::from_be_bytes([p[6], p[7]]),
            data: &p[8..],
        }),
        ROUTER_SOLICIT | ROUTER_ADVERT | NEIGHBOR_SOLICIT | NEIGHBOR_ADVERT
            if h.hop_limit != 255 =>
        {
            None
        }
        ROUTER_SOLICIT if p.len() >= 8 => Some(Msg::RouterSolicit),
        ROUTER_ADVERT if p.len() >= 16 => parse_ra(p),
        NEIGHBOR_SOLICIT | NEIGHBOR_ADVERT if p.len() >= 24 => parse_na_ns(p),
        _ => None,
    }
}

fn mac_at(v: &[u8]) -> Option<Mac> {
    Some(Mac(v.get(..6)?.try_into().ok()?))
}

fn parse_ra(p: &[u8]) -> Option<Msg<'_>> {
    if !options_ok(&p[16..]) {
        return None;
    }
    let mut prefixes = [None; MAX_PREFIXES];
    let mut slla = None;
    let mut n = 0;
    for (code, v) in options(&p[16..]) {
        match code {
            OPT_SLLA if v.len() == 6 => slla = mac_at(v),
            OPT_PREFIX if v.len() == 30 && n < MAX_PREFIXES => {
                let mut prefix = [0u8; 16];
                prefix.copy_from_slice(&v[14..30]);
                prefixes[n] = Some(Prefix {
                    prefix,
                    len: v[0],
                    onlink: v[1] & PREFIX_ONLINK != 0,
                    autonomous: v[1] & PREFIX_AUTO != 0,
                    valid: u32::from_be_bytes([v[2], v[3], v[4], v[5]]),
                    preferred: u32::from_be_bytes([v[6], v[7], v[8], v[9]]),
                });
                n += 1;
            }
            _ => {}
        }
    }
    Some(Msg::RouterAdvert {
        lifetime: u16::from_be_bytes([p[6], p[7]]),
        prefixes,
        slla,
    })
}

/// Solicitação ou anúncio de vizinho: alvo e a opção de endereço de enlace.
fn parse_na_ns(p: &[u8]) -> Option<Msg<'_>> {
    let mut target = [0u8; 16];
    target.copy_from_slice(&p[8..24]);
    if ip6::is_multicast(&target) || !options_ok(&p[24..]) {
        return None;
    }
    let want = if p[0] == NEIGHBOR_SOLICIT {
        OPT_SLLA
    } else {
        OPT_TLLA
    };
    let mut lla = None;
    for (code, v) in options(&p[24..]) {
        if code == want && v.len() == 6 {
            lla = mac_at(v);
        }
    }
    Some(if p[0] == NEIGHBOR_SOLICIT {
        Msg::NeighborSolicit { target, slla: lla }
    } else {
        Msg::NeighborAdvert {
            flags: p[4],
            target,
            tlla: lla,
        }
    })
}

/// Percorre as opções TLV de ND (tamanho em unidades de 8 bytes, nunca
/// zero). Só se chama com `options_ok`.
fn options(o: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut rest = o;
    core::iter::from_fn(move || {
        let len = usize::from(*rest.get(1)?) * 8;
        let (head, tail) = rest.split_at_checked(len)?;
        rest = tail;
        Some((head[0], &head[2..]))
    })
}

/// As opções cobrem o corpo sem sobra e nenhuma tem tamanho zero.
fn options_ok(mut o: &[u8]) -> bool {
    while !o.is_empty() {
        let len = o.get(1).map_or(0, |l| usize::from(*l) * 8);
        if len == 0 || len > o.len() {
            return false;
        }
        o = &o[len..];
    }
    true
}

fn finish(src: &Ip6, dst: &Ip6, msg: &mut [u8]) -> usize {
    msg[2..4].fill(0);
    let c = ip4::fold(ip4::sum(
        msg,
        ip6::pseudo_sum(src, dst, ip6::PROTO_ICMP6, msg.len()),
    ));
    msg[2..4].copy_from_slice(&c.to_be_bytes());
    msg.len()
}

/// Eco (`kind` 128 ou 129): devolve os bytes da mensagem.
#[must_use]
pub fn build_echo(
    src: &Ip6,
    dst: &Ip6,
    kind: u8,
    id: u16,
    seq: u16,
    data: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let len = 8 + data.len();
    let msg = out.get_mut(..len)?;
    msg[0] = kind;
    msg[1] = 0;
    msg[4..6].copy_from_slice(&id.to_be_bytes());
    msg[6..8].copy_from_slice(&seq.to_be_bytes());
    msg[8..].copy_from_slice(data);
    Some(finish(src, dst, msg))
}

/// Solicitação de vizinho para `target`; `slla` vai se a origem não for `::`.
#[must_use]
pub fn build_ns(
    src: &Ip6,
    dst: &Ip6,
    target: &Ip6,
    slla: Option<Mac>,
    out: &mut [u8],
) -> Option<usize> {
    let len = 24 + if slla.is_some() { 8 } else { 0 };
    let msg = out.get_mut(..len)?;
    msg.fill(0);
    msg[0] = NEIGHBOR_SOLICIT;
    msg[8..24].copy_from_slice(target);
    if let Some(m) = slla {
        msg[24] = OPT_SLLA;
        msg[25] = 1;
        msg[26..32].copy_from_slice(&m.0);
    }
    Some(finish(src, dst, msg))
}

/// Anúncio de vizinho.
#[must_use]
pub fn build_na(
    src: &Ip6,
    dst: &Ip6,
    flags: u8,
    target: &Ip6,
    tlla: Mac,
    out: &mut [u8],
) -> Option<usize> {
    let msg = out.get_mut(..32)?;
    msg.fill(0);
    msg[0] = NEIGHBOR_ADVERT;
    msg[4] = flags;
    msg[8..24].copy_from_slice(target);
    msg[24] = OPT_TLLA;
    msg[25] = 1;
    msg[26..32].copy_from_slice(&tlla.0);
    Some(finish(src, dst, msg))
}

/// Solicitação de roteador.
#[must_use]
pub fn build_rs(src: &Ip6, dst: &Ip6, slla: Option<Mac>, out: &mut [u8]) -> Option<usize> {
    let len = 8 + if slla.is_some() { 8 } else { 0 };
    let msg = out.get_mut(..len)?;
    msg.fill(0);
    msg[0] = ROUTER_SOLICIT;
    if let Some(m) = slla {
        msg[8] = OPT_SLLA;
        msg[9] = 1;
        msg[10..16].copy_from_slice(&m.0);
    }
    Some(finish(src, dst, msg))
}
