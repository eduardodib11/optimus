//! IPv6 (RFC 8200): cabeçalho fixo, cabeçalhos de extensão que se pulam e
//! endereços especiais. O cabeçalho de fragmento é entregue a quem monta
//! ([`crate::frag`]); não há fragmentação de saída (ADR 0069, item 4).

use crate::eth::Mac;
use crate::ip4;

/// Endereço IPv6.
pub type Ip6 = [u8; 16];

/// Bytes do cabeçalho fixo.
pub const HEADER_LEN: usize = 40;
/// `Next Header` do TCP, do UDP e do ICMPv6.
pub const PROTO_TCP: u8 = 6;
/// UDP.
pub const PROTO_UDP: u8 = 17;
/// ICMPv6.
pub const PROTO_ICMP6: u8 = 58;
/// Limite de saltos dos pacotes de ND e dos de saída.
pub const HOP_LIMIT: u8 = 64;
/// Cabeçalhos de extensão que se aceita pular num pacote.
const MAX_EXT: usize = 4;

/// `ff02::1`: todos os nós do enlace.
pub const ALL_NODES: Ip6 = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// `ff02::2`: todos os roteadores do enlace.
pub const ALL_ROUTERS: Ip6 = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// `::`.
pub const UNSPECIFIED: Ip6 = [0; 16];

/// O cabeçalho de um pacote (com o protocolo da camada de cima, depois dos
/// cabeçalhos de extensão).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Classe de tráfego.
    pub traffic_class: u8,
    /// Rótulo de fluxo (20 bits).
    pub flow_label: u32,
    /// Protocolo da carga.
    pub next: u8,
    /// Limite de saltos.
    pub hop_limit: u8,
    /// Origem.
    pub src: Ip6,
    /// Destino.
    pub dst: Ip6,
    /// Preenchido quando o pacote é um fragmento (cabeçalho de fragmento).
    pub frag: Option<Frag>,
}

/// O cabeçalho de fragmento (RFC 8200, 4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frag {
    /// Identificação (32 bits).
    pub id: u32,
    /// Deslocamento em bytes (múltiplo de 8).
    pub offset: u16,
    /// Há mais fragmentos.
    pub more: bool,
}

/// Endereço de grupo (`ff00::/8`).
#[must_use]
pub fn is_multicast(a: &Ip6) -> bool {
    a[0] == 0xff
}

/// Endereço local do enlace (`fe80::/10`).
#[must_use]
pub fn is_link_local(a: &Ip6) -> bool {
    a[0] == 0xfe && a[1] & 0xc0 == 0x80
}

/// Endereço do nó solicitado (`ff02::1:ffXX:XXXX`, RFC 4291 2.7.1).
#[must_use]
pub fn solicited_node(a: &Ip6) -> Ip6 {
    let mut o = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0];
    o[13..16].copy_from_slice(&a[13..16]);
    o
}

/// MAC de um endereço de grupo (`33:33` e os 4 últimos bytes, RFC 2464).
#[must_use]
pub fn multicast_mac(a: &Ip6) -> Mac {
    Mac([0x33, 0x33, a[12], a[13], a[14], a[15]])
}

/// Soma do pseudo-cabeçalho de 40 bytes (RFC 8200, 8.1) para o checksum.
#[must_use]
pub fn pseudo_sum(src: &Ip6, dst: &Ip6, next: u8, len: usize) -> u32 {
    let mut s = ip4::sum(src, 0);
    s = ip4::sum(dst, s);
    let l = u32::try_from(len).unwrap_or(u32::MAX);
    s += (l >> 16) + (l & 0xffff);
    s + u32::from(next)
}

/// Lê um pacote. Pula cabeçalhos de extensão (opções de salto, de destino e
/// roteamento sem saltos restantes); roteamento ativo, extensão em excesso
/// e qualquer inconsistência devolvem `None`. Num fragmento, devolve o
/// cabeçalho com `frag` preenchido e a carga do fragmento.
#[must_use]
pub fn parse(pkt: &[u8]) -> Option<(Header, &[u8])> {
    if pkt.len() < HEADER_LEN || pkt[0] >> 4 != 6 {
        return None;
    }
    let plen = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
    let body = pkt.get(HEADER_LEN..HEADER_LEN + plen)?;
    let mut next = pkt[6];
    let mut rest = body;
    for _ in 0..=MAX_EXT {
        match next {
            0 | 60 | 43 => {
                let len = (usize::from(*rest.get(1)?) + 1) * 8;
                if next == 43 && rest.get(3).copied()? != 0 {
                    return None;
                }
                let n = *rest.first()?;
                rest = rest.get(len..)?;
                next = n;
            }
            44 => {
                let f = rest.get(..8)?;
                let n = f[0];
                // Extensão dentro do fragmentável não se trata.
                if matches!(n, 0 | 43 | 44 | 60) {
                    return None;
                }
                let field = u16::from_be_bytes([f[2], f[3]]);
                let frag = Frag {
                    id: u32::from_be_bytes([f[4], f[5], f[6], f[7]]),
                    offset: field & 0xfff8,
                    more: field & 1 != 0,
                };
                // Fragmento "atômico" (RFC 6946): é o pacote inteiro.
                let frag = (frag.offset != 0 || frag.more).then_some(frag);
                next = n;
                rest = &rest[8..];
                return Some((header(pkt, next, frag), rest));
            }
            _ => {
                return Some((header(pkt, next, None), rest));
            }
        }
    }
    None
}

fn header(pkt: &[u8], next: u8, frag: Option<Frag>) -> Header {
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    dst.copy_from_slice(&pkt[24..40]);
    Header {
        traffic_class: (pkt[0] << 4) | (pkt[1] >> 4),
        flow_label: u32::from_be_bytes([0, pkt[1] & 0x0f, pkt[2], pkt[3]]),
        next,
        hop_limit: pkt[7],
        src,
        dst,
        frag,
    }
}

/// Monta um pacote em `out` (sem extensões); devolve o tamanho.
#[must_use]
pub fn build(h: &Header, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let len = HEADER_LEN + payload.len();
    if len > out.len() || payload.len() > usize::from(u16::MAX) || h.flow_label > 0xf_ffff {
        return None;
    }
    out[0] = 0x60 | (h.traffic_class >> 4);
    out[1] = (h.traffic_class << 4) | u8::try_from(h.flow_label >> 16).ok()?;
    out[2..4].copy_from_slice(&u16::try_from(h.flow_label & 0xffff).ok()?.to_be_bytes());
    out[4..6].copy_from_slice(&u16::try_from(payload.len()).ok()?.to_be_bytes());
    out[6] = h.next;
    out[7] = h.hop_limit;
    out[8..24].copy_from_slice(&h.src);
    out[24..40].copy_from_slice(&h.dst);
    out[HEADER_LEN..len].copy_from_slice(payload);
    Some(len)
}
