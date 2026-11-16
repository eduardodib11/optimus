//! Segmento TCP (RFC 9293): cabeçalho, opções e checksum.

use crate::arp::Ip4;
use crate::ip4::{self, PROTO_TCP};
use crate::udp::pseudo_sum;

/// Cabeçalho sem opções.
pub const HEADER_LEN: usize = 20;

/// Flags.
pub const FIN: u8 = 0x01;
/// Abertura.
pub const SYN: u8 = 0x02;
/// Reinício.
pub const RST: u8 = 0x04;
/// Entrega já (sem efeito no receptor).
pub const PSH: u8 = 0x08;
/// O campo de confirmação vale.
pub const ACK: u8 = 0x10;

/// Um segmento lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    /// Porta de origem.
    pub sport: u16,
    /// Porta de destino.
    pub dport: u16,
    /// Número de sequência.
    pub seq: u32,
    /// Número de confirmação.
    pub ack: u32,
    /// Flags.
    pub flags: u8,
    /// Janela anunciada (sem escala).
    pub window: u16,
    /// MSS da opção, se veio.
    pub mss: Option<u16>,
    /// Dados.
    pub data: &'a [u8],
}

impl Segment<'_> {
    /// Quanto o segmento ocupa no espaço de sequência (dados, SYN e FIN).
    #[must_use]
    pub fn seq_len(&self) -> u32 {
        u32::try_from(self.data.len()).unwrap_or(u32::MAX)
            + u32::from(self.flags & SYN != 0)
            + u32::from(self.flags & FIN != 0)
    }
}

/// Lê um segmento de `p` (a carga do IP). Confere o deslocamento de dados, as
/// opções e o checksum; `None` para qualquer inconsistência.
#[must_use]
pub fn parse(src: Ip4, dst: Ip4, p: &[u8]) -> Option<Segment<'_>> {
    if p.len() < HEADER_LEN {
        return None;
    }
    let off = usize::from(p[12] >> 4) * 4;
    if off < HEADER_LEN || off > p.len() {
        return None;
    }
    if ip4::fold(ip4::sum(p, pseudo_sum(src, dst, PROTO_TCP, p.len()))) != 0 {
        return None;
    }
    let mss = parse_options(&p[HEADER_LEN..off])?;
    Some(Segment {
        sport: u16::from_be_bytes([p[0], p[1]]),
        dport: u16::from_be_bytes([p[2], p[3]]),
        seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
        flags: p[13] & 0x3f,
        window: u16::from_be_bytes([p[14], p[15]]),
        mss,
        data: &p[off..],
    })
}

/// Percorre as opções; devolve o MSS (se houver) ou `None` se malformadas.
#[allow(
    clippy::option_option,
    reason = "malformada, sem MSS e com MSS são três casos"
)]
fn parse_options(mut o: &[u8]) -> Option<Option<u16>> {
    let mut mss = None;
    while let Some(&kind) = o.first() {
        match kind {
            0 => break,
            1 => o = &o[1..],
            _ => {
                let len = usize::from(*o.get(1)?);
                if len < 2 || len > o.len() {
                    return None;
                }
                if kind == 2 {
                    if len != 4 {
                        return None;
                    }
                    mss = Some(u16::from_be_bytes([o[2], o[3]]));
                }
                o = &o[len..];
            }
        }
    }
    Some(mss)
}

/// O que montar.
#[derive(Clone, Copy, Debug)]
pub struct Header {
    /// Porta de origem.
    pub sport: u16,
    /// Porta de destino.
    pub dport: u16,
    /// Sequência.
    pub seq: u32,
    /// Confirmação.
    pub ack: u32,
    /// Flags.
    pub flags: u8,
    /// Janela.
    pub window: u16,
    /// MSS a anunciar (só em SYN).
    pub mss: Option<u16>,
}

/// Monta o segmento em `out`; devolve o tamanho. `None` se não couber.
#[must_use]
pub fn build(src: Ip4, dst: Ip4, h: &Header, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let off = if h.mss.is_some() {
        HEADER_LEN + 4
    } else {
        HEADER_LEN
    };
    let len = off + data.len();
    if len > out.len() || len > usize::from(u16::MAX) {
        return None;
    }
    out[0..2].copy_from_slice(&h.sport.to_be_bytes());
    out[2..4].copy_from_slice(&h.dport.to_be_bytes());
    out[4..8].copy_from_slice(&h.seq.to_be_bytes());
    out[8..12].copy_from_slice(&h.ack.to_be_bytes());
    out[12] = u8::try_from(off / 4).ok()? << 4;
    out[13] = h.flags;
    out[14..16].copy_from_slice(&h.window.to_be_bytes());
    out[16..20].fill(0);
    if let Some(m) = h.mss {
        out[20..22].copy_from_slice(&[2, 4]);
        out[22..24].copy_from_slice(&m.to_be_bytes());
    }
    out[off..len].copy_from_slice(data);
    let c = ip4::fold(ip4::sum(&out[..len], pseudo_sum(src, dst, PROTO_TCP, len)));
    out[16..18].copy_from_slice(&c.to_be_bytes());
    Some(len)
}
