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

/// Blocos SACK que cabem num segmento (RFC 2018: no máximo 4, ou 3 com
/// timestamps).
pub const MAX_SACK: usize = 4;

/// As opções que a pilha entende. O resto é ignorado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opts {
    /// MSS (só em SYN).
    pub mss: Option<u16>,
    /// Escala da janela (só em SYN, RFC 7323).
    pub wscale: Option<u8>,
    /// SACK permitido (só em SYN, RFC 2018).
    pub sack_ok: bool,
    /// Timestamps: (`TSval`, `TSecr`), RFC 7323.
    pub ts: Option<(u32, u32)>,
    /// Blocos SACK: início e fim (exclusivo) de cada faixa recebida.
    pub sack: [(u32, u32); MAX_SACK],
    /// Quantos blocos de `sack` valem.
    pub nsack: usize,
}

impl Opts {
    /// Nenhuma opção.
    pub const NONE: Self = Self {
        mss: None,
        wscale: None,
        sack_ok: false,
        ts: None,
        sack: [(0, 0); MAX_SACK],
        nsack: 0,
    };

    /// Os blocos SACK que valem.
    #[must_use]
    pub fn blocks(&self) -> &[(u32, u32)] {
        &self.sack[..self.nsack.min(MAX_SACK)]
    }

    /// Bytes que as opções ocupam no cabeçalho (múltiplo de 4).
    fn wire_len(&self) -> usize {
        let mut n = 0;
        if self.mss.is_some() {
            n += 4;
        }
        if self.sack_ok && self.ts.is_none() {
            n += 2;
        }
        if self.ts.is_some() {
            n += 12;
        }
        if self.wscale.is_some() {
            n += 4;
        }
        if self.nsack > 0 {
            n += 4 + 8 * self.nsack.min(MAX_SACK);
        }
        n.div_ceil(4) * 4
    }
}

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
    /// As opções.
    pub opts: Opts,
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
    let opts = parse_options(&p[HEADER_LEN..off])?;
    Some(Segment {
        sport: u16::from_be_bytes([p[0], p[1]]),
        dport: u16::from_be_bytes([p[2], p[3]]),
        seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
        flags: p[13] & 0x3f,
        window: u16::from_be_bytes([p[14], p[15]]),
        opts,
        data: &p[off..],
    })
}

/// Percorre as opções; `None` se alguma das que entendemos vier malformada.
fn parse_options(mut o: &[u8]) -> Option<Opts> {
    let mut out = Opts::NONE;
    while let Some(&kind) = o.first() {
        match kind {
            0 => break,
            1 => o = &o[1..],
            _ => {
                let len = usize::from(*o.get(1)?);
                if len < 2 || len > o.len() {
                    return None;
                }
                let v = &o[2..len];
                match kind {
                    2 => {
                        if v.len() != 2 {
                            return None;
                        }
                        out.mss = Some(u16::from_be_bytes([v[0], v[1]]));
                    }
                    3 => {
                        if v.len() != 1 {
                            return None;
                        }
                        // RFC 7323: acima de 14 vale 14.
                        out.wscale = Some(v[0].min(14));
                    }
                    4 => {
                        if !v.is_empty() {
                            return None;
                        }
                        out.sack_ok = true;
                    }
                    5 => {
                        if v.is_empty() || !v.len().is_multiple_of(8) || v.len() / 8 > MAX_SACK {
                            return None;
                        }
                        for (i, c) in v.chunks_exact(8).enumerate() {
                            out.sack[i] = (
                                u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                                u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                            );
                            out.nsack = i + 1;
                        }
                    }
                    8 => {
                        if v.len() != 8 {
                            return None;
                        }
                        out.ts = Some((
                            u32::from_be_bytes([v[0], v[1], v[2], v[3]]),
                            u32::from_be_bytes([v[4], v[5], v[6], v[7]]),
                        ));
                    }
                    _ => {}
                }
                o = &o[len..];
            }
        }
    }
    Some(out)
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
    /// Opções a anunciar.
    pub opts: Opts,
}

/// Monta o segmento em `out`; devolve o tamanho. `None` se não couber.
#[must_use]
pub fn build(src: Ip4, dst: Ip4, h: &Header, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let olen = h.opts.wire_len();
    let off = HEADER_LEN + olen;
    let len = off + data.len();
    if olen > 40 || len > out.len() || len > usize::from(u16::MAX) {
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
    let o = &mut out[HEADER_LEN..off];
    o.fill(1);
    let mut n = 0;
    let mut put = |b: &[u8]| {
        o[n..n + b.len()].copy_from_slice(b);
        n += b.len();
    };
    if let Some(m) = h.opts.mss {
        put(&[2, 4]);
        put(&m.to_be_bytes());
    }
    match (h.opts.sack_ok, h.opts.ts) {
        (true, Some((v, e))) => {
            put(&[4, 2, 8, 10]);
            put(&v.to_be_bytes());
            put(&e.to_be_bytes());
        }
        (false, Some((v, e))) => {
            put(&[1, 1, 8, 10]);
            put(&v.to_be_bytes());
            put(&e.to_be_bytes());
        }
        (true, None) => put(&[4, 2]),
        (false, None) => {}
    }
    if let Some(w) = h.opts.wscale {
        put(&[1, 3, 3, w]);
    }
    let nsack = h.opts.nsack.min(MAX_SACK);
    if nsack > 0 {
        put(&[1, 1, 5, u8::try_from(2 + 8 * nsack).ok()?]);
        for &(a, b) in &h.opts.sack[..nsack] {
            put(&a.to_be_bytes());
            put(&b.to_be_bytes());
        }
    }
    out[off..len].copy_from_slice(data);
    let c = ip4::fold(ip4::sum(&out[..len], pseudo_sum(src, dst, PROTO_TCP, len)));
    out[16..18].copy_from_slice(&c.to_be_bytes());
    Some(len)
}
