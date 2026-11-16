//! UDP (RFC 768): cabeçalho, checksum com pseudo-cabeçalho e montagem.

use crate::arp::Ip4;
use crate::ip4::{self, PROTO_UDP};

/// Tamanho do cabeçalho.
pub const HEADER_LEN: usize = 8;

/// Um datagrama lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Datagram<'a> {
    /// Porta de origem.
    pub sport: u16,
    /// Porta de destino.
    pub dport: u16,
    /// Dados.
    pub data: &'a [u8],
}

/// Soma do pseudo-cabeçalho (RFC 768) de um segmento de `len` bytes.
#[must_use]
pub fn pseudo_sum(src: Ip4, dst: Ip4, proto: u8, len: usize) -> u32 {
    let mut acc = ip4::sum(&src, 0);
    acc = ip4::sum(&dst, acc);
    acc += u32::from(proto);
    acc + u32::try_from(len).unwrap_or(0xffff)
}

/// Lê um datagrama de `p` (a carga do IP). Confere o comprimento do
/// cabeçalho UDP contra o recebido (o excesso, como preenchimento, é
/// cortado) e o checksum quando presente. `None` para qualquer
/// inconsistência.
#[must_use]
pub fn parse(src: Ip4, dst: Ip4, p: &[u8]) -> Option<Datagram<'_>> {
    if p.len() < HEADER_LEN {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([p[4], p[5]]));
    if len < HEADER_LEN || len > p.len() {
        return None;
    }
    let p = &p[..len];
    // Checksum zero quer dizer "sem checksum", permitido no IPv4.
    if p[6..8] != [0, 0] && ip4::fold(ip4::sum(p, pseudo_sum(src, dst, PROTO_UDP, len))) != 0 {
        return None;
    }
    Some(Datagram {
        sport: u16::from_be_bytes([p[0], p[1]]),
        dport: u16::from_be_bytes([p[2], p[3]]),
        data: &p[HEADER_LEN..],
    })
}

/// Monta o datagrama em `out`; devolve o tamanho. `None` se não couber.
#[must_use]
pub fn build(
    src: Ip4,
    dst: Ip4,
    sport: u16,
    dport: u16,
    data: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let len = HEADER_LEN + data.len();
    if len > out.len() || len > usize::from(u16::MAX) {
        return None;
    }
    out[0..2].copy_from_slice(&sport.to_be_bytes());
    out[2..4].copy_from_slice(&dport.to_be_bytes());
    out[4..6].copy_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
    out[6..8].fill(0);
    out[HEADER_LEN..len].copy_from_slice(data);
    let mut c = ip4::fold(ip4::sum(&out[..len], pseudo_sum(src, dst, PROTO_UDP, len)));
    // O zero calculado vira todos os bits em um (RFC 768).
    if c == 0 {
        c = 0xffff;
    }
    out[6..8].copy_from_slice(&c.to_be_bytes());
    Some(len)
}
