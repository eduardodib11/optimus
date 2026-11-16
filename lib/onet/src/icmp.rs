//! `ICMPv4` (RFC 792): eco e o que a pilha precisa reconhecer.

use crate::ip4;

/// Tamanho do cabeçalho do eco.
pub const ECHO_HEADER: usize = 8;

/// Tipo: resposta de eco.
pub const ECHO_REPLY: u8 = 0;
/// Tipo: destino inalcançável.
pub const DEST_UNREACHABLE: u8 = 3;
/// Tipo: pedido de eco.
pub const ECHO_REQUEST: u8 = 8;

/// Uma mensagem de eco (pedido ou resposta).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo<'a> {
    /// `ECHO_REQUEST` ou `ECHO_REPLY`.
    pub kind: u8,
    /// Identificador.
    pub id: u16,
    /// Número de sequência.
    pub seq: u16,
    /// Dados.
    pub data: &'a [u8],
}

/// Lê uma mensagem de eco; `None` se o checksum não bate, se é curta ou se
/// é de outro tipo.
#[must_use]
pub fn parse_echo(p: &[u8]) -> Option<Echo<'_>> {
    if p.len() < ECHO_HEADER || ip4::checksum(p) != 0 {
        return None;
    }
    let kind = p[0];
    if (kind != ECHO_REQUEST && kind != ECHO_REPLY) || p[1] != 0 {
        return None;
    }
    Some(Echo {
        kind,
        id: u16::from_be_bytes([p[4], p[5]]),
        seq: u16::from_be_bytes([p[6], p[7]]),
        data: &p[ECHO_HEADER..],
    })
}

/// Monta a mensagem de eco em `out`; devolve o tamanho ou `None` se não couber.
#[must_use]
pub fn build_echo(e: &Echo<'_>, out: &mut [u8]) -> Option<usize> {
    let n = ECHO_HEADER + e.data.len();
    if n > out.len() {
        return None;
    }
    out[0] = e.kind;
    out[1] = 0;
    out[2..4].fill(0);
    out[4..6].copy_from_slice(&e.id.to_be_bytes());
    out[6..8].copy_from_slice(&e.seq.to_be_bytes());
    out[ECHO_HEADER..n].copy_from_slice(e.data);
    let c = ip4::checksum(&out[..n]);
    out[2..4].copy_from_slice(&c.to_be_bytes());
    Some(n)
}
