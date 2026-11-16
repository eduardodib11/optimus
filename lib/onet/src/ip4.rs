//! IPv4 (RFC 791): checksum da Internet, cabeçalho e montagem. Opções são
//! aceitas e ignoradas na entrada e nunca geradas na saída.

use crate::arp::Ip4;

/// Tamanho do cabeçalho sem opções.
pub const HEADER_LEN: usize = 20;
/// TTL dos pacotes que o `netd` origina.
pub const DEFAULT_TTL: u8 = 64;

/// Protocolo ICMP.
pub const PROTO_ICMP: u8 = 1;
/// Protocolo TCP.
pub const PROTO_TCP: u8 = 6;
/// Protocolo UDP.
pub const PROTO_UDP: u8 = 17;

/// Soma de complemento de um (RFC 1071), sem a negação final, de `data`
/// somada a `init`.
#[must_use]
pub fn sum(data: &[u8], init: u32) -> u32 {
    let mut acc = init;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

/// Dobra a soma em 16 bits e nega: o valor do campo de checksum.
#[must_use]
pub fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !u16::try_from(acc).unwrap_or(0xffff)
}

/// Checksum da Internet de `data`.
#[must_use]
pub fn checksum(data: &[u8]) -> u16 {
    fold(sum(data, 0))
}

/// O cabeçalho IPv4 que a pilha usa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Identificação (só importa com fragmentos).
    pub id: u16,
    /// Bit "não fragmentar".
    pub dont_fragment: bool,
    /// Há mais fragmentos.
    pub more_fragments: bool,
    /// Deslocamento do fragmento, em bytes (múltiplo de 8).
    pub frag_offset: u16,
    /// Tempo de vida.
    pub ttl: u8,
    /// Protocolo da carga.
    pub proto: u8,
    /// Origem.
    pub src: Ip4,
    /// Destino.
    pub dst: Ip4,
}

impl Header {
    /// O pacote é um fragmento (não é o datagrama inteiro).
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        self.more_fragments || self.frag_offset != 0
    }
}

/// Lê um pacote IPv4: confere versão, tamanhos e checksum e devolve o
/// cabeçalho e a carga (cortada em `total_length`, o que descarta o
/// preenchimento do quadro). `None` para qualquer inconsistência.
#[must_use]
pub fn parse(p: &[u8]) -> Option<(Header, &[u8])> {
    if p.len() < HEADER_LEN || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(p[0] & 0xf) * 4;
    let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
    if ihl < HEADER_LEN || total < ihl || total > p.len() || checksum(&p[..ihl]) != 0 {
        return None;
    }
    let flags = u16::from_be_bytes([p[6], p[7]]);
    let h = Header {
        id: u16::from_be_bytes([p[4], p[5]]),
        dont_fragment: flags & 0x4000 != 0,
        more_fragments: flags & 0x2000 != 0,
        frag_offset: (flags & 0x1fff) * 8,
        ttl: p[8],
        proto: p[9],
        src: [p[12], p[13], p[14], p[15]],
        dst: [p[16], p[17], p[18], p[19]],
    };
    Some((h, &p[ihl..total]))
}

/// Monta cabeçalho (sem opções) e carga em `out`; devolve o tamanho. `None`
/// se não couber ou passar de 65535 bytes.
#[must_use]
pub fn build(h: &Header, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = HEADER_LEN + payload.len();
    if total > usize::from(u16::MAX) || total > out.len() {
        return None;
    }
    out[0] = 0x45;
    out[1] = 0;
    out[2..4].copy_from_slice(&u16::try_from(total).ok()?.to_be_bytes());
    out[4..6].copy_from_slice(&h.id.to_be_bytes());
    let mut flags = h.frag_offset / 8;
    if h.dont_fragment {
        flags |= 0x4000;
    }
    if h.more_fragments {
        flags |= 0x2000;
    }
    out[6..8].copy_from_slice(&flags.to_be_bytes());
    out[8] = h.ttl;
    out[9] = h.proto;
    out[10..12].fill(0);
    out[12..16].copy_from_slice(&h.src);
    out[16..20].copy_from_slice(&h.dst);
    let c = checksum(&out[..HEADER_LEN]);
    out[10..12].copy_from_slice(&c.to_be_bytes());
    out[HEADER_LEN..total].copy_from_slice(payload);
    Some(total)
}

/// Endereço de difusão limitada.
pub const LIMITED_BROADCAST: Ip4 = [255; 4];

/// A rede local: endereço, máscara e roteador.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Config {
    /// Endereço da interface (zero sem configuração).
    pub ip: Ip4,
    /// Máscara.
    pub mask: Ip4,
    /// Roteador padrão (zero se não há).
    pub gateway: Ip4,
}

impl Config {
    /// `a` e `b` estão na mesma rede, pela máscara.
    #[must_use]
    pub fn same_net(&self, a: Ip4, b: Ip4) -> bool {
        (0..4).all(|i| a[i] & self.mask[i] == b[i] & self.mask[i])
    }

    /// Difusão da rede local.
    #[must_use]
    pub fn broadcast(&self) -> Ip4 {
        let mut b = [0u8; 4];
        for (i, x) in b.iter_mut().enumerate() {
            *x = self.ip[i] | !self.mask[i];
        }
        b
    }

    /// Próximo salto para `dst`: o próprio destino na rede local, senão o
    /// roteador; `None` sem rota.
    #[must_use]
    pub fn next_hop(&self, dst: Ip4) -> Option<Ip4> {
        if self.ip == [0; 4] {
            return None;
        }
        if self.same_net(self.ip, dst) {
            Some(dst)
        } else if self.gateway != [0; 4] {
            Some(self.gateway)
        } else {
            None
        }
    }

    /// O destino é para esta máquina: o IP, a difusão da rede ou a limitada.
    #[must_use]
    pub fn is_local(&self, dst: Ip4) -> bool {
        dst == LIMITED_BROADCAST
            || (self.ip != [0; 4] && (dst == self.ip || dst == self.broadcast()))
    }
}
