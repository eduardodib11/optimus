//! Quadros Ethernet II (sem VLAN: o 802.1Q fica para o perfil Server, ADR 0069).

/// Bytes do cabeçalho Ethernet.
pub const HEADER_LEN: usize = 14;
/// Maior quadro que o `NetDevice` aceita (ADR 0064): cabeçalho mais MTU 1500.
pub const MAX_FRAME: usize = 1514;
/// MTU de carga do enlace.
pub const MTU: usize = 1500;

/// `EtherType` do IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// `EtherType` do ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// `EtherType` do IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Endereço MAC de 48 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Difusão (`ff:ff:ff:ff:ff:ff`).
    pub const BROADCAST: Mac = Mac([0xff; 6]);

    /// MAC a partir do `u64` do `NetInfo` (48 bits baixos, primeiro byte
    /// do endereço no mais baixo; ADR 0064).
    #[must_use]
    pub const fn from_u64(raw: u64) -> Mac {
        let b = raw.to_le_bytes();
        Mac([b[0], b[1], b[2], b[3], b[4], b[5]])
    }

    /// Endereço de grupo (difusão ou multicast): bit 0 do primeiro byte.
    #[must_use]
    pub const fn is_group(&self) -> bool {
        self.0[0] & 1 != 0
    }
}

/// O cabeçalho de um quadro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// Destino.
    pub dst: Mac,
    /// Origem.
    pub src: Mac,
    /// `EtherType`.
    pub ethertype: u16,
}

/// Separa o cabeçalho da carga; `None` se o quadro for curto demais ou
/// maior que [`MAX_FRAME`].
#[must_use]
pub fn parse(frame: &[u8]) -> Option<(Header, &[u8])> {
    if frame.len() < HEADER_LEN || frame.len() > MAX_FRAME {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    Some((
        Header {
            dst: Mac(dst),
            src: Mac(src),
            ethertype,
        },
        &frame[HEADER_LEN..],
    ))
}

/// Monta um quadro em `out` e devolve o tamanho; `None` se não couber ou se
/// passar de [`MAX_FRAME`].
#[must_use]
pub fn build(h: &Header, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let len = HEADER_LEN + payload.len();
    if len > MAX_FRAME || len > out.len() {
        return None;
    }
    out[0..6].copy_from_slice(&h.dst.0);
    out[6..12].copy_from_slice(&h.src.0);
    out[12..14].copy_from_slice(&h.ethertype.to_be_bytes());
    out[HEADER_LEN..len].copy_from_slice(payload);
    Some(len)
}

/// O quadro é para esta interface: nosso MAC, difusão ou o multicast do
/// IPv6 (`33:33:...`, RFC 2464). Quais grupos a interface escuta é decisão
/// da camada IPv6.
#[must_use]
pub fn for_us(h: &Header, ours: Mac) -> bool {
    h.dst == ours || h.dst == Mac::BROADCAST || h.dst.0[..2] == [0x33, 0x33]
}
