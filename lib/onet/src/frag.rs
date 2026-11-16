//! Remontagem de fragmentos IPv4 e IPv6 limitada (ADR 0069, item 4): poucos
//! datagramas em andamento, poucos fragmentos cada um, tamanho máximo
//! pequeno e prazo curto. Fragmento que se sobrepõe a outro derruba o
//! datagrama todo (RFC 5722 e a prática do Linux contra evasão de filtros).
//! Datagrama novo com todas as vagas ocupadas é recusado, e não despeja os
//! que estão em andamento: um atacante não expulsa os legítimos.

use crate::ip4::Header;

/// Datagramas em remontagem ao mesmo tempo.
pub const SLOTS: usize = 4;
/// Fragmentos por datagrama.
pub const MAX_FRAGS: usize = 8;
/// Maior datagrama remontado, em bytes de carga.
pub const MAX_DATAGRAM: usize = 2048;
/// Prazo de um datagrama incompleto (ns).
pub const TIMEOUT_NS: u64 = 15_000_000_000;

/// Quem identifica um datagrama em remontagem (RFC 791 e RFC 8200): origem,
/// destino, identificação e protocolo, no IPv4 ou no IPv6.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Key {
    /// Endereços de 16 bytes (os do IPv4 vão nos 4 primeiros, o resto zero).
    pub src: [u8; 16],
    /// Destino.
    pub dst: [u8; 16],
    /// Identificação (16 bits no IPv4, 32 no IPv6).
    pub id: u32,
    /// Protocolo da carga.
    pub proto: u8,
    /// É IPv6.
    pub v6: bool,
}

/// Fragmento: posição, tamanho e marca de "há mais".
#[derive(Clone, Copy)]
pub struct Piece {
    /// Início em bytes.
    pub offset: usize,
    /// Há mais fragmentos depois deste.
    pub more: bool,
}

struct Slot {
    used: bool,
    key: Key,
    deadline: u64,
    /// Fragmentos recebidos: (início, fim) em bytes.
    ranges: [(u16, u16); MAX_FRAGS],
    count: usize,
    /// Tamanho total, conhecido ao chegar o último fragmento.
    total: Option<usize>,
    buf: [u8; MAX_DATAGRAM],
}

impl Slot {
    const EMPTY: Slot = Slot {
        used: false,
        key: Key {
            src: [0; 16],
            dst: [0; 16],
            id: 0,
            proto: 0,
            v6: false,
        },
        deadline: 0,
        ranges: [(0, 0); MAX_FRAGS],
        count: 0,
        total: None,
        buf: [0; MAX_DATAGRAM],
    };

    fn matches(&self, k: &Key) -> bool {
        self.used && self.key == *k
    }
}

/// A remontagem.
pub struct Reassembler {
    slots: [Slot; SLOTS],
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Reassembler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let used = self.slots.iter().filter(|s| s.used).count();
        f.debug_struct("Reassembler")
            .field("em_andamento", &used)
            .finish()
    }
}

impl Reassembler {
    /// Remontagem vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; SLOTS],
        }
    }

    /// Datagramas em andamento.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.slots.iter().filter(|s| s.used).count()
    }

    /// Descarta o que passou do prazo.
    pub fn expire(&mut self, now: u64) {
        for s in &mut self.slots {
            if s.used && now >= s.deadline {
                s.used = false;
            }
        }
    }

    /// Recebe um fragmento IPv4 (`h.is_fragment()`). Quando o datagrama fica
    /// completo, copia a carga para `out` e devolve o cabeçalho sem as marcas
    /// de fragmento e o tamanho. `out` precisa ter [`MAX_DATAGRAM`] bytes.
    pub fn add(
        &mut self,
        h: &Header,
        payload: &[u8],
        now: u64,
        out: &mut [u8],
    ) -> Option<(Header, usize)> {
        let mut key = Key {
            src: [0; 16],
            dst: [0; 16],
            id: u32::from(h.id),
            proto: h.proto,
            v6: false,
        };
        key.src[..4].copy_from_slice(&h.src);
        key.dst[..4].copy_from_slice(&h.dst);
        let piece = Piece {
            offset: usize::from(h.frag_offset),
            more: h.more_fragments,
        };
        let n = self.add_piece(&key, piece, payload, now, out)?;
        let mut done = *h;
        done.more_fragments = false;
        done.frag_offset = 0;
        Some((done, n))
    }

    /// Recebe um fragmento de qualquer versão; devolve o tamanho da carga
    /// remontada (em `out`) quando completa.
    pub fn add_piece(
        &mut self,
        key: &Key,
        p: Piece,
        payload: &[u8],
        now: u64,
        out: &mut [u8],
    ) -> Option<usize> {
        self.expire(now);
        let start = p.offset;
        let end = start.checked_add(payload.len())?;
        // Fragmento que não é o último precisa de múltiplo de 8 bytes.
        if payload.is_empty() || end > MAX_DATAGRAM || (p.more && !payload.len().is_multiple_of(8))
        {
            return None;
        }
        let i = if let Some(i) = self.slots.iter().position(|s| s.matches(key)) {
            i
        } else {
            let i = self.slots.iter().position(|s| !s.used)?;
            let s = &mut self.slots[i];
            s.used = true;
            s.key = *key;
            s.deadline = now.saturating_add(TIMEOUT_NS);
            s.count = 0;
            s.total = None;
            i
        };
        let s = &mut self.slots[i];
        let (a, b) = (u16::try_from(start).ok()?, u16::try_from(end).ok()?);
        let overlap = s.ranges[..s.count].iter().any(|&(x, y)| a < y && x < b);
        let bad_end = if p.more {
            s.total.is_some_and(|t| end > t)
        } else {
            s.total.is_some()
                || s.ranges[..s.count]
                    .iter()
                    .any(|&(_, y)| usize::from(y) > end)
        };
        if overlap || bad_end || s.count == MAX_FRAGS {
            s.used = false;
            return None;
        }
        s.ranges[s.count] = (a, b);
        s.count += 1;
        s.buf[start..end].copy_from_slice(payload);
        if !p.more {
            s.total = Some(end);
        }
        let total = s.total?;
        let have: usize = s.ranges[..s.count]
            .iter()
            .map(|&(x, y)| usize::from(y - x))
            .sum();
        if have != total || out.len() < total {
            return None;
        }
        out[..total].copy_from_slice(&s.buf[..total]);
        s.used = false;
        Some(total)
    }
}
