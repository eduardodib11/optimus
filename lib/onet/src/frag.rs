//! Remontagem de fragmentos IPv4 limitada (ADR 0069, item 4): poucos
//! datagramas em andamento, poucos fragmentos cada um, tamanho máximo
//! pequeno e prazo curto. Fragmento que se sobrepõe a outro derruba o
//! datagrama todo (RFC 5722 e a prática do Linux contra evasão de filtros).
//! Datagrama novo com todas as vagas ocupadas é recusado, e não despeja os
//! que estão em andamento: um atacante não expulsa os legítimos.

use alloc::boxed::Box;

use crate::ip4::Header;

/// Datagramas em remontagem ao mesmo tempo.
pub const SLOTS: usize = 4;
/// Fragmentos por datagrama.
pub const MAX_FRAGS: usize = 8;
/// Maior datagrama remontado, em bytes de carga.
pub const MAX_DATAGRAM: usize = 2048;
/// Prazo de um datagrama incompleto (ns).
pub const TIMEOUT_NS: u64 = 15_000_000_000;

struct Slot {
    used: bool,
    src: [u8; 4],
    dst: [u8; 4],
    id: u16,
    proto: u8,
    deadline: u64,
    /// Fragmentos recebidos: (início, fim) em bytes.
    ranges: [(u16, u16); MAX_FRAGS],
    count: usize,
    /// Tamanho total, conhecido ao chegar o último fragmento.
    total: Option<usize>,
    /// Alocado no primeiro uso: um `Slot` por valor na pilha de 64 KiB de um
    /// processo em depuração estoura.
    buf: Option<Box<[u8; MAX_DATAGRAM]>>,
}

impl Slot {
    const EMPTY: Slot = Slot {
        used: false,
        src: [0; 4],
        dst: [0; 4],
        id: 0,
        proto: 0,
        deadline: 0,
        ranges: [(0, 0); MAX_FRAGS],
        count: 0,
        total: None,
        buf: None,
    };

    fn matches(&self, h: &Header) -> bool {
        self.used
            && self.src == h.src
            && self.dst == h.dst
            && self.id == h.id
            && self.proto == h.proto
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

    /// Recebe um fragmento (`h.is_fragment()`). Quando o datagrama fica
    /// completo, copia a carga para `out` e devolve o cabeçalho sem as marcas
    /// de fragmento e o tamanho. `out` precisa ter [`MAX_DATAGRAM`] bytes.
    pub fn add(
        &mut self,
        h: &Header,
        payload: &[u8],
        now: u64,
        out: &mut [u8],
    ) -> Option<(Header, usize)> {
        self.expire(now);
        let start = usize::from(h.frag_offset);
        let end = start.checked_add(payload.len())?;
        // Fragmento que não é o último precisa de múltiplo de 8 bytes.
        if payload.is_empty()
            || end > MAX_DATAGRAM
            || (h.more_fragments && !payload.len().is_multiple_of(8))
        {
            return None;
        }
        let i = if let Some(i) = self.slots.iter().position(|s| s.matches(h)) {
            i
        } else {
            let i = self.slots.iter().position(|s| !s.used)?;
            let s = &mut self.slots[i];
            s.used = true;
            s.src = h.src;
            s.dst = h.dst;
            s.id = h.id;
            s.proto = h.proto;
            s.deadline = now.saturating_add(TIMEOUT_NS);
            s.count = 0;
            s.total = None;
            i
        };
        let s = &mut self.slots[i];
        let (a, b) = (u16::try_from(start).ok()?, u16::try_from(end).ok()?);
        let overlap = s.ranges[..s.count].iter().any(|&(x, y)| a < y && x < b);
        let bad_end = if h.more_fragments {
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
        let buf = s.buf.get_or_insert_with(|| Box::new([0; MAX_DATAGRAM]));
        buf[start..end].copy_from_slice(payload);
        if !h.more_fragments {
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
        out[..total].copy_from_slice(&buf[..total]);
        s.used = false;
        let mut done = *h;
        done.more_fragments = false;
        done.frag_offset = 0;
        Some((done, total))
    }
}
