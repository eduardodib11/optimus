//! Handles que a thread principal tem, com o tipo, o pai na árvore de
//! derivação e marcas de proteção. O pool é exato: todo handle válido do
//! `CapSpace` que a principal conhece está aqui, e só ele; isso serve de
//! oráculo depois de `cap_delete` e `cap_revoke`.

use crate::rng::Rng;

/// Não pode ser apagado (cota raiz, o próprio espaço, objetos da auxiliar).
pub const PRECIOUS: u8 = 1;
/// Talvez seja o próprio `AddressSpace`: `vm_*` respeitam as faixas protegidas.
pub const SELF_AS: u8 = 2;

/// Tipo desconhecido.
pub const UNKNOWN: u8 = 0xff;

/// Um handle conhecido.
#[derive(Clone, Copy, Debug, Default)]
pub struct Entry {
    /// Handle cru.
    pub raw: u32,
    /// `ObjectType` cru (ou [`UNKNOWN`]).
    pub ty: u8,
    /// Pai na árvore de derivação (0: raiz).
    pub parent: u32,
    /// Marcas.
    pub flags: u8,
}

/// Capacidade do pool.
pub const CAP: usize = 192;
const STALE: usize = 16;

/// Os handles conhecidos e os apagados há pouco.
pub struct Pool {
    entries: [Entry; CAP],
    len: usize,
    stale: [u32; STALE],
    stale_at: usize,
}

impl Pool {
    /// Pool vazio.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [Entry {
                raw: 0,
                ty: 0,
                parent: 0,
                flags: 0,
            }; CAP],
            len: 0,
            stale: [0; STALE],
            stale_at: 0,
        }
    }

    /// Handles conhecidos.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries[..self.len]
    }

    /// Verdadeiro sem espaço para mais um.
    #[must_use]
    pub const fn full(&self) -> bool {
        self.len == CAP
    }

    /// Acrescenta `e`; falso se cheio.
    pub fn add(&mut self, e: Entry) -> bool {
        if self.full() {
            return false;
        }
        self.entries[self.len] = e;
        self.len += 1;
        true
    }

    /// O handle de valor `raw` (só `u32`), se conhecido.
    #[must_use]
    pub fn find(&self, raw: u64) -> Option<Entry> {
        let raw = u32::try_from(raw).ok()?;
        self.entries().iter().copied().find(|e| e.raw == raw)
    }

    /// Marcas de `raw` (zero se desconhecido).
    #[must_use]
    pub fn flags(&self, raw: u64) -> u8 {
        self.find(raw).map_or(0, |e| e.flags)
    }

    /// Tira `raw` como `cap_delete` faz: os filhos sobem para o pai dele.
    pub fn remove(&mut self, raw: u32) {
        let Some(i) = self.entries().iter().position(|e| e.raw == raw) else {
            return;
        };
        let parent = self.entries[i].parent;
        self.len -= 1;
        self.entries[i] = self.entries[self.len];
        for e in &mut self.entries[..self.len] {
            if e.parent == raw {
                e.parent = parent;
            }
        }
        self.stale[self.stale_at % STALE] = raw;
        self.stale_at += 1;
    }

    /// Verdadeiro se `raw` descende de `root` (sem contar ele mesmo).
    #[must_use]
    pub fn descends(&self, raw: u32, root: u32) -> bool {
        let mut at = self.find(u64::from(raw)).map_or(0, |e| e.parent);
        for _ in 0..=CAP {
            if at == 0 {
                return false;
            }
            if at == root {
                return true;
            }
            at = self.find(u64::from(at)).map_or(0, |e| e.parent);
        }
        false
    }

    /// Um handle qualquer do pool (0 se vazio).
    pub fn any(&self, rng: &mut Rng) -> u32 {
        if self.len == 0 {
            return 0;
        }
        self.entries[usize::try_from(rng.below(self.len as u64)).unwrap_or(0)].raw
    }

    /// Um handle do pool de tipo `ty`, se houver.
    pub fn of_type(&self, rng: &mut Rng, ty: u8) -> Option<u32> {
        let n = self.entries().iter().filter(|e| e.ty == ty).count();
        if n == 0 {
            return None;
        }
        let k = usize::try_from(rng.below(n as u64)).unwrap_or(0);
        self.entries()
            .iter()
            .filter(|e| e.ty == ty)
            .nth(k)
            .map(|e| e.raw)
    }

    /// Um handle apagado há pouco (0 se nenhum).
    pub fn stale(&self, rng: &mut Rng) -> u32 {
        self.stale[usize::try_from(rng.below(STALE as u64)).unwrap_or(0)]
    }
}
