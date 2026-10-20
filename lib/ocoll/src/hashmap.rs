//! `HashMap` e `HashSet` com endereçamento aberto (*Robin Hood*, sondagem
//! linear, remoção por deslocamento para trás: sem lápides).
//!
//! A tabela é um `Vec<Option<Bucket>>` de potência de dois; cresce ao passar
//! de 3/4 de carga. A ordem de iteração depende do hasher e não é estável.

#![allow(clippy::cast_possible_truncation)] // hash `u64` mascarado para índice

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::iter::FusedIterator;
use core::mem;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use crate::prng::mix64;
use crate::siphash::SipHasher13;

// ---- RandomState ----

static SEED0: AtomicU64 = AtomicU64::new(0x243F_6A88_85A3_08D3);
static SEED1: AtomicU64 = AtomicU64::new(0x1319_8A2E_0370_7344);
static SEEDED: AtomicBool = AtomicBool::new(false);
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Dá a semente do processo aos [`RandomState`] (128 bits). O `ostd` a chama
/// em `rt::init`, com bytes do kernel (`ostd::rand`). Cada
/// [`RandomState::new`] deriva dela, mais um contador, uma chave própria.
///
/// Sem esta chamada a semente é uma constante: o comportamento é
/// determinista e [`is_seeded`] dá `false`.
pub fn seed_random_state(seed: [u64; 2]) {
    SEED0.store(seed[0], Relaxed);
    SEED1.store(seed[1], Relaxed);
    SEEDED.store(true, Relaxed);
}

/// A semente do processo já foi dada por [`seed_random_state`]?
#[must_use]
pub fn is_seeded() -> bool {
    SEEDED.load(Relaxed)
}

/// Constrói [`SipHasher13`] com a chave de 128 bits do mapa.
#[derive(Clone, Debug)]
pub struct RandomState {
    k0: u64,
    k1: u64,
}

impl RandomState {
    /// Estado com chave nova, derivada da semente do processo e de um
    /// contador (duas chamadas nunca dão a mesma chave).
    #[must_use]
    pub fn new() -> Self {
        let n = COUNTER.fetch_add(1, Relaxed);
        let (s0, s1) = (SEED0.load(Relaxed), SEED1.load(Relaxed));
        // `mix64` é uma bijeção: contadores distintos dão chaves distintas.
        Self {
            k0: mix64(s0 ^ mix64(n.wrapping_mul(2))),
            k1: mix64(s1 ^ mix64(n.wrapping_mul(2).wrapping_add(1))),
        }
    }

    /// Estado com a chave dada (testes e mapas reproduzíveis).
    #[must_use]
    pub const fn with_keys(k0: u64, k1: u64) -> Self {
        Self { k0, k1 }
    }

    /// A chave `(k0, k1)`.
    #[must_use]
    pub const fn keys(&self) -> (u64, u64) {
        (self.k0, self.k1)
    }
}

impl Default for RandomState {
    fn default() -> Self {
        Self::new()
    }
}

impl BuildHasher for RandomState {
    type Hasher = SipHasher13;

    fn build_hasher(&self) -> SipHasher13 {
        SipHasher13::new_with_keys(self.k0, self.k1)
    }
}

// ---- HashMap ----

struct Bucket<K, V> {
    hash: u64,
    key: K,
    value: V,
}

/// Mapa hash. Com o `S` padrão, SipHash-1-3 e chave aleatória por mapa.
pub struct HashMap<K, V, S = RandomState> {
    slots: Vec<Option<Bucket<K, V>>>,
    len: usize,
    hasher: S,
}

const MIN_SLOTS: usize = 8;

impl<K, V> HashMap<K, V, RandomState> {
    /// Mapa vazio com uma chave nova ([`RandomState::new`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_hasher(RandomState::new())
    }

    /// Mapa com espaço para `n` entradas sem crescer.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self::with_capacity_and_hasher(n, RandomState::new())
    }
}

impl<K, V, S: Default> Default for HashMap<K, V, S> {
    fn default() -> Self {
        Self::with_hasher(S::default())
    }
}

impl<K, V, S> HashMap<K, V, S> {
    /// Mapa vazio com o hasher dado.
    #[must_use]
    pub const fn with_hasher(hasher: S) -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
            hasher,
        }
    }

    /// Mapa com espaço para `n` entradas e o hasher dado.
    #[must_use]
    pub fn with_capacity_and_hasher(n: usize, hasher: S) -> Self {
        let mut map = Self::with_hasher(hasher);
        if n > 0 {
            map.slots = empty_slots(slots_for(n));
        }
        map
    }

    /// Quantas entradas.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Sem entradas?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Entradas que cabem sem crescer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.slots.len() / 4 * 3
    }

    /// Apaga tudo, mantendo a memória.
    pub fn clear(&mut self) {
        for s in &mut self.slots {
            *s = None;
        }
        self.len = 0;
    }

    /// Entradas `(&chave, &valor)`, em ordem sem garantia.
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            inner: self.slots.iter(),
            left: self.len,
        }
    }

    /// Entradas `(&chave, &mut valor)`.
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        IterMut {
            inner: self.slots.iter_mut(),
            left: self.len,
        }
    }

    /// Chaves.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(k, _)| k)
    }

    /// Valores.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }

    /// O hasher.
    #[must_use]
    pub fn hasher(&self) -> &S {
        &self.hasher
    }
}

fn empty_slots<K, V>(n: usize) -> Vec<Option<Bucket<K, V>>> {
    let mut v = Vec::with_capacity(n);
    v.resize_with(n, || None);
    v
}

/// Tamanho da tabela (potência de dois) que guarda `n` entradas a 3/4.
fn slots_for(n: usize) -> usize {
    let need = n.saturating_mul(4).div_ceil(3).max(MIN_SLOTS);
    need.next_power_of_two()
}

impl<K: Eq + Hash, V, S: BuildHasher> HashMap<K, V, S> {
    fn hash_of<Q: Hash + ?Sized>(&self, key: &Q) -> u64 {
        self.hasher.hash_one(key)
    }

    /// Distância de `index` ao lugar ideal do hash.
    fn dist(&self, hash: u64, index: usize) -> usize {
        let mask = self.slots.len() - 1;
        index.wrapping_sub(hash as usize & mask) & mask
    }

    fn find<Q>(&self, hash: u64, key: &Q) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut index = hash as usize & mask;
        let mut dist = 0;
        loop {
            let e = self.slots[index].as_ref()?;
            if e.hash == hash && e.key.borrow() == key {
                return Some(index);
            }
            // Robin Hood: se o ocupante está mais perto do lugar ideal do
            // que nós, a chave não pode estar mais adiante.
            if self.dist(e.hash, index) < dist {
                return None;
            }
            index = (index + 1) & mask;
            dist += 1;
        }
    }

    /// Põe `bucket` (chave ainda ausente) na tabela, que tem espaço.
    /// Devolve onde o próprio `bucket` ficou (os deslocados vão adiante).
    fn place(&mut self, mut bucket: Bucket<K, V>) -> usize {
        let mask = self.slots.len() - 1;
        let mut index = bucket.hash as usize & mask;
        let mut dist = 0;
        let mut landed = None;
        loop {
            let ideal_dist = match &self.slots[index] {
                None => {
                    self.slots[index] = Some(bucket);
                    self.len += 1;
                    return landed.unwrap_or(index);
                }
                Some(e) => self.dist(e.hash, index),
            };
            if ideal_dist < dist {
                // Rouba o lugar de quem está mais perto de casa.
                if let Some(e) = self.slots[index].as_mut() {
                    mem::swap(e, &mut bucket);
                }
                landed.get_or_insert(index);
                dist = ideal_dist;
            }
            index = (index + 1) & mask;
            dist += 1;
        }
    }

    fn grow_for_one_more(&mut self) {
        if self.slots.is_empty() {
            self.slots = empty_slots(MIN_SLOTS);
        } else if (self.len + 1) * 4 > self.slots.len() * 3 {
            let bigger = empty_slots(self.slots.len() * 2);
            let old = mem::replace(&mut self.slots, bigger);
            self.len = 0;
            for bucket in old.into_iter().flatten() {
                self.place(bucket);
            }
        }
    }

    /// Garante espaço para mais `extra` entradas sem crescer de novo.
    pub fn reserve(&mut self, extra: usize) {
        let want = slots_for(self.len.saturating_add(extra));
        if want > self.slots.len() {
            let old = mem::replace(&mut self.slots, empty_slots(want));
            self.len = 0;
            for bucket in old.into_iter().flatten() {
                self.place(bucket);
            }
        }
    }

    /// Insere; devolve o valor antigo se a chave já existia (a chave antiga
    /// fica).
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let hash = self.hash_of(&key);
        if let Some(i) = self.find(hash, &key) {
            let e = self.slots[i].as_mut()?;
            return Some(mem::replace(&mut e.value, value));
        }
        self.grow_for_one_more();
        self.place(Bucket { hash, key, value });
        None
    }

    /// O valor da chave.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let i = self.find(self.hash_of(key), key)?;
        self.slots[i].as_ref().map(|e| &e.value)
    }

    /// A entrada `(chave, valor)` da chave.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let i = self.find(self.hash_of(key), key)?;
        self.slots[i].as_ref().map(|e| (&e.key, &e.value))
    }

    /// O valor da chave, para alterar.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let i = self.find(self.hash_of(key), key)?;
        self.slots[i].as_mut().map(|e| &mut e.value)
    }

    /// A chave existe?
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.find(self.hash_of(key), key).is_some()
    }

    /// O valor da chave; se faltar, insere o que `make` devolver.
    pub fn get_or_insert_with(&mut self, key: K, make: impl FnOnce() -> V) -> &mut V {
        let hash = self.hash_of(&key);
        let i = if let Some(i) = self.find(hash, &key) {
            i
        } else {
            self.grow_for_one_more();
            self.place(Bucket {
                hash,
                key,
                value: make(),
            })
        };
        match self.slots[i].as_mut() {
            Some(e) => &mut e.value,
            None => unreachable!("a entrada acabou de ser achada ou posta"),
        }
    }

    /// Remove a chave e devolve o valor.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove_entry(key).map(|(_, v)| v)
    }

    /// Remove a chave e devolve a entrada.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut hole = self.find(self.hash_of(key), key)?;
        let taken = self.slots[hole].take()?;
        let mask = self.slots.len() - 1;
        // Desloca para trás os seguintes que não estão em casa.
        loop {
            let next = (hole + 1) & mask;
            let movable = self.slots[next]
                .as_ref()
                .is_some_and(|e| self.dist(e.hash, next) > 0);
            if !movable {
                break;
            }
            self.slots[hole] = self.slots[next].take();
            hole = next;
        }
        self.len -= 1;
        Some((taken.key, taken.value))
    }

    /// Confere o invariante do Robin Hood e a contagem (só nos testes): toda
    /// entrada tem, entre o lugar ideal e o dela, ocupantes que estão pelo
    /// menos tão longe de casa quanto ela estaria naquele ponto.
    #[cfg(test)]
    pub(crate) fn check_invariants(&self) {
        if self.slots.is_empty() {
            assert_eq!(self.len, 0);
            return;
        }
        assert!(self.slots.len().is_power_of_two());
        let mask = self.slots.len() - 1;
        let mut count = 0;
        for (i, slot) in self.slots.iter().enumerate() {
            let Some(e) = slot else { continue };
            count += 1;
            let d = self.dist(e.hash, i);
            for j in 1..=d {
                let other = self.slots[(i.wrapping_sub(j)) & mask]
                    .as_ref()
                    .expect("buraco entre a entrada e o lugar ideal");
                assert!(self.dist(other.hash, i.wrapping_sub(j) & mask) >= d - j);
            }
        }
        assert_eq!(count, self.len);
        assert!(self.len * 4 <= self.slots.len() * 3);
    }

    /// Fica só com as entradas para as quais `keep` devolve `true`.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let fresh = empty_slots(self.slots.len());
        let old = mem::replace(&mut self.slots, fresh);
        self.len = 0;
        for mut bucket in old.into_iter().flatten() {
            if keep(&bucket.key, &mut bucket.value) {
                self.place(bucket);
            }
        }
    }
}

impl<K: Clone, V: Clone, S: Clone> Clone for HashMap<K, V, S> {
    fn clone(&self) -> Self {
        Self {
            slots: self
                .slots
                .iter()
                .map(|s| {
                    s.as_ref().map(|b| Bucket {
                        hash: b.hash,
                        key: b.key.clone(),
                        value: b.value.clone(),
                    })
                })
                .collect(),
            len: self.len,
            hasher: self.hasher.clone(),
        }
    }
}

impl<K: fmt::Debug, V: fmt::Debug, S> fmt::Debug for HashMap<K, V, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl<K: Eq + Hash, V: PartialEq, S: BuildHasher> PartialEq for HashMap<K, V, S> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.iter().all(|(k, v)| other.get(k) == Some(v))
    }
}

impl<K: Eq + Hash, V: Eq, S: BuildHasher> Eq for HashMap<K, V, S> {}

impl<K: Eq + Hash, V, S: BuildHasher + Default> FromIterator<(K, V)> for HashMap<K, V, S> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::default();
        map.extend(iter);
        map
    }
}

impl<K: Eq + Hash, V, S: BuildHasher> Extend<(K, V)> for HashMap<K, V, S> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

/// Iterador de `(&K, &V)`.
pub struct Iter<'a, K, V> {
    inner: core::slice::Iter<'a, Option<Bucket<K, V>>>,
    left: usize,
}

impl<'a, K, V> Iterator for Iter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.inner.by_ref().flatten().next()?;
        self.left -= 1;
        Some((&b.key, &b.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl<K, V> ExactSizeIterator for Iter<'_, K, V> {}
impl<K, V> FusedIterator for Iter<'_, K, V> {}

/// Iterador de `(&K, &mut V)`.
pub struct IterMut<'a, K, V> {
    inner: core::slice::IterMut<'a, Option<Bucket<K, V>>>,
    left: usize,
}

impl<'a, K, V> Iterator for IterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.inner.by_ref().flatten().next()?;
        self.left -= 1;
        Some((&b.key, &mut b.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl<K, V> ExactSizeIterator for IterMut<'_, K, V> {}
impl<K, V> FusedIterator for IterMut<'_, K, V> {}

/// Iterador que consome o mapa.
pub struct IntoIter<K, V> {
    inner: alloc::vec::IntoIter<Option<Bucket<K, V>>>,
    left: usize,
}

impl<K, V> Iterator for IntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.inner.by_ref().flatten().next()?;
        self.left -= 1;
        Some((b.key, b.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl<K, V> ExactSizeIterator for IntoIter<K, V> {}
impl<K, V> FusedIterator for IntoIter<K, V> {}

impl<K, V, S> IntoIterator for HashMap<K, V, S> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;

    fn into_iter(self) -> IntoIter<K, V> {
        IntoIter {
            left: self.len,
            inner: self.slots.into_iter(),
        }
    }
}

impl<'a, K, V, S> IntoIterator for &'a HashMap<K, V, S> {
    type Item = (&'a K, &'a V);
    type IntoIter = Iter<'a, K, V>;

    fn into_iter(self) -> Iter<'a, K, V> {
        self.iter()
    }
}

impl<'a, K, V, S> IntoIterator for &'a mut HashMap<K, V, S> {
    type Item = (&'a K, &'a mut V);
    type IntoIter = IterMut<'a, K, V>;

    fn into_iter(self) -> IterMut<'a, K, V> {
        self.iter_mut()
    }
}

// ---- HashSet ----

/// Conjunto hash: um [`HashMap`] sem valores.
pub struct HashSet<T, S = RandomState> {
    map: HashMap<T, (), S>,
}

impl<T> HashSet<T, RandomState> {
    /// Conjunto vazio com uma chave nova.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<T, S: Default> Default for HashSet<T, S> {
    fn default() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}

impl<T, S> HashSet<T, S> {
    /// Conjunto vazio com o hasher dado.
    #[must_use]
    pub const fn with_hasher(hasher: S) -> Self {
        Self {
            map: HashMap::with_hasher(hasher),
        }
    }

    /// Quantos elementos.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Vazio?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Apaga tudo.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Elementos, em ordem sem garantia.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.map.keys()
    }
}

impl<T: Eq + Hash, S: BuildHasher> HashSet<T, S> {
    /// Insere; `true` se era novo.
    pub fn insert(&mut self, value: T) -> bool {
        self.map.insert(value, ()).is_none()
    }

    /// O elemento existe?
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.contains_key(value)
    }

    /// Remove; `true` se existia.
    pub fn remove<Q>(&mut self, value: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.remove(value).is_some()
    }
}

impl<T: Eq + Hash, S: BuildHasher + Default> FromIterator<T> for HashSet<T, S> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = Self::default();
        set.extend(iter);
        set
    }
}

impl<T: Eq + Hash, S: BuildHasher> Extend<T> for HashSet<T, S> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for v in iter {
            self.insert(v);
        }
    }
}

impl<T: Clone, S: Clone> Clone for HashSet<T, S> {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

impl<T: fmt::Debug, S> fmt::Debug for HashSet<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}
