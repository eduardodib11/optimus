//! Tipos e rotinas para segredos (ADR 0053, itens 6 e 7: P5 e P8).
//!
//! [`Secret`] não implementa `Debug`, `Display`, `Clone` nem `Copy`, é
//! zerado no `Drop` e só se compara em tempo constante. [`wipe`] zera sem
//! `unsafe`: escreve zeros, e `black_box` mais `compiler_fence` impedem o
//! compilador de eliminar a escrita como "morta".

use core::hint::black_box;
use core::sync::atomic::{Ordering, compiler_fence};

/// Zera `buf` de modo que o compilador não possa descartar a escrita.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    black_box(&mut *buf);
    compiler_fence(Ordering::SeqCst);
}

/// Compara `a` e `b` em tempo constante em relação ao conteúdo. Tamanhos
/// diferentes dão `false` (o tamanho não é segredo).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    black_box(diff) == 0
}

/// Segredo de `N` bytes: chave, PRK, saída de HKDF. Sem `Debug`, `Display`,
/// `Clone` e `Copy` de propósito (P8); zerado ao sair de escopo.
pub struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    /// Segredo de zeros, para preencher depois.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self([0; N])
    }

    /// Toma os bytes de `bytes` e zera a cópia do chamador.
    #[must_use]
    pub fn take(bytes: &mut [u8; N]) -> Self {
        let s = Self(*bytes);
        wipe(bytes);
        s
    }

    /// Os bytes do segredo, só para alimentar uma primitiva.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Os bytes do segredo, para preencher.
    pub const fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Igualdade em tempo constante.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests;
