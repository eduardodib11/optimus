//! `MemoryQuota`: orçamento de bytes para criar objetos (T-202; ADR 0006).
//!
//! Toda memória que um objeto do kernel ocupa é cobrada de uma cota por um
//! [`Charge`], que devolve os bytes quando é destruído (junto com o objeto).
//! Uma cota filha, criada por `obj_create` com o direito `SPLIT`, cobra da
//! mãe o próprio tamanho mais o orçamento inteiro: os bytes saem da mãe na
//! criação e voltam quando a filha morre. A cota raiz é do kernel e não tem
//! mãe.
//!
//! A contabilidade é uma palavra atômica com compare-and-swap, então cobrar e
//! devolver não tomam trava e servem a qualquer núcleo.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use kabi::Error;

/// Orçamento de bytes e quanto dele está em uso.
#[derive(Debug)]
pub struct MemoryQuota {
    limit: u64,
    used: AtomicU64,
    /// O que esta cota custa à mãe (nada na raiz); devolvido ao morrer.
    parent: Option<Charge>,
}

impl MemoryQuota {
    /// Cota raiz do kernel com `limit` bytes.
    #[must_use]
    pub fn root(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicU64::new(0),
            parent: None,
        })
    }

    /// Cota filha com orçamento `limit`, pagando à mãe com `charge`.
    pub(super) fn child(limit: u64, charge: Charge) -> Self {
        Self {
            limit,
            used: AtomicU64::new(0),
            parent: Some(charge),
        }
    }

    /// Orçamento total, em bytes.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes cobrados e ainda não devolvidos.
    #[must_use]
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }

    /// Bytes ainda disponíveis.
    #[must_use]
    pub fn available(&self) -> u64 {
        self.limit - self.used()
    }

    /// Bytes que esta cota custa à mãe (zero na raiz).
    #[must_use]
    pub fn parent_charge(&self) -> u64 {
        self.parent.as_ref().map_or(0, Charge::bytes)
    }

    /// Reserva `bytes` sem passar do limite.
    fn take(&self, bytes: u64) -> Result<(), Error> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|&n| n <= self.limit)
            })
            .map(drop)
            .map_err(|_| Error::QuotaExceeded)
    }

    /// Devolve `bytes` reservados antes.
    fn give_back(&self, bytes: u64) {
        let before = self.used.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(before >= bytes, "cota devolveu mais do que cobrou");
    }

    /// Cobra `bytes` desta cota.
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] se a cota não tiver `bytes` livres; nada é
    /// cobrado nesse caso.
    pub fn charge(self: &Arc<Self>, bytes: u64) -> Result<Charge, Error> {
        self.take(bytes)?;
        Ok(Charge {
            quota: Arc::clone(self),
            bytes,
        })
    }
}

/// Bytes cobrados de uma cota, devolvidos quando o `Charge` é destruído.
///
/// Mantém a cota viva enquanto houver cobrança pendente, mesmo sem
/// capabilities para ela.
#[derive(Debug)]
pub struct Charge {
    quota: Arc<MemoryQuota>,
    bytes: u64,
}

impl Charge {
    /// Bytes cobrados.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// A cota cobrada.
    #[must_use]
    pub const fn quota(&self) -> &Arc<MemoryQuota> {
        &self.quota
    }

    /// Cobra mais `extra` bytes da mesma cota (objeto que cresce).
    ///
    /// # Errors
    ///
    /// [`Error::QuotaExceeded`] sem bytes livres; a cobrança não muda.
    pub fn grow(&mut self, extra: u64) -> Result<(), Error> {
        let total = self.bytes.checked_add(extra).ok_or(Error::QuotaExceeded)?;
        self.quota.take(extra)?;
        self.bytes = total;
        Ok(())
    }

    /// Devolve `less` bytes à cota antes da destruição (objeto que encolhe).
    pub fn shrink(&mut self, less: u64) {
        let less = less.min(self.bytes);
        self.quota.give_back(less);
        self.bytes -= less;
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.quota.give_back(self.bytes);
    }
}
