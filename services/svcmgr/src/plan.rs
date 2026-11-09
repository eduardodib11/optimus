//! Plano de partida (ADR 0034, itens 4 e 5): os manifestos compilados do
//! bootfs (`manifest/<nome>.oman`) viram o [`Broker`] e a ordem de partida
//! por níveis de dependência.
//!
//! Um driver (manifesto com necessidades `dev:`, as regras de `[match]`)
//! não entra nos níveis: ele só parte quando o `devmgr` casa um nó com ele
//! (ADR 0042, itens 1 e 5). Fica em [`Plan::drivers`].
//!
//! Um manifesto ilegível, um binário ausente, um provedor duplicado, uma
//! dependência obrigatória sem provedor ou um ciclo recusam o plano
//! inteiro: o `svcmgr` não sobe um sistema pela metade sem dizer por quê.

use alloc::string::String;
use alloc::vec::Vec;

use crate::broker::{Broker, DeliverError};

/// Prefixo das entradas de manifesto no bootfs.
pub const PREFIX: &str = "manifest/";
/// Sufixo das entradas de manifesto no bootfs.
pub const SUFFIX: &str = ".oman";

/// Por que o plano foi recusado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// O manifesto `name` não decodifica.
    BadManifest(String),
    /// O binário pedido por `service` não está no bootfs.
    MissingBinary(String),
    /// Recusa do corretor (provedor duplicado, por exemplo).
    Broker(DeliverError),
    /// Dependência obrigatória sem provedor ou ciclo.
    Graph(oman::Error),
}

/// O plano: o corretor e os ids dos serviços por nível.
pub struct Plan {
    /// O corretor, com um serviço por manifesto, na ordem dos nomes.
    pub broker: Broker,
    /// Ids por nível; os de um nível só dependem dos anteriores. Sem os
    /// drivers.
    pub levels: Vec<Vec<u32>>,
    /// Ids dos drivers, na ordem dos nomes.
    pub drivers: Vec<u32>,
}

/// Monta o plano a partir das entradas `(nome, dados)` do bootfs.
///
/// # Errors
/// Ver [`PlanError`].
pub fn build(entries: &[(&str, &[u8])]) -> Result<Plan, PlanError> {
    let mut found: Vec<(&str, &[u8])> = entries
        .iter()
        .copied()
        .filter(|(n, _)| n.starts_with(PREFIX) && n.ends_with(SUFFIX))
        .collect();
    found.sort_by(|a, b| a.0.cmp(b.0));
    let mut manifests = Vec::with_capacity(found.len());
    for (name, data) in found {
        let m = oman::parse(data).map_err(|_| PlanError::BadManifest(String::from(name)))?;
        if !entries.iter().any(|(n, _)| *n == m.binary) {
            return Err(PlanError::MissingBinary(m.name.clone()));
        }
        manifests.push(m);
    }
    let order = oman::levels(&manifests).map_err(PlanError::Graph)?;
    let drivers: Vec<u32> = (0u32..)
        .zip(&manifests)
        .filter(|(_, m)| m.needs.iter().any(|n| n.kind == oman::NeedKind::Dev))
        .map(|(id, _)| id)
        .collect();
    let broker = Broker::new(manifests).map_err(PlanError::Broker)?;
    let levels = order
        .into_iter()
        .map(|l| -> Vec<u32> {
            l.into_iter()
                .filter_map(|i| u32::try_from(i).ok())
                .filter(|id| !drivers.contains(id))
                .collect()
        })
        .filter(|l| !l.is_empty())
        .collect();
    Ok(Plan {
        broker,
        levels,
        drivers,
    })
}

#[cfg(test)]
mod tests;
