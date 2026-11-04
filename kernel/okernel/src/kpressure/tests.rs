//! Testes de kernel da pressão de memória (T-360; ADR 0038, item 5).

use alloc::sync::Arc;

use kabi::Error;
use okernel::notify::Notification;

use super::{create, freeze, note, signal};
use crate::kcap::root_quota;
use crate::kmem;
use crate::ktest::{Outcome, Test};

/// Testes de kernel da pressão de memória.
pub const TESTS: &[Test] = &[Test {
    name: "pressao.limiar_dispara_a_notificacao",
    run: limiar,
}];

/// Aceite da T-360: cruzar o limiar baixo dispara o bit ligado à linha
/// baixa, e só ele; o `ack` com o nível ainda afirmado dispara de novo; o
/// crítico dispara o outro bit; a histerese desafirma e o `ack` deixa de
/// disparar. Os quadros livres são simulados ([`note`]) com um total fixo.
fn limiar() -> Outcome {
    const TOTAL: usize = 32_000;
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    let ntfy = Arc::new(Notification::new(&quota).map_err(|_| "Notification")?);
    let [low, critical] = create(&quota).map_err(|_| "create")?;
    ensure!(create(&quota).err() == Some(Error::Busy));
    low.bind(Arc::clone(&ntfy), 0).map_err(|_| "bind")?;
    critical.bind(Arc::clone(&ntfy), 1).map_err(|_| "bind")?;
    let was = freeze(true);
    // Nada abaixo dos limiares.
    note(TOTAL / 2, TOTAL);
    signal();
    let first = ntfy.poll();
    // Baixo: < 1/8.
    note(TOTAL / 8 - 1, TOTAL);
    signal();
    let low_only = ntfy.poll();
    // O `ack` com o nível afirmado dispara de novo.
    let again = low.ack().is_some();
    // Crítico: < 1/32.
    note(TOTAL / 32 - 1, TOTAL);
    signal();
    let both = ntfy.poll();
    // Acima de 1/8 + 1/16: tudo desafirmado; o `ack` não dispara mais.
    note(TOTAL / 8 + TOTAL / 16 + 1, TOTAL);
    signal();
    let quiet = ntfy.poll();
    let after_ack = low.ack().is_some() || critical.ack().is_some();
    // O estado real volta antes de qualquer `ensure!`.
    freeze(was);
    let (free, total) = kmem::frame_stats();
    note(free, total);
    signal();
    info!(
        "ktest: · bits: {first:#b}, {low_only:#b}, {both:#b}, {quiet:#b}; ack de novo: {again}, depois: {after_ack}"
    );
    ensure!(first == 0 && low_only == 0b01 && again);
    // A baixa ainda mascarada; a crítica dispara.
    ensure!(both == 0b10);
    ensure!(quiet == 0 && !after_ack);
    drop((low, critical, ntfy));
    ensure!(quota.used() == used0);
    // Sem as linhas, a criação volta a valer.
    let lines = create(&quota).map_err(|_| "create de novo")?;
    drop(lines);
    ensure!(quota.used() == used0);
    Ok(())
}
