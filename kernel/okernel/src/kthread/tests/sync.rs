//! Testes de kernel de notificações, interrupções e futex (T-209).

use alloc::sync::Arc;
use alloc::vec::Vec;

use kabi::vm::PAGE_SIZE;
use kabi::{ObjectType, STATUS_OK};
use okernel::cap::{Cap, Object, default_rights};
use okernel::futex::FUTEXES;
use okernel::thread::RunState;

use super::super::{UserEntry, start, yield_now};
use super::{DATA_VA, Process, delete, process, run_until_exit, thread, user_symbol};
use crate::arch::x86_64::{apic, cpu, probe};
use crate::kcap::root_quota;
use crate::ktest::Outcome;
use crate::kvm::activate;
use crate::{kirq, ktime};

unsafe extern "C" {
    static user_irq_wait: u8;
    static user_mutex: u8;
}

/// Vetor livre usado pelo teste de interrupção.
const TEST_VECTOR: u8 = 0x40;
/// Voltas de cada thread no teste do mutex.
const VOLTAS: u64 = 2000;

/// Lê `N` palavras de 64 bits do usuário em `va`, no espaço de `p`.
fn read_user<const N: usize>(p: &Process, va: u64) -> Result<[u64; N], &'static str> {
    let root = p
        .aspace
        .object
        .as_address_space()
        .map_err(|_| "tipo")?
        .lock()
        .root();
    let mut bytes = [0u8; 64];
    // SAFETY: o espaço segue vivo (em `p`) até o CR3 voltar.
    let old = unsafe { activate(root) };
    let ok = probe::copy_from_user(&mut bytes[..N * 8], va);
    // SAFETY: o CR3 anterior era o do kernel.
    unsafe { cpu::write_cr3(old) };
    ensure!(ok);
    let mut out = [0u64; N];
    for (word, chunk) in out.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().map_err(|_| "tamanho")?);
    }
    Ok(out)
}

/// Uma thread liga a interrupção a um bit, espera na notificação e é
/// acordada pelo disparo do vetor (self-IPI), já de volta ao anel 3.
pub fn irq_acorda() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let p = process(1)?;
    let (ntfy, irq) = {
        let irq = kirq::create(&quota, TEST_VECTOR).map_err(|_| "kirq::create")?;
        ensure!(kirq::create(&quota, TEST_VECTOR).is_err());
        let mut s = p.cspace.lock();
        let n = s
            .obj_create(p.quota, ObjectType::Notification, 0)
            .map_err(|_| "obj_create(Notification)")?;
        let i = s
            .insert(Cap {
                object: Object::Interrupt(irq),
                rights: default_rights(ObjectType::Interrupt),
                badge: 0,
            })
            .map_err(|_| "insert")?;
        (n, i)
    };
    let notification = Arc::clone(
        p.cspace
            .lock()
            .get(ntfy)
            .map_err(|_| "handle")?
            .object
            .as_notification()
            .map_err(|_| "tipo")?,
    );
    let (h, t) = thread(&p)?;
    let e = UserEntry {
        rip: user_symbol(&raw const user_irq_wait),
        rsp: DATA_VA + PAGE_SIZE,
        args: [u64::from(irq.raw()), u64::from(ntfy.raw()), DATA_VA],
    };
    ensure!(start(&t, &e).is_ok());
    for _ in 0..100 {
        if t.state() == RunState::Blocked {
            break;
        }
        yield_now();
    }
    ensure!(t.state() == RunState::Blocked && notification.waiters() == 1);
    apic::self_ipi(TEST_VECTOR);
    let give_up = ktime::now_ns() + 1_000_000_000;
    while t.state() != RunState::Exited && ktime::now_ns() < give_up {
        cpu::wait_for_interrupt();
        yield_now();
    }
    ensure!(t.state() == RunState::Exited);
    let [bind, wait, bits, ack] = read_user::<4>(&p, DATA_VA)?;
    info!("ktest: · obj_bind_notify {bind}, ntfy_wait {wait} com bits {bits:#x}, irq_ack {ack}");
    ensure!(bind == STATUS_OK && wait == STATUS_OK && ack == STATUS_OK);
    ensure!(bits == 1 << 3);
    ensure!(apic::unexpected() == 0);
    delete(&p, &[h, ntfy, irq])?;
    // Com a capability apagada, o vetor fica livre de novo.
    let again = kirq::create(&quota, TEST_VECTOR).map_err(|_| "vetor não liberado")?;
    drop(again);
    Ok(())
}

/// Aceite do T-209: 4 threads somam `VOLTAS` cada a um contador sob um
/// mutex de futex; o total sai exato, todas terminam e cada espera teve
/// exatamente um despertar.
pub fn mutex_4_threads() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    let before = FUTEXES.stats();
    {
        // Página 0: mutex (u32) e contador (u64); páginas 1 a 4: pilhas.
        let p = process(5)?;
        let mut handles = Vec::new();
        let mut threads = Vec::new();
        for i in 1..=4 {
            let (h, t) = thread(&p)?;
            let e = UserEntry {
                rip: user_symbol(&raw const user_mutex),
                rsp: DATA_VA + (i + 1) * PAGE_SIZE,
                args: [DATA_VA, DATA_VA + 8, VOLTAS],
            };
            ensure!(start(&t, &e).is_ok());
            handles.push(h);
            threads.push(t);
        }
        run_until_exit(&threads)?;
        let [mutex, counter] = read_user::<2>(&p, DATA_VA)?;
        let after = FUTEXES.stats();
        let (blocked, woken) = (after.blocked - before.blocked, after.woken - before.woken);
        info!(
            "ktest: · contador {counter} de {}; {blocked} esperas, {woken} despertares, \
             {} futex_wait recusados",
            4 * VOLTAS,
            after.stale - before.stale
        );
        ensure!(counter == 4 * VOLTAS);
        ensure!(mutex == 0);
        ensure!(blocked > 0 && woken == blocked);
        drop(threads);
        delete(&p, &handles)?;
    }
    ensure!(quota.used() == used0);
    Ok(())
}
