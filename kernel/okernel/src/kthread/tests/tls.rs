//! Testes de kernel do TLS por thread (T-333; ADR 0039, item 3): cada
//! thread vê o próprio `FS_BASE`, em CPUs diferentes e na mesma CPU, venha
//! ele de `thread_configure` da própria thread ou do kernel antes da
//! partida, mesmo depois de outra thread zerar o `FS_BASE` da CPU.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use kabi::exit::CAUSE_EXITED;
use kabi::vm::{PAGE_SIZE, WRITE};
use kabi::{Error, STATUS_OK};
use okernel::vm::vm_map;

use super::super::{UserEntry, start_on};
use super::smp::{gone, option, wait_with};
use super::sync::read_user;
use super::{DATA_VA, Page, delete, pin, process, settled, thread, user_symbol};
use crate::kcap::root_quota;
use crate::ksmp;
use crate::ktest::Outcome;

unsafe extern "C" {
    static user_tls: u8;
}

/// Onde o processo mapeia as páginas de TLS, uma por valor.
const TLS_VA: u64 = 0x80_0000;
/// Voltas de cada thread sem `smp.tls`.
const DEFAULT_ROUNDS: u64 = 2_000;
/// Modo de `user_tls`: a thread fixa o próprio TLS por `thread_configure`.
const SELF_CONFIGURE: u64 = 1;
/// Modo de `user_tls`: a thread não lê; zera o `FS_BASE` da CPU (seletor em
/// FS) e cede a vez.
const CLOBBER: u64 = 2;

/// Aceite da T-333: duas threads com TLS diferente em CPUs diferentes
/// enxergam cada uma o seu valor.
///
/// Na CPU `a`, uma thread zera o `FS_BASE` (carrega um seletor em FS) e
/// cede a vez a outra com o mesmo TLS dela: a troca tem de comparar com o
/// valor que está na CPU, não com o da que saiu. Na CPU `b`, duas threads
/// com TLS diferentes se alternam, uma fixada pelo kernel antes da partida
/// (a primeira entrada) e outra pela própria thread. Com uma CPU só, as
/// quatro dividem a mesma.
pub fn cada_thread_ve_o_seu() -> Outcome {
    // Com APs livres, longe do BSP (que roda o teste); com duas CPUs, o
    // BSP roda as da CPU `a` quando o teste cede a vez.
    let (a, b) = match ksmp::start::online_count() {
        0 | 1 => (0u32, 0u32),
        2 => (0, 1),
        _ => (1, 2),
    };
    let rounds = option("smp.tls", DEFAULT_ROUNDS);
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let p = process(4)?;
        let mut handles = Vec::new();
        let mut values = [0u64; 3];
        for (k, value) in values.iter_mut().enumerate() {
            let page = Page::new(&p)?;
            let va = TLS_VA + k as u64 * PAGE_SIZE;
            ensure!(vm_map(&p.aspace, &page.cap, va, 0, PAGE_SIZE, WRITE).is_ok());
            // O ponteiro para si no início do bloco (ABI x86-64).
            page.word(0).store(va, Ordering::Release);
            *value = va;
            handles.push(page.handle);
        }
        // (valor de TLS, modo, CPU) de cada thread.
        let plan = [
            (values[0], CLOBBER, a),
            (values[0], SELF_CONFIGURE, a),
            (values[1], SELF_CONFIGURE, b),
            (values[2], 0, b),
        ];
        let entry = user_symbol(&raw const user_tls);
        let mut threads = Vec::new();
        for (i, &(tls, mode, cpu)) in plan.iter().enumerate() {
            let (handle, t) = thread(&p)?;
            if mode & SELF_CONFIGURE == 0 {
                ensure!(t.set_tls(tls).is_ok());
            }
            let page = DATA_VA + i as u64 * PAGE_SIZE;
            let user = UserEntry {
                rip: entry,
                rsp: page + PAGE_SIZE,
                args: [tls, rounds | mode << 32, page],
            };
            pin(&t, cpu)?;
            handles.push(handle);
            threads.push((t, user, cpu));
        }
        for (t, e, cpu) in &threads {
            ensure!(start_on(t, e, *cpu).is_ok());
        }
        let limit = 60_000 * super::smp::MS + rounds * 2_000_000;
        let done = wait_with(limit, a != 0, || threads.iter().all(|(t, ..)| gone(t)));
        ensure!(done);
        let invalid = Error::InvalidArgument.to_raw();
        for (i, ((t, _, cpu), &(tls, mode, _))) in threads.iter().zip(&plan).enumerate() {
            let page = DATA_VA + i as u64 * PAGE_SIZE;
            let [status, wrong, done, seen, group, unknown] = read_user::<6>(&p, page)?;
            info!(
                "ktest: · thread {i} (cpu{cpu}, TLS {tls:#x}, modo {mode}): {done} voltas, \
                 {wrong} leituras erradas, última na cpu{seen}"
            );
            ensure!(status == STATUS_OK && done == rounds);
            ensure!(group == invalid && unknown == invalid);
            ensure!(t.tls() == tls && t.cpu() == *cpu);
            ensure!(t.death() == Some((CAUSE_EXITED, rounds, 0)));
            if mode & CLOBBER == 0 {
                ensure!(wrong == 0 && seen == u64::from(*cpu));
            }
        }
        drop(threads);
        delete(&p, &handles)?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}
