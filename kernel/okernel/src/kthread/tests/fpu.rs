//! Teste de kernel da troca de FPU (T-519; ADR 0058, item 1): a troca
//! que pula o `XSAVE`/`XRSTOR` com os registradores no estado inicial não
//! deixa estado de uma thread chegar a outra, nem perde o de quem o tem.

use alloc::vec::Vec;

use super::super::{UserEntry, start};
use super::sync::read_user;
use super::{DATA_VA, delete, pin, process, run_until_exit, settled, thread, user_symbol};
use crate::arch::x86_64::{fpu, percpu};
use crate::kcap::root_quota;
use crate::ktest::Outcome;
use kabi::vm::PAGE_SIZE;

unsafe extern "C" {
    static user_fpu: u8;
}

const VOLTAS: u64 = 500;

/// Quatro threads na mesma CPU alternam por `yield`: duas nunca tocam na
/// FPU, uma suja `xmm0` e o MXCSR, outra só o MXCSR. Cada uma confere, a
/// cada volta, que vê o próprio estado.
pub fn estado_inicial_nao_vaza() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let modes = [0u64, 1, 0, 2];
        let p = process(modes.len() as u64)?;
        let entry = user_symbol(&raw const user_fpu);
        let mut handles = Vec::new();
        let mut threads = Vec::new();
        for (i, &mode) in modes.iter().enumerate() {
            let (h, t) = thread(&p)?;
            let page = DATA_VA + i as u64 * PAGE_SIZE;
            let e = UserEntry {
                rip: entry,
                rsp: page + PAGE_SIZE,
                args: [mode, VOLTAS, page],
            };
            pin(&t, percpu::cpu_id())?;
            ensure!(start(&t, &e).is_ok());
            handles.push(h);
            threads.push(t);
        }
        run_until_exit(&threads)?;
        info!(
            "ktest: · troca pula XSAVE/XRSTOR redundantes: {}",
            if fpu::skips_redundant() {
                "sim (XINUSE)"
            } else {
                "não (sem XINUSE)"
            }
        );
        for (i, &mode) in modes.iter().enumerate() {
            let [wrong, done] = read_user::<2>(&p, DATA_VA + i as u64 * PAGE_SIZE)?;
            info!("ktest: · thread {i} (modo {mode}): {done} voltas, {wrong} com estado errado");
            ensure!(wrong == 0 && done == VOLTAS);
        }
        drop(threads);
        delete(&p, &handles)?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}
