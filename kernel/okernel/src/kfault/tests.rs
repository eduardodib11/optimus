//! Testes de kernel das faltas de usuário (T-210): sem tratador, a thread
//! que acessa o endereço nulo (ou divide por zero, executa `ud2` ou `hlt`)
//! é encerrada e reportada; com tratador, ele recebe a falta pelo
//! endpoint, mapeia a página e a thread segue.

use alloc::sync::Arc;

use kabi::fault::{DIVIDE_ERROR, GENERAL_PROTECTION, INVALID_OPCODE, PAGE_FAULT};
use kabi::ipc::recv_target;
use kabi::vm::PAGE_SIZE;
use kabi::{Error, ObjectType, Rights, STATUS_OK};
use okernel::fault::Kill;
use okernel::thread::RunState;

use super::{killed, last};
use crate::kcap::root_quota;
use crate::kipc::tests::{create, give, run_until_blocked, spawn, user_words};
use crate::kmem;
use crate::ktest::{Outcome, Test};
use crate::kthread::tests::{DATA_VA, delete, process, run_until_exit};

/// Testes de kernel das faltas de usuário.
pub const TESTS: &[Test] = &[
    Test {
        name: "falta.acesso_nulo_encerra_e_reporta",
        run: acesso_nulo,
    },
    Test {
        name: "falta.tratador_recebe_a_falta_e_mapeia_a_pagina",
        run: tratador,
    },
    Test {
        name: "falta.endpoint_destruido_encerra_quem_espera",
        run: ninguem_atende,
    },
];

unsafe extern "C" {
    static user_fault: u8;
    static user_fault_read: u8;
    static user_fault_handler: u8;
}

/// Aceite do T-210: sem endpoint de exceções, a thread que lê o endereço
/// 0 é encerrada e a falta reportada; o mesmo para #DE, #UD e #GP. Nada
/// vaza da cota.
fn acesso_nulo() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    for vector in [PAGE_FAULT, DIVIDE_ERROR, INVALID_OPCODE, GENERAL_PROTECTION] {
        let p = process(1)?;
        let before = killed();
        let (h, t) = spawn(&p, &raw const user_fault, [vector, DATA_VA, 0], 0)?;
        run_until_exit(&[Arc::clone(&t)])?;
        let report = last().ok_or("sem relatório")?;
        let [mark] = user_words::<1>(&p, DATA_VA, None)?;
        info!(
            "ktest: · vetor {vector}: encerrada em rip {:#x}, endereço {:#x} ({})",
            report.fault.rip, report.fault.addr, report.kill
        );
        ensure!(killed() == before + 1 && t.state() == RunState::Exited);
        ensure!(report.thread == Arc::as_ptr(&t).addr());
        ensure!(report.fault.vector == vector && report.kill == Kill::NoHandler);
        ensure!(report.fault.addr == 0);
        // Chegou à instrução que falta e não passou dela.
        ensure!(mark == 1);
        drop(t);
        delete(&p, &[h])?;
    }
    ensure!(quota.used() == used0);
    Ok(())
}

/// O tratador (outro processo) recebe a falta de página pelo endpoint de
/// exceções, com o badge da thread, mapeia um `MemoryObject` no endereço
/// que faltou e responde; a thread retoma e lê o que o tratador mapeou.
fn tratador() -> Outcome {
    const BADGE: u64 = 0xFA17;
    const VALUE: u64 = 0x0123_4567_89ab_cdef;
    let (faulty, memd) = (process(1)?, process(1)?);
    let addr = DATA_VA + 8 * PAGE_SIZE + 0x18;
    // A página que o tratador vai mapear, já com o valor.
    let mo = faulty
        .cspace
        .lock()
        .obj_create(faulty.quota, ObjectType::MemoryObject, PAGE_SIZE)
        .map_err(|_| "obj_create")?;
    let mo = faulty
        .cspace
        .lock()
        .get(mo)
        .map_err(|_| "handle")?
        .object
        .clone();
    let frame = mo
        .as_memory_object()
        .map_err(|_| "tipo")?
        .frame(0)
        .ok_or("frame")?;
    // SAFETY: frame recém-criado do objeto, no mapa direto, alinhado.
    unsafe { ((kmem::direct(frame) + 0x18) as *mut u64).write(VALUE) };
    let (ep_h, ep) = create(&memd, ObjectType::Endpoint)?;
    let (reply, _) = create(&memd, ObjectType::Reply)?;
    let m_aspace = give(&memd, &faulty.aspace.object, faulty.aspace.rights, 0)?;
    let m_mo = give(&memd, &mo, Rights::MAP | Rights::READ | Rights::WRITE, 0)?;
    let exc = give(&faulty, &ep, Rights::SEND, BADGE)?;
    let maps = u64::from(m_aspace.raw()) | (u64::from(m_mo.raw()) << 32);
    let (hm, tm) = spawn(
        &memd,
        &raw const user_fault_handler,
        [recv_target(ep_h, reply), DATA_VA, maps],
        0,
    )?;
    let (hf, tf) = crate::kthread::tests::thread(&faulty)?;
    tf.set_exception_handler(exc);
    let e = crate::kthread::UserEntry {
        rip: crate::kthread::tests::user_symbol(&raw const user_fault_read),
        rsp: DATA_VA + PAGE_SIZE,
        args: [addr, DATA_VA, 0],
    };
    ensure!(crate::kthread::start(&tf, &e).is_ok());
    let before = killed();
    run_until_exit(&[Arc::clone(&tm), Arc::clone(&tf)])?;
    let [status, badge, label, error, at, rip, map, sent] =
        user_words::<8>(&memd, DATA_VA + 16, None)?;
    let [mark, read] = user_words::<2>(&faulty, DATA_VA, None)?;
    info!(
        "ktest: · tratador recebeu rótulo {label}, endereço {at:#x}, rip {rip:#x}; a thread leu {read:#x}"
    );
    ensure!(status == STATUS_OK && badge == BADGE && label == PAGE_FAULT);
    // Leitura de usuário de página ausente: U=1, W=0, P=0.
    ensure!(at == addr && error == 4);
    ensure!(map == STATUS_OK && sent == STATUS_OK);
    ensure!(mark == 2 && read == VALUE);
    ensure!(killed() == before);
    drop((tm, tf));
    delete(&memd, &[hm])?;
    delete(&faulty, &[hf])?;
    Ok(())
}

/// Ninguém atende: a thread espera na fila do endpoint de exceções até
/// a última capability dele sumir; aí é encerrada (`PeerClosed`).
fn ninguem_atende() -> Outcome {
    let p = process(1)?;
    let (ep_h, ep) = create(&p, ObjectType::Endpoint)?;
    drop(ep);
    let before = killed();
    let (h, t) = crate::kthread::tests::thread(&p)?;
    t.set_exception_handler(ep_h);
    let e = crate::kthread::UserEntry {
        rip: crate::kthread::tests::user_symbol(&raw const user_fault),
        rsp: DATA_VA + PAGE_SIZE,
        args: [PAGE_FAULT, DATA_VA, 0],
    };
    ensure!(crate::kthread::start(&t, &e).is_ok());
    run_until_blocked(&t)?;
    ensure!(killed() == before);
    delete(&p, &[ep_h])?;
    run_until_exit(&[Arc::clone(&t)])?;
    let report = last().ok_or("sem relatório")?;
    info!("ktest: · {}", report.kill);
    ensure!(killed() == before + 1);
    ensure!(report.kill == Kill::Unanswered(Error::PeerClosed));
    drop(t);
    delete(&p, &[h])?;
    Ok(())
}
