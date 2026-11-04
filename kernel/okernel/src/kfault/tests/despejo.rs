//! Teste de kernel do despejo de páginas (T-363; ADR 0038, itens 2 e 3).
//!
//! O kernel faz o papel da política do `memd`: oculta a página de um
//! objeto `LAZY` que outra thread (noutra CPU, se houver) escreve sem
//! parar, guarda a cópia e a descompromete. A falta seguinte vai a um
//! tratador em assembly, que compromete a página oculta, copia a cópia
//! guardada pela visão `RAW` e a publica.

use alloc::sync::Arc;

use kabi::ipc::recv_target;
use kabi::mem::LAZY;
use kabi::vm::{PAGE_SIZE, RAW, WRITE};
use kabi::{ObjectType, Rights};
use okernel::cap::Cap;
use okernel::mm::PhysAddr;
use okernel::sched::Params;
use okernel::vm::vm_map;

use crate::arch::x86_64::percpu;
use crate::kfault::killed;
use crate::kipc::tests::{create, give, spawn, user_words};
use crate::kmem;
use crate::ksmp;
use crate::ktest::Outcome;
use crate::kthread::tests::{
    DATA_VA, delete, pin, process, run_until_exit, thread_with, user_symbol,
};
use crate::{kthread, ktime};

unsafe extern "C" {
    static user_restore_handler: u8;
    static user_lazy_counter: u8;
}

/// Despejos por rodada do teste.
const ROUNDS: u64 = 16;
/// Quanto o kernel olha a página oculta sem que ela mude.
const QUIET_NS: u64 = 300_000;

/// O contador no início do frame.
fn counter(frame: PhysAddr) -> u64 {
    // SAFETY: frame de um objeto vivo, no mapa direto, alinhado; o usuário
    // pode escrever nele ao mesmo tempo, por isso a leitura volátil.
    unsafe { core::ptr::read_volatile(kmem::direct(frame) as *const u64) }
}

/// FNV-1a dos bytes 8 a 4095 do frame (o resto da página, que o contador
/// não toca).
fn hash(frame: PhysAddr) -> u64 {
    // SAFETY: como em `counter`; só o kernel escreve nesses bytes.
    let bytes =
        unsafe { core::slice::from_raw_parts((kmem::direct(frame) + 8) as *const u8, 4088) };
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

fn wait_for(what: &'static str, mut done: impl FnMut() -> bool) -> Outcome {
    let give_up = ktime::now_ns() + 30_000_000_000;
    while !done() {
        if ktime::now_ns() > give_up {
            return Err(what);
        }
        kthread::yield_now();
    }
    Ok(())
}

/// Aceite da T-363: a página descomprometida e reacessada volta com o
/// conteúdo restaurado (checado por hash), e depois que `HIDE` volta
/// nenhuma CPU escreve na página pela visão normal (sem janela de acesso
/// obsoleto).
#[expect(
    clippy::too_many_lines,
    reason = "montagem, rodadas e conferência de um cenário só"
)]
pub fn despejo() -> Outcome {
    let (faulty, memd) = (process(1)?, process(2)?);
    let base = DATA_VA + 16 * PAGE_SIZE;
    let raw_va = DATA_VA + 32 * PAGE_SIZE;
    let h = faulty
        .cspace
        .lock()
        .obj_create_with(faulty.quota, ObjectType::MemoryObject, PAGE_SIZE, LAZY)
        .map_err(|_| "obj_create(LAZY)")?;
    let mo = faulty.cspace.lock().get(h).map_err(|_| "handle")?.clone();
    vm_map(&faulty.aspace, &mo, base, 0, PAGE_SIZE, WRITE).map_err(|_| "vm_map")?;
    let evict = Rights::READ | Rights::WRITE | Rights::MAP | Rights::EVICT;
    let m_mo = give(&memd, &mo.object, evict, 0)?;
    let raw_cap = Cap {
        rights: evict,
        ..mo.clone()
    };
    vm_map(&memd.aspace, &raw_cap, raw_va, 0, PAGE_SIZE, WRITE | RAW).map_err(|_| "vm_map(RAW)")?;
    let memory = Arc::clone(mo.object.as_memory_object().map_err(|_| "tipo")?);
    memory.commit(0, 1, true).map_err(|_| "commit")?;
    let first = memory.frame(0).ok_or("frame")?;
    // O resto da página com um padrão, para o hash.
    for i in 8..PAGE_SIZE {
        // SAFETY: frame recém-comprometido, no mapa direto; `i` < 4096.
        unsafe { ((kmem::direct(first) + i) as *mut u8).write((i * 7 + 3).to_le_bytes()[0]) };
    }
    let want = hash(first);
    let backing_va = DATA_VA + PAGE_SIZE;
    let backing = memd
        .aspace
        .object
        .as_address_space()
        .map_err(|_| "tipo")?
        .lock()
        .query(backing_va)
        .ok_or("cópia")?
        .0;
    let (ntfy_h, ntfy) = create(&memd, ObjectType::Notification)?;
    let release = Arc::clone(ntfy.as_notification().map_err(|_| "tipo")?);
    drop(ntfy);
    user_words(
        &memd,
        DATA_VA,
        Some([backing_va, base, u64::from(ntfy_h.raw())]),
    )?;
    let (ep_h, ep) = create(&memd, ObjectType::Endpoint)?;
    let (reply, _) = create(&memd, ObjectType::Reply)?;
    let exc = give(&faulty, &ep, Rights::SEND, 0x5E)?;
    drop(ep);
    let (hm, tm) = spawn(
        &memd,
        &raw const user_restore_handler,
        [
            recv_target(ep_h, reply),
            DATA_VA,
            u64::from(m_mo.raw()) | (raw_va >> 12) << 32,
        ],
        0,
    )?;
    let me = percpu::cpu_id() as usize;
    let far = (0..ksmp::count())
        .find(|&c| c != me && ksmp::start::is_online(c))
        .unwrap_or(me);
    // Com 30% da CPU, quem escreve não toma a CPU do teste quando só há
    // uma.
    let params = Params::new(300_000, 1_000_000, 100).map_err(|_| "params")?;
    let (hw, tw) = thread_with(&faulty, params)?;
    pin(&tw, u32::try_from(far).map_err(|_| "cpu")?)?;
    tw.set_exception_handler(exc);
    let e = kthread::UserEntry {
        rip: user_symbol(&raw const user_lazy_counter),
        rsp: DATA_VA + PAGE_SIZE,
        args: [base, DATA_VA, 0],
    };
    ensure!(kthread::start(&tw, &e).is_ok());
    let before = killed();
    let mut frame = first;
    let mut last = 0;
    let mut quiet_ok = true;
    let mut hashes_ok = true;
    for round in 0..ROUNDS {
        wait_for("o contador não andou", || counter(frame) > last + 1000)?;
        memory.hide(0, 1).map_err(|_| "hide")?;
        let c1 = counter(frame);
        let t = ktime::now_ns();
        while ktime::now_ns() < t + QUIET_NS {
            core::hint::spin_loop();
        }
        let c2 = counter(frame);
        quiet_ok &= c1 == c2;
        hashes_ok &= hash(frame) == want;
        // SAFETY: os dois frames são de objetos vivos, distintos, no mapa
        // direto; o da página oculta só muda pela visão RAW, que o tratador
        // não toca até a liberação abaixo.
        unsafe {
            core::ptr::copy_nonoverlapping(
                kmem::direct(frame) as *const u8,
                kmem::direct(backing) as *mut u8,
                4096,
            );
        }
        memory.decommit(0, 1).map_err(|_| "decommit")?;
        ensure!(memory.frame(0).is_none());
        if let Some((t, word)) = release.signal(1) {
            kthread::wake(t, word);
        }
        wait_for("a página não voltou", || {
            memory.frame(0).is_some()
                && user_words::<1>(&memd, DATA_VA + 24, None).is_ok_and(|[n]| n == round + 1)
        })?;
        frame = memory.frame(0).ok_or("frame")?;
        hashes_ok &= hash(frame) == want;
        quiet_ok &= counter(frame) >= c1;
        last = c1;
    }
    user_words(&faulty, DATA_VA + 8, Some([1]))?;
    run_until_exit(&[Arc::clone(&tw)])?;
    let [done] = user_words::<1>(&faulty, DATA_VA, None)?;
    let [_, _, _, served, failed] = user_words::<5>(&memd, DATA_VA, None)?;
    info!(
        "ktest: · {ROUNDS} despejos em CPU {far} (tratador na {me}): {served} faltas restauradas, contador em {}",
        counter(frame)
    );
    ensure!(quiet_ok && hashes_ok);
    ensure!(done == 1 && served == ROUNDS && failed == 0);
    ensure!(killed() == before);
    // Sem o endpoint, o `ipc_recv` do tratador falha e ele sai.
    drop(tw);
    delete(&faulty, &[hw, exc])?;
    delete(&memd, &[ep_h])?;
    run_until_exit(&[Arc::clone(&tm)])?;
    drop(tm);
    delete(&memd, &[hm, m_mo, ntfy_h])?;
    delete(&faulty, &[h])?;
    Ok(())
}
