//! Testes de kernel do IPC (T-208): ping-pong entre duas threads de
//! usuário em processos diferentes, transferência de capability com e sem
//! `GRANT` (e a revogação que alcança a cópia, ADR 0028), prazo vencido e
//! `PeerClosed` quando o objeto morre.

use alloc::sync::Arc;
use alloc::vec::Vec;

use kabi::ipc::{MsgInfo, recv_target};
use kabi::vm::PAGE_SIZE;
use kabi::{Error, Handle, ObjectType, Rights, STATUS_OK, Syscall};
use okernel::cap::{Cap, Object};
use okernel::sys;
use okernel::thread::{RunState, Thread};

use crate::arch::x86_64::{cpu, probe};
use crate::kcap::root_quota;
use crate::ktest::{Outcome, Test};
use crate::kthread::tests::{
    DATA_VA, Process, delete, process, run_until_exit, thread, user_symbol,
};
use crate::kthread::{KernelEnv, UserEntry, fast_switches, start, yield_now};
use crate::ktime;
use crate::kvm::activate;

/// Testes de kernel do IPC.
pub const TESTS: &[Test] = &[
    Test {
        name: "ipc.ping_pong_de_10000_idas_e_voltas",
        run: ping_pong,
    },
    Test {
        name: "ipc.transferencia_de_capability_com_e_sem_grant",
        run: transferencia,
    },
    Test {
        name: "ipc.prazo_vencido_devolve_timed_out",
        run: prazo,
    },
    Test {
        name: "ipc.objeto_destruido_acorda_com_peer_closed",
        run: peer_closed,
    },
];

unsafe extern "C" {
    static user_ipc_server: u8;
    static user_ipc_client: u8;
    static user_ipc_send_cap: u8;
    static user_ipc_recv: u8;
}

const VOLTAS: u64 = 10_000;
const BADGE: u64 = 0x77;

/// Lê ou grava `N` palavras do usuário em `va`, no espaço de `p`.
pub(crate) fn user_words<const N: usize>(
    p: &Process,
    va: u64,
    write: Option<[u64; N]>,
) -> Result<[u64; N], &'static str> {
    let root = p
        .aspace
        .object
        .as_address_space()
        .map_err(|_| "tipo")?
        .lock()
        .root();
    let mut bytes = [0u8; 64];
    if let Some(words) = write {
        for (chunk, w) in bytes.chunks_exact_mut(8).zip(words) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
    }
    // SAFETY: o espaço segue vivo (em `p`) até o CR3 voltar.
    let old = unsafe { activate(root) };
    let ok = if write.is_some() {
        probe::copy_to_user(va, &bytes[..N * 8])
    } else {
        probe::copy_from_user(&mut bytes[..N * 8], va)
    };
    // SAFETY: o CR3 anterior era o do kernel.
    unsafe { cpu::write_cr3(old) };
    ensure!(ok);
    let mut out = [0u64; N];
    for (word, chunk) in out.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().map_err(|_| "tamanho")?);
    }
    Ok(out)
}

/// Guarda em `p` uma capability de `object`.
pub(crate) fn give(
    p: &Process,
    object: &Object,
    rights: Rights,
    badge: u64,
) -> Result<Handle, &'static str> {
    p.cspace
        .lock()
        .insert(Cap {
            object: object.clone(),
            rights,
            badge,
        })
        .map_err(|_| "insert")
}

/// Objeto novo de `ty` na cota de `p`, com a capability de `obj_create`.
pub(crate) fn create(p: &Process, ty: ObjectType) -> Result<(Handle, Object), &'static str> {
    let h = p
        .cspace
        .lock()
        .obj_create(p.quota, ty, 0)
        .map_err(|_| "obj_create")?;
    let object = p.cspace.lock().get(h).map_err(|_| "handle")?.object.clone();
    Ok((h, object))
}

/// Inicia em `p` uma thread em `sym` com a pilha no topo da página
/// `stack_page` de dados e o buffer de IPC na página 0.
pub(crate) fn spawn(
    p: &Process,
    sym: *const u8,
    args: [u64; 3],
    stack_page: u64,
) -> Result<(Handle, Arc<Thread>), &'static str> {
    let (h, t) = thread(p)?;
    t.set_ipc_buffer(DATA_VA).map_err(|_| "buffer")?;
    let e = UserEntry {
        rip: user_symbol(sym),
        rsp: DATA_VA + (stack_page + 1) * PAGE_SIZE,
        args,
    };
    ensure!(start(&t, &e).is_ok());
    Ok((h, t))
}

/// Aceite do T-208: 10⁴ idas e voltas conferidas pelos dois lados, pelo
/// caminho rápido (troca direta nos dois sentidos).
fn ping_pong() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let (client, server) = (process(2)?, process(2)?);
        let (ep_h, ep) = create(&client, ObjectType::Endpoint)?;
        let c_ep = client
            .cspace
            .lock()
            .mint(ep_h, Rights::SEND, Some(BADGE))
            .map_err(|_| "mint")?;
        let s_ep = give(&server, &ep, Rights::RECV, 0)?;
        let (s_reply, _) = create(&server, ObjectType::Reply)?;
        user_words(&server, DATA_VA + 16, Some([BADGE]))?;
        let fast0 = fast_switches();
        let t0 = ktime::now_ns();
        let target = recv_target(s_ep, s_reply);
        let (hs, ts) = spawn(
            &server,
            &raw const user_ipc_server,
            [target, VOLTAS, DATA_VA],
            1,
        )?;
        let (hc, tc) = spawn(
            &client,
            &raw const user_ipc_client,
            [u64::from(c_ep.raw()), VOLTAS, DATA_VA],
            1,
        )?;
        run_until_exit(&[Arc::clone(&ts), Arc::clone(&tc)])?;
        let ns = ktime::now_ns() - t0;
        let fast = fast_switches() - fast0;
        let [c_status, c_count] = user_words::<2>(&client, DATA_VA, None)?;
        let [s_status, s_count] = user_words::<2>(&server, DATA_VA, None)?;
        info!(
            "ktest: · {c_count} idas e voltas em {} µs ({} ns cada), {fast} trocas diretas",
            ns / 1000,
            ns / VOLTAS
        );
        ensure!(c_status == STATUS_OK && s_status == STATUS_OK);
        ensure!(c_count == VOLTAS && s_count == VOLTAS);
        // Cada volta tem duas trocas (chamada e resposta); só a primeira
        // chamada e a última resposta podem não ser diretas.
        ensure!(fast + 2 >= 2 * VOLTAS);
        drop((ts, tc));
        delete(&client, &[hc])?;
        delete(&server, &[hs])?;
    }
    ensure!(quota.used() == used0);
    Ok(())
}

/// Transferência de capability: com `GRANT` o servidor recebe uma cópia
/// do mesmo objeto, com os mesmos direitos; sem, o envio é recusado com
/// `AccessDenied` e nada é anexado.
fn transferencia() -> Outcome {
    for grant in [true, false] {
        let (client, server) = (process(2)?, process(2)?);
        let (ep_h, ep) = create(&client, ObjectType::Endpoint)?;
        let mask = if grant {
            Rights::SEND | Rights::GRANT
        } else {
            Rights::SEND
        };
        let c_ep = client
            .cspace
            .lock()
            .mint(ep_h, mask, Some(BADGE))
            .map_err(|_| "mint")?;
        let (ntfy_h, ntfy) = create(&client, ObjectType::Notification)?;
        let signal = client
            .cspace
            .lock()
            .mint(ntfy_h, Rights::SIGNAL, None)
            .map_err(|_| "mint")?;
        let s_ep = give(&server, &ep, Rights::RECV, 0)?;
        let (s_reply, _) = create(&server, ObjectType::Reply)?;
        let target = recv_target(s_ep, s_reply);
        let mut handles = Vec::new();
        let mut threads = Vec::new();
        let (h, t) = spawn(&server, &raw const user_ipc_recv, [target, 0, DATA_VA], 1)?;
        handles.push((h, true));
        threads.push(t);
        let args = [u64::from(c_ep.raw()), u64::from(signal.raw()), DATA_VA];
        let (h, t) = spawn(&client, &raw const user_ipc_send_cap, args, 1)?;
        handles.push((h, false));
        threads.push(t);
        let before = server.cspace.lock().len();
        run_until_exit(&threads)?;
        let [first, second] = user_words::<2>(&client, DATA_VA + 16, None)?;
        let [status, badge, label, info, got] = user_words::<5>(&server, DATA_VA + 16, None)?;
        let info = MsgInfo::try_from(info).map_err(|_| "info")?;
        info!(
            "ktest: · GRANT {grant}: envio {:?}, servidor recebeu rótulo {label:#x} com {} capability(ies)",
            Error::try_from(first).ok(),
            info.caps
        );
        ensure!(status == STATUS_OK && badge == BADGE);
        if grant {
            ensure!(first == STATUS_OK && label == 0x11 && info.caps == 1);
            let h = Handle::from_raw(u32::try_from(got).map_err(|_| "handle")?);
            let s = server.cspace.lock();
            let cap = s.get(h).map_err(|_| "capability recebida")?;
            ensure!(cap.object.same(&ntfy) && cap.rights == Rights::SIGNAL);
            ensure!(s.len() == before + 1);
            drop(s);
            // A cópia é filha da original (ADR 0028): `cap_revoke` no
            // cliente a apaga no servidor.
            let revoke = [u64::from(ntfy_h.raw()), 0, 0, 0, 0, 0];
            let space = &client.cspace;
            let revoked = sys::invoke(space, Syscall::CapRevoke, revoke, 4, &mut KernelEnv);
            info!("ktest: · cap_revoke no cliente: {revoked:?}");
            ensure!(revoked.is_ok());
            ensure!(server.cspace.lock().get(h).err() == Some(Error::InvalidHandle));
            ensure!(server.cspace.lock().len() == before);
        } else {
            ensure!(first == Error::AccessDenied.to_raw() && second == STATUS_OK);
            ensure!(label == 0x12 && info.caps == 0);
            ensure!(server.cspace.lock().len() == before);
        }
        drop(threads);
        for (h, in_server) in handles {
            delete(if in_server { &server } else { &client }, &[h])?;
        }
    }
    Ok(())
}

/// `ipc_recv` com prazo de 2 ms sem remetente volta com `TimedOut`.
fn prazo() -> Outcome {
    let server = process(2)?;
    let (ep_h, _) = create(&server, ObjectType::Endpoint)?;
    let (reply, _) = create(&server, ObjectType::Reply)?;
    let t0 = ktime::now_ns();
    let args = [recv_target(ep_h, reply), 2_000_000, DATA_VA];
    let (h, t) = spawn(&server, &raw const user_ipc_recv, args, 1)?;
    run_until_exit(&[Arc::clone(&t)])?;
    let ns = ktime::now_ns() - t0;
    let [status] = user_words::<1>(&server, DATA_VA + 16, None)?;
    info!(
        "ktest: · ipc_recv com prazo de 2 ms voltou em {} µs",
        ns / 1000
    );
    ensure!(status == Error::TimedOut.to_raw());
    ensure!(ns >= 2_000_000);
    drop(t);
    delete(&server, &[h])?;
    Ok(())
}

/// Roda as prontas até `t` bloquear.
pub(crate) fn run_until_blocked(t: &Thread) -> Outcome {
    for _ in 0..1000 {
        if t.state() == RunState::Blocked {
            return Ok(());
        }
        yield_now();
    }
    Err("a thread não bloqueou")
}

/// Quem espera num endpoint ou num `Reply` cuja última capability some
/// acorda com `PeerClosed`, em vez de esperar para sempre.
fn peer_closed() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        // Receptor esperando; o endpoint é apagado.
        let server = process(1)?;
        let (ep_h, ep) = create(&server, ObjectType::Endpoint)?;
        let (reply, _) = create(&server, ObjectType::Reply)?;
        drop(ep);
        let args = [recv_target(ep_h, reply), 0, DATA_VA];
        let (h, t) = spawn(&server, &raw const user_ipc_recv, args, 0)?;
        run_until_blocked(&t)?;
        delete(&server, &[ep_h])?;
        run_until_exit(&[Arc::clone(&t)])?;
        let [recv_status] = user_words::<1>(&server, DATA_VA + 16, None)?;
        drop(t);
        delete(&server, &[h])?;
        // Quem chamou espera a resposta; o servidor recebe, termina sem
        // responder e o Reply é apagado.
        let (client, server) = (process(1)?, process(1)?);
        let (ep_h, ep) = create(&server, ObjectType::Endpoint)?;
        let (reply, _) = create(&server, ObjectType::Reply)?;
        let c_ep = give(&client, &ep, Rights::SEND, BADGE)?;
        drop(ep);
        let args = [recv_target(ep_h, reply), 0, DATA_VA];
        let (hs, ts) = spawn(&server, &raw const user_ipc_recv, args, 0)?;
        let args = [u64::from(c_ep.raw()), 1, DATA_VA];
        let (hc, tc) = spawn(&client, &raw const user_ipc_client, args, 0)?;
        run_until_exit(&[Arc::clone(&ts)])?;
        run_until_blocked(&tc)?;
        delete(&server, &[reply])?;
        run_until_exit(&[Arc::clone(&tc)])?;
        let [call_status] = user_words::<1>(&client, DATA_VA, None)?;
        info!(
            "ktest: · ipc_recv: {:?}; ipc_call: {:?}",
            Error::try_from(recv_status).ok(),
            Error::try_from(call_status).ok()
        );
        ensure!(recv_status == Error::PeerClosed.to_raw());
        ensure!(call_status == Error::PeerClosed.to_raw());
        drop((ts, tc));
        delete(&server, &[hs])?;
        delete(&client, &[hc])?;
    }
    ensure!(quota.used() == used0);
    Ok(())
}
