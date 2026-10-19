//! Testes no host do caminho rápido: o mesmo estado que o caminho comum
//! deixaria, e nada mudado quando ele recusa.

use alloc::sync::Arc;

use kabi::ipc::{FLAG_NONBLOCK, MsgInfo};
use kabi::{Rights, Syscall};

use super::{Fast, call, reply_recv};
use crate::ipc::ops::tests::{Fake, World, bind_sc, regs, runs_on, world};
use crate::ipc::ops::{Out, Regs, Step, finish};
use crate::sched::SchedContext;

/// Mundo com o servidor esperando em `ipc_recv` e `SchedContext`s ligados
/// (cliente 200, servidor 10).
fn waiting() -> (World, Arc<SchedContext>, Arc<SchedContext>) {
    let w = world(Rights::SEND);
    let c_sc = bind_sc(&w.quota, &w.client.thread, 200);
    let s_sc = bind_sc(&w.quota, &w.server.thread, 10);
    let mut env = Fake::default();
    let recv = regs(w.s_target, 0, &[]);
    assert!(matches!(
        w.server.begin(&mut env, Syscall::IpcRecv, &recv),
        Ok(Step::Block { .. })
    ));
    (w, c_sc, s_sc)
}

fn switched_to(f: Fast, to: &World, server: bool) -> bool {
    let t = if server {
        &to.server.thread
    } else {
        &to.client.thread
    };
    matches!(f, Fast::Switch(x) if Arc::ptr_eq(&x, t))
}

/// O que se vê de um mundo depois de uma operação.
#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "um campo por fato comparado")]
struct Seen {
    server_got: Option<Out>,
    client_got: Option<Out>,
    awaiting: bool,
    receiving: bool,
    queued: (usize, usize),
    pending: bool,
    server_on_client_sc: bool,
}

fn seen(w: &World, c_sc: &Arc<SchedContext>) -> Seen {
    let reply = w
        .server
        .space
        .lock()
        .get(kabi::Handle::from_raw((w.s_target >> 32) as u32))
        .unwrap()
        .object
        .clone();
    Seen {
        server_got: finish(&w.server.thread).ok(),
        client_got: finish(&w.client.thread).ok(),
        awaiting: w.client.thread.ipc().lock().awaiting_reply(),
        receiving: w.server.thread.ipc().lock().receiving(),
        queued: w.ep.as_endpoint().unwrap().queued(),
        pending: reply.as_reply().unwrap().pending(),
        server_on_client_sc: runs_on(&w.server.thread, c_sc),
    }
}

#[test]
fn ida_e_volta_deixa_o_mesmo_estado_que_o_caminho_comum() {
    let (slow, slow_c, slow_s) = waiting();
    let (fast, fast_c, fast_s) = waiting();
    let mut env = Fake::default();
    let call_regs = regs(slow.c_ep, 0xAB, &[1, 2, 3, 4, 5, 6]);
    let Ok(Step::Block {
        handoff: Some(to), ..
    }) = slow.client.begin(&mut env, Syscall::IpcCall, &call_regs)
    else {
        panic!("o caminho comum troca direto para o servidor");
    };
    assert!(Arc::ptr_eq(&to, &slow.server.thread));
    let f = call(&fast.client.space, &fast.client.thread, &call_regs, 0);
    assert!(switched_to(f, &fast, true));
    assert_eq!(seen(&fast, &fast_c), seen(&slow, &slow_c));
    assert!(runs_on(&fast.server.thread, &fast_c));
    assert_eq!(finish(&fast.server.thread).unwrap().badge, 7);

    let answer = regs(slow.s_target, 0xCD, &[9]);
    let Ok(Step::Block {
        handoff: Some(to), ..
    }) = slow.server.begin(&mut env, Syscall::IpcReplyRecv, &answer)
    else {
        panic!("o caminho comum troca direto para quem chamou");
    };
    assert!(Arc::ptr_eq(&to, &slow.client.thread));
    let f = reply_recv(
        &fast.server.space,
        &fast.server.thread,
        &answer,
        0,
        &mut env,
    );
    assert!(switched_to(f, &fast, false));
    assert_eq!(seen(&fast, &fast_c), seen(&slow, &slow_c));
    assert!(runs_on(&fast.server.thread, &fast_s));
    assert!(runs_on(&slow.server.thread, &slow_s));
    let back = finish(&fast.client.thread).unwrap();
    assert_eq!(
        (back.badge, back.label, back.words),
        (0, 0xCD, [9, 0, 0, 0, 0, 0])
    );
    assert!(env.woken.is_empty() && env.preempts == 0);
}

/// `call` recusa `regs` e nada muda.
fn refuses_call(w: &World, regs: &Regs) {
    let before = w.ep.as_endpoint().unwrap().queued();
    let f = call(&w.client.space, &w.client.thread, regs, 0);
    assert!(matches!(f, Fast::Slow), "{regs:?}");
    assert_eq!(w.ep.as_endpoint().unwrap().queued(), before);
    assert!(!w.client.thread.ipc().lock().awaiting_reply());
    assert_eq!(
        w.server.thread.ipc().lock().receiving(),
        before.1 == 1,
        "o servidor segue na fila"
    );
}

#[test]
fn chamada_fora_das_condicoes_vai_pelo_caminho_comum() {
    let (w, _, _) = waiting();
    let base = regs(w.c_ep, 1, &[2]);
    for regs in [
        Regs {
            deadline: 5,
            ..base
        },
        Regs {
            info: MsgInfo {
                caps: 1,
                ..MsgInfo::words(1)
            }
            .to_raw(),
            ..base
        },
        Regs {
            info: MsgInfo {
                flags: FLAG_NONBLOCK,
                ..MsgInfo::words(1)
            }
            .to_raw(),
            ..base
        },
        Regs {
            info: MsgInfo {
                buffer_words: 3,
                ..MsgInfo::words(1)
            }
            .to_raw(),
            ..base
        },
        Regs { info: 7, ..base },
        Regs {
            target: 0x7777,
            ..base
        },
        Regs {
            target: u64::MAX,
            ..base
        },
    ] {
        refuses_call(&w, &regs);
    }
    // Servidor de outra CPU (o caminho comum o traz) ou ainda saindo dela.
    w.server.thread.set_cpu(1);
    refuses_call(&w, &base);
    w.server.thread.set_cpu(0);
    w.server.thread.set_on_cpu(true);
    refuses_call(&w, &base);
    w.server.thread.set_on_cpu(false);
    // Na CPU 1 o servidor (da CPU 0) também não serve.
    assert!(matches!(
        call(&w.client.space, &w.client.thread, &base, 1),
        Fast::Slow
    ));
    // Sem `SEND` na capability.
    let w2 = world(Rights::GRANT);
    let mut env = Fake::default();
    let recv = regs(w2.s_target, 0, &[]);
    assert!(w2.server.begin(&mut env, Syscall::IpcRecv, &recv).is_ok());
    refuses_call(&w2, &regs(w2.c_ep, 1, &[]));
    // Sem ninguém esperando: o caminho comum põe quem chama na fila.
    let w3 = world(Rights::SEND);
    refuses_call(&w3, &regs(w3.c_ep, 1, &[]));
    // E pelo caminho rápido dá certo depois de tudo isso.
    let f = call(&w.client.space, &w.client.thread, &base, 0);
    assert!(switched_to(f, &w, true));
}

#[test]
fn resposta_fora_das_condicoes_vai_pelo_caminho_comum() {
    let (w, _, _) = waiting();
    let mut env = Fake::default();
    let answer = regs(w.s_target, 3, &[4]);
    // Sem chamada pendente (o primeiro `ipc_recv` do servidor).
    w.server.thread.ipc().lock().blocked = crate::ipc::Blocked::None;
    w.ep.as_endpoint().unwrap().remove(&w.server.thread);
    assert!(matches!(
        reply_recv(&w.server.space, &w.server.thread, &answer, 0, &mut env),
        Fast::Slow
    ));
    let recv = regs(w.s_target, 0, &[]);
    assert!(w.server.begin(&mut env, Syscall::IpcRecv, &recv).is_ok());
    let f = call(&w.client.space, &w.client.thread, &regs(w.c_ep, 1, &[]), 0);
    assert!(switched_to(f, &w, true));
    let refuses = |env: &mut Fake, regs: &Regs| {
        let f = reply_recv(&w.server.space, &w.server.thread, regs, 0, env);
        assert!(matches!(f, Fast::Slow), "{regs:?}");
        assert!(
            w.client.thread.ipc().lock().awaiting_reply(),
            "sem resposta"
        );
    };
    refuses(
        &mut env,
        &Regs {
            deadline: 9,
            ..answer
        },
    );
    refuses(
        &mut env,
        &Regs {
            info: MsgInfo {
                caps: 1,
                ..MsgInfo::words(1)
            }
            .to_raw(),
            ..answer
        },
    );
    // Endpoint e `Reply` trocados no alvo.
    refuses(
        &mut env,
        &Regs {
            target: w.s_target.rotate_left(32),
            ..answer
        },
    );
    // Quem chamou está noutra CPU: o despertar comum o acorda lá.
    w.client.thread.set_cpu(1);
    refuses(&mut env, &answer);
    w.client.thread.set_cpu(0);
    // Outro cliente na fila de envio: o servidor recebe dele sem esperar.
    let other = crate::ipc::ops::tests::Proc::new(&w.quota);
    let h = other.give(&w.ep, Rights::SEND, 9);
    let send = regs(u64::from(h.raw()), 5, &[]);
    assert!(other.begin(&mut env, Syscall::IpcCall, &send).is_ok());
    refuses(&mut env, &answer);
    assert!(env.woken.is_empty());
}
