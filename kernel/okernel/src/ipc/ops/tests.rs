//! Testes no host das primitivas de IPC.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use std::collections::HashMap;

use kabi::ipc::{FLAG_NONBLOCK, IpcBuffer, MsgInfo, recv_target};
use kabi::{Error, Handle, ObjectType, Rights, Syscall};

use super::{Out, Regs, Step, begin, finish};
use crate::cap::space::Revoke;
use crate::cap::{
    Cap, CapSpace, MemoryQuota, Object, SharedCapSpace, default_rights, obj_create, xcdt,
};
use crate::sched::{Params, SchedContext};
use crate::sync::SpinLock;
use crate::sys::Env;
use crate::thread::Thread;
use crate::vm::AddressSpace;
use crate::vm::tests::platform;

/// Onde as threads de teste têm o buffer de IPC.
pub const BUFFER_VA: u64 = 0x50_0000;

/// Ambiente falso: relógio, buffers de IPC em memória e registro de quem
/// foi acordado.
#[derive(Default)]
pub struct Fake {
    pub current: Option<Arc<Thread>>,
    pub now: u64,
    pub woken: Vec<Arc<Thread>>,
    pub handoffs: Vec<Arc<Thread>>,
    pub blocks: Vec<u64>,
    pub preempts: u32,
    /// Buffers por thread (endereço do objeto), 512 palavras.
    pub buffers: HashMap<usize, Vec<u64>>,
}

impl Fake {
    /// Buffer de `t`, criado zerado se faltar.
    pub fn buffer(&mut self, t: &Thread) -> &mut Vec<u64> {
        let key = core::ptr::from_ref(t).addr();
        self.buffers.entry(key).or_insert_with(|| vec![0; 512])
    }
}

impl Env for Fake {
    fn preempt(&mut self) {
        self.preempts += 1;
    }
    fn wake(&mut self, thread: Arc<Thread>, _value: u64) {
        self.woken.push(thread);
    }
    fn current(&self) -> Option<Arc<Thread>> {
        self.current.clone()
    }
    fn block(&mut self) {}
    fn read_u32(&mut self, _addr: u64) -> Option<u32> {
        None
    }
    fn now(&self) -> u64 {
        self.now
    }
    fn block_until(&mut self, deadline: u64) {
        self.blocks.push(deadline);
    }
    fn handoff(&mut self, to: Arc<Thread>, deadline: u64) {
        self.handoffs.push(to);
        self.blocks.push(deadline);
    }
    fn read_buffer(&mut self, t: &Thread, at: usize, out: &mut [u64]) -> bool {
        if t.ipc_buffer().is_none() {
            return false;
        }
        out.copy_from_slice(&self.buffer(t)[at..at + out.len()]);
        true
    }
    fn write_buffer(&mut self, t: &Thread, at: usize, data: &[u64]) -> bool {
        if t.ipc_buffer().is_none() {
            return false;
        }
        self.buffer(t)[at..at + data.len()].copy_from_slice(data);
        true
    }
}

/// Um processo de uma thread, com `CapSpace` e buffer de IPC próprios.
pub struct Proc {
    pub space: Arc<SharedCapSpace>,
    pub thread: Arc<Thread>,
}

impl Proc {
    pub fn new(quota: &Arc<MemoryQuota>) -> Self {
        let p = platform(1000).1;
        let space = Arc::new(SpinLock::new(CapSpace::new(quota).unwrap()));
        let aspace = Arc::new(SpinLock::new(AddressSpace::new(quota, p).unwrap()));
        let thread = Arc::new(Thread::new(quota, p).unwrap());
        thread.configure(Arc::clone(&space), aspace).unwrap();
        thread.set_ipc_buffer(BUFFER_VA).unwrap();
        Self { space, thread }
    }

    /// Guarda uma capability de `object` com `rights` e `badge`.
    pub fn give(&self, object: &Object, rights: Rights, badge: u64) -> Handle {
        self.space
            .lock()
            .insert(Cap {
                object: object.clone(),
                rights,
                badge,
            })
            .unwrap()
    }

    /// `begin` como thread atual de `env`.
    pub fn begin(&self, env: &mut Fake, call: Syscall, regs: &Regs) -> Result<Step, Error> {
        env.current = Some(Arc::clone(&self.thread));
        begin(&self.space, call, regs, env)
    }
}

pub fn regs(target: u64, label: u64, words: &[u64]) -> Regs {
    let mut w = [0; 6];
    w[..words.len()].copy_from_slice(words);
    Regs {
        target,
        label,
        info: MsgInfo::words(u8::try_from(words.len()).unwrap()).to_raw(),
        deadline: 0,
        words: w,
    }
}

pub fn raw(h: Handle) -> u64 {
    u64::from(h.raw())
}

fn blocked(step: &Result<Step, Error>) -> bool {
    matches!(step, Ok(Step::Block { .. }))
}

pub struct World {
    pub quota: Arc<MemoryQuota>,
    pub ep: Object,
    pub client: Proc,
    pub server: Proc,
    /// Handles do endpoint no cliente (SEND, badge 7) e no servidor.
    pub c_ep: u64,
    pub s_target: u64,
}

pub fn world(client_rights: Rights) -> World {
    let quota = MemoryQuota::root(64 << 20);
    let ep = obj_create(&quota, ObjectType::Endpoint, 0).unwrap();
    let reply = obj_create(&quota, ObjectType::Reply, 0).unwrap();
    let (client, server) = (Proc::new(&quota), Proc::new(&quota));
    let c_ep = raw(client.give(&ep, client_rights, 7));
    let s_ep = server.give(&ep, default_rights(ObjectType::Endpoint), 0);
    let s_reply = server.give(&reply, Rights::SEND, 0);
    World {
        s_target: recv_target(s_ep, s_reply),
        quota,
        ep,
        client,
        server,
        c_ep,
    }
}

#[test]
fn call_encontra_o_servidor_e_a_resposta_volta_pelo_caminho_rapido() {
    let w = world(Rights::SEND);
    let mut env = Fake::default();
    let r = regs(w.s_target, 0, &[]);
    assert!(blocked(&w.server.begin(&mut env, Syscall::IpcRecv, &r)));
    let call = regs(w.c_ep, 0xAB, &[1, 2, 3, 4, 5, 6]);
    let Ok(Step::Block {
        handoff, follow, ..
    }) = w.client.begin(&mut env, Syscall::IpcCall, &call)
    else {
        panic!("a chamada bloqueia esperando a resposta");
    };
    assert!(Arc::ptr_eq(&handoff.unwrap(), &w.server.thread));
    assert!(follow, "o servidor segue quem chama para a CPU dele");
    let got = finish(&w.server.thread).unwrap();
    assert_eq!(
        got,
        Out {
            badge: 7,
            label: 0xAB,
            info: MsgInfo::words(6).to_raw(),
            words: [1, 2, 3, 4, 5, 6],
        }
    );
    assert!(w.client.thread.ipc().lock().awaiting_reply());
    // Resposta com reply_recv: o servidor volta a esperar e cede a CPU
    // direto ao cliente.
    let answer = regs(w.s_target, 0xCD, &[9]);
    let Ok(Step::Block {
        handoff, follow, ..
    }) = w.server.begin(&mut env, Syscall::IpcReplyRecv, &answer)
    else {
        panic!("sem outro remetente, o servidor espera");
    };
    assert!(Arc::ptr_eq(&handoff.unwrap(), &w.client.thread));
    assert!(!follow, "a resposta não move quem chamou");
    let back = finish(&w.client.thread).unwrap();
    assert_eq!((back.badge, back.label, back.words[0]), (0, 0xCD, 9));
    assert_eq!(back.words[1..], [0; 5], "palavras não declaradas zeradas");
    assert_eq!(w.ep.as_endpoint().unwrap().queued(), (0, 1));
}

#[test]
fn chamada_espera_na_fila_e_resposta_e_de_uso_unico() {
    let w = world(Rights::SEND);
    let mut env = Fake::default();
    let call = regs(w.c_ep, 1, &[42]);
    assert!(blocked(&w.client.begin(&mut env, Syscall::IpcCall, &call)));
    assert_eq!(w.ep.as_endpoint().unwrap().queued(), (1, 0));
    let Ok(Step::Done(got)) = w
        .server
        .begin(&mut env, Syscall::IpcRecv, &regs(w.s_target, 0, &[]))
    else {
        panic!("havia remetente");
    };
    assert_eq!((got.badge, got.label, got.words[0]), (7, 1, 42));
    assert!(env.woken.is_empty(), "quem chamou espera a resposta");
    // Com o Reply pendente, ipc_recv é recusado (a spec proíbe).
    assert_eq!(
        w.server
            .begin(&mut env, Syscall::IpcRecv, &regs(w.s_target, 0, &[]))
            .unwrap_err(),
        Error::Busy
    );
    let reply_h = (w.s_target >> 32) & 0xffff_ffff;
    let send = regs(reply_h, 2, &[43]);
    assert!(matches!(
        w.server.begin(&mut env, Syscall::IpcSend, &send),
        Ok(Step::Done(_))
    ));
    assert!(Arc::ptr_eq(&env.woken[0], &w.client.thread));
    assert_eq!(finish(&w.client.thread).unwrap().words[0], 43);
    assert_eq!(
        w.server
            .begin(&mut env, Syscall::IpcSend, &send)
            .unwrap_err(),
        Error::PeerClosed
    );
}

#[test]
fn envio_sem_bloqueio_prazo_e_direitos() {
    let w = world(Rights::SEND);
    let mut env = Fake {
        now: 1000,
        ..Fake::default()
    };
    let mut send = regs(w.c_ep, 5, &[]);
    send.info = MsgInfo {
        flags: FLAG_NONBLOCK,
        ..MsgInfo::default()
    }
    .to_raw();
    let nb = w.client.begin(&mut env, Syscall::IpcSend, &send);
    assert_eq!(nb.unwrap_err(), Error::WouldBlock);
    send.info = 0;
    send.deadline = 1000;
    let late = w.client.begin(&mut env, Syscall::IpcSend, &send);
    assert_eq!(late.unwrap_err(), Error::TimedOut);
    // Prazo futuro: bloqueia, e o cancelamento do prazo devolve TimedOut.
    send.deadline = 5000;
    let Ok(Step::Block { deadline, .. }) = w.client.begin(&mut env, Syscall::IpcSend, &send) else {
        panic!("sem receptor, bloqueia");
    };
    assert_eq!(deadline, 5000);
    assert!(super::super::cancel(&w.client.thread, Error::TimedOut));
    assert_eq!(finish(&w.client.thread).unwrap_err(), Error::TimedOut);
    assert_eq!(w.ep.as_endpoint().unwrap().queued(), (0, 0));
    // Direitos e tipos.
    let recv_only = raw(w.client.give(&w.ep, Rights::RECV, 0));
    let refused = w
        .client
        .begin(&mut env, Syscall::IpcSend, &regs(recv_only, 0, &[]));
    assert_eq!(refused.unwrap_err(), Error::AccessDenied);
    let not_recv = w
        .client
        .begin(&mut env, Syscall::IpcRecv, &regs(w.c_ep, 0, &[]));
    assert_eq!(not_recv.unwrap_err(), Error::AccessDenied);
    let bad_info = Regs {
        info: 7,
        ..regs(w.c_ep, 0, &[])
    };
    let bad = w.client.begin(&mut env, Syscall::IpcSend, &bad_info);
    assert_eq!(bad.unwrap_err(), Error::InvalidArgument);
    let q = w
        .client
        .give(&Object::MemoryQuota(Arc::clone(&w.quota)), Rights::SEND, 0);
    let wrong = w
        .client
        .begin(&mut env, Syscall::IpcCall, &regs(raw(q), 0, &[]));
    assert_eq!(wrong.unwrap_err(), Error::WrongType);
}

#[test]
fn envio_acorda_o_receptor_e_entrega_o_badge() {
    let w = world(Rights::SEND);
    let mut env = Fake::default();
    assert!(blocked(&w.server.begin(
        &mut env,
        Syscall::IpcRecv,
        &regs(w.s_target, 0, &[])
    )));
    let sent = w
        .client
        .begin(&mut env, Syscall::IpcSend, &regs(w.c_ep, 3, &[8, 9]));
    assert!(matches!(sent, Ok(Step::Done(_))));
    assert!(Arc::ptr_eq(&env.woken[0], &w.server.thread));
    assert_eq!(env.preempts, 1);
    let got = finish(&w.server.thread).unwrap();
    assert_eq!((got.badge, got.label, &got.words[..2]), (7, 3, &[8, 9][..]));
    // Envio que espera na fila é liberado pelo receptor.
    assert!(blocked(&w.client.begin(
        &mut env,
        Syscall::IpcSend,
        &regs(w.c_ep, 4, &[])
    )));
    let got = w
        .server
        .begin(&mut env, Syscall::IpcRecv, &regs(w.s_target, 0, &[]));
    assert!(matches!(got, Ok(Step::Done(Out { label: 4, .. }))));
    assert!(Arc::ptr_eq(&env.woken[1], &w.client.thread));
    assert!(finish(&w.client.thread).is_ok());
}

/// Põe `handles` no cabeçalho do buffer de `p`.
fn put_caps(env: &mut Fake, p: &Proc, handles: &[Handle]) {
    let mut raw = [0u32; 4];
    for (r, h) in raw.iter_mut().zip(handles) {
        *r = h.raw();
    }
    let buf = env.buffer(&p.thread);
    buf[0] = u64::from(raw[0]) | (u64::from(raw[1]) << 32);
    buf[1] = u64::from(raw[2]) | (u64::from(raw[3]) << 32);
}

fn with_caps(target: u64, caps: u8, buffer_words: u16) -> Regs {
    Regs {
        info: MsgInfo {
            caps,
            buffer_words,
            ..MsgInfo::words(1)
        }
        .to_raw(),
        ..regs(target, 0, &[1])
    }
}

#[test]
fn transferencia_de_capability_exige_grant() {
    for grant in [false, true] {
        let rights = if grant {
            Rights::SEND | Rights::GRANT
        } else {
            Rights::SEND
        };
        let w = world(rights);
        let mut env = Fake::default();
        let ntfy = obj_create(&w.quota, ObjectType::Notification, 0).unwrap();
        let mine = w.client.give(&ntfy, Rights::SIGNAL, 0x55);
        put_caps(&mut env, &w.client, &[mine]);
        env.buffer(&w.client.thread)[IpcBuffer::WORDS_OFFSET..][..3].copy_from_slice(&[7, 8, 9]);
        assert!(blocked(&w.server.begin(
            &mut env,
            Syscall::IpcRecv,
            &regs(w.s_target, 0, &[])
        )));
        let before = w.server.space.lock().len();
        let sent = w
            .client
            .begin(&mut env, Syscall::IpcSend, &with_caps(w.c_ep, 1, 3));
        if !grant {
            assert_eq!(sent.unwrap_err(), Error::AccessDenied);
            assert_eq!(w.server.space.lock().len(), before, "nada anexado");
            assert!(env.woken.is_empty());
            continue;
        }
        assert!(sent.is_ok());
        let info = MsgInfo::try_from(finish(&w.server.thread).unwrap().info).unwrap();
        assert_eq!((info.caps, info.buffer_words), (1, 3));
        let buf = env.buffer(&w.server.thread).clone();
        let got = Handle::from_raw(u32::try_from(buf[0] & 0xffff_ffff).unwrap());
        let s = w.server.space.lock();
        let cap = s.get(got).unwrap();
        assert!(cap.object.same(&ntfy));
        assert_eq!((cap.rights, cap.badge), (Rights::SIGNAL, 0x55));
        assert_eq!(buf[IpcBuffer::WORDS_OFFSET..][..3], [7, 8, 9]);
        drop(s);
        // A original continua com o remetente, e a cópia é filha dela
        // (ADR 0028): revogar a original apaga a cópia no servidor.
        assert!(w.client.space.lock().get(mine).is_ok());
        let root = w.client.give(&ntfy, Rights::ALL, 0);
        xcdt::delete(&w.client.space, mine).unwrap();
        let mine = xcdt::mint(&w.client.space, root, Rights::SIGNAL, Some(0x55)).unwrap();
        put_caps(&mut env, &w.client, &[mine]);
        let recv = regs(w.s_target, 0, &[]);
        assert!(blocked(&w.server.begin(&mut env, Syscall::IpcRecv, &recv)));
        let sent = w
            .client
            .begin(&mut env, Syscall::IpcSend, &with_caps(w.c_ep, 1, 0));
        assert!(sent.is_ok());
        let buf = env.buffer(&w.server.thread).clone();
        let copy = Handle::from_raw(u32::try_from(buf[0] & 0xffff_ffff).unwrap());
        assert!(w.server.space.lock().get(copy).is_ok());
        while xcdt::revoke(&w.client.space, root, 1).unwrap() == Revoke::Continue {}
        assert!(w.client.space.lock().get(mine).is_err());
        assert_eq!(
            w.server.space.lock().get(copy).unwrap_err(),
            Error::InvalidHandle
        );
        w.server.space.lock().check_invariants().unwrap();
    }
}

#[test]
fn handle_invalido_e_receptor_sem_buffer() {
    let w = world(Rights::SEND | Rights::GRANT);
    let mut env = Fake::default();
    put_caps(&mut env, &w.client, &[Handle::from_raw(0x99)]);
    let bad = w
        .client
        .begin(&mut env, Syscall::IpcSend, &with_caps(w.c_ep, 1, 0));
    assert_eq!(bad.unwrap_err(), Error::InvalidHandle);
    // Sem buffer, o receptor recebe só os registradores.
    let ntfy = obj_create(&w.quota, ObjectType::Notification, 0).unwrap();
    let mine = w.client.give(&ntfy, Rights::SIGNAL, 0);
    put_caps(&mut env, &w.client, &[mine]);
    w.server.thread.set_ipc_buffer(0).unwrap();
    let before = w.server.space.lock().len();
    assert!(blocked(&w.server.begin(
        &mut env,
        Syscall::IpcRecv,
        &regs(w.s_target, 0, &[])
    )));
    assert!(
        w.client
            .begin(&mut env, Syscall::IpcSend, &with_caps(w.c_ep, 1, 2))
            .is_ok()
    );
    let info = MsgInfo::try_from(finish(&w.server.thread).unwrap().info).unwrap();
    assert_eq!((info.words, info.caps, info.buffer_words), (1, 0, 0));
    assert_eq!(w.server.space.lock().len(), before);
    // Remetente sem buffer não manda capability.
    w.client.thread.set_ipc_buffer(0).unwrap();
    let none = w
        .client
        .begin(&mut env, Syscall::IpcSend, &with_caps(w.c_ep, 1, 0));
    assert_eq!(none.unwrap_err(), Error::InvalidArgument);
}

#[test]
fn resposta_com_capability_exige_grant_do_servidor() {
    for grant in [false, true] {
        let w = world(Rights::SEND);
        let mut env = Fake::default();
        // O servidor recebe por uma capability com ou sem GRANT.
        let rights = if grant {
            Rights::RECV | Rights::GRANT
        } else {
            Rights::RECV
        };
        let s_ep = w.server.give(&w.ep, rights, 0);
        let reply = obj_create(&w.quota, ObjectType::Reply, 0).unwrap();
        let s_reply = w.server.give(&reply, Rights::SEND, 0);
        let target = recv_target(s_ep, s_reply);
        assert!(blocked(&w.server.begin(
            &mut env,
            Syscall::IpcRecv,
            &regs(target, 0, &[])
        )));
        assert!(blocked(&w.client.begin(
            &mut env,
            Syscall::IpcCall,
            &regs(w.c_ep, 0, &[])
        )));
        let mo = obj_create(&w.quota, ObjectType::Notification, 0).unwrap();
        let h = w.server.give(&mo, Rights::WAIT, 0);
        put_caps(&mut env, &w.server, &[h]);
        let answer = with_caps(raw(s_reply), 1, 0);
        let sent = w.server.begin(&mut env, Syscall::IpcSend, &answer);
        if grant {
            assert!(sent.is_ok());
            let info = MsgInfo::try_from(finish(&w.client.thread).unwrap().info).unwrap();
            assert_eq!(info.caps, 1);
        } else {
            assert_eq!(sent.unwrap_err(), Error::AccessDenied);
            assert!(
                reply.as_reply().unwrap().pending(),
                "o Reply segue pendente"
            );
        }
    }
}

/// Apaga a capability de handle cru `h` (32 bits baixos) de `p`.
fn delete(p: &Proc, h: u64) {
    let h = Handle::from_raw(u32::try_from(h & 0xffff_ffff).unwrap());
    drop(p.space.lock().delete(h).unwrap());
}

#[test]
fn endpoint_destruido_acorda_quem_espera_com_peer_closed() {
    // Receptor na fila; some a última capability do endpoint.
    let w = world(Rights::SEND);
    let mut env = Fake::default();
    let recv = regs(w.s_target, 0, &[]);
    assert!(blocked(&w.server.begin(&mut env, Syscall::IpcRecv, &recv)));
    let World {
        ep,
        client,
        server,
        c_ep,
        s_target,
        ..
    } = w;
    drop(ep);
    delete(&client, c_ep);
    assert!(
        server.thread.ipc().lock().receiving(),
        "ainda há capability"
    );
    delete(&server, s_target);
    assert_eq!(finish(&server.thread), Err(Error::PeerClosed));
    assert!(!server.thread.ipc().lock().receiving());
    // Remetente na fila (chamada sem servidor) levando uma capability: ela
    // é solta com a mensagem.
    let w = world(Rights::SEND | Rights::GRANT);
    let ntfy = obj_create(&w.quota, ObjectType::Notification, 0).unwrap();
    let h = w.client.give(&ntfy, Rights::SIGNAL, 0);
    put_caps(&mut env, &w.client, &[h]);
    let call = with_caps(w.c_ep, 1, 0);
    assert!(blocked(&w.client.begin(&mut env, Syscall::IpcCall, &call)));
    let World {
        ep,
        client,
        server,
        c_ep,
        s_target,
        ..
    } = w;
    drop(ep);
    delete(&client, c_ep);
    delete(&server, s_target);
    assert_eq!(finish(&client.thread), Err(Error::PeerClosed));
    assert!(client.thread.ipc().lock().out.is_none());
    delete(&client, u64::from(h.raw()));
    assert_eq!(Arc::strong_count(ntfy.as_notification().unwrap()), 1);
}

#[test]
fn reply_destruido_acorda_quem_chamou_com_peer_closed() {
    let w = world(Rights::SEND);
    let mut env = Fake::default();
    let call = regs(w.c_ep, 1, &[42]);
    assert!(blocked(&w.client.begin(&mut env, Syscall::IpcCall, &call)));
    let recv = regs(w.s_target, 0, &[]);
    let got = w.server.begin(&mut env, Syscall::IpcRecv, &recv);
    assert!(matches!(got, Ok(Step::Done(_))));
    assert!(w.client.thread.ipc().lock().awaiting_reply());
    // O servidor apaga o Reply sem responder.
    delete(&w.server, w.s_target >> 32);
    assert_eq!(finish(&w.client.thread), Err(Error::PeerClosed));
    assert!(!w.client.thread.ipc().lock().awaiting_reply());
}

/// Liga a `t` um `SchedContext` novo com prioridade `priority`.
pub fn bind_sc(quota: &Arc<MemoryQuota>, t: &Thread, priority: u64) -> Arc<SchedContext> {
    let sc = obj_create(quota, ObjectType::SchedContext, 0).unwrap();
    let sc = Arc::clone(sc.as_sched_context().unwrap());
    sc.configure(Params::new(1_000_000, 1_000_000, priority).unwrap());
    t.bind_sched(Arc::clone(&sc)).unwrap();
    sc
}

pub fn runs_on(t: &Thread, sc: &Arc<SchedContext>) -> bool {
    t.sched_context().is_some_and(|s| Arc::ptr_eq(&s, sc))
}

#[test]
fn servidor_roda_com_o_schedcontext_de_quem_chama_ate_responder() {
    let w = world(Rights::SEND);
    let mut env = Fake::default();
    let c_sc = bind_sc(&w.quota, &w.client.thread, 200);
    let s_sc = bind_sc(&w.quota, &w.server.thread, 10);
    // Servidor esperando: a chamada doa ao entregar.
    let recv = regs(w.s_target, 0, &[]);
    assert!(blocked(&w.server.begin(&mut env, Syscall::IpcRecv, &recv)));
    let call = regs(w.c_ep, 1, &[]);
    assert!(blocked(&w.client.begin(&mut env, Syscall::IpcCall, &call)));
    assert!(runs_on(&w.server.thread, &c_sc));
    // A resposta devolve a doação.
    let answer = regs(w.s_target, 2, &[]);
    let replied = w.server.begin(&mut env, Syscall::IpcReplyRecv, &answer);
    assert!(blocked(&replied));
    assert!(runs_on(&w.server.thread, &s_sc));
    // Chamada já na fila: a doação vem ao receber, com um ponto de
    // preempção para o escalonador cobrar o SchedContext certo.
    w.server.thread.ipc().lock().blocked = crate::ipc::Blocked::None;
    w.ep.as_endpoint().unwrap().remove(&w.server.thread);
    assert!(blocked(&w.client.begin(&mut env, Syscall::IpcCall, &call)));
    let preempts = env.preempts;
    let got = w.server.begin(&mut env, Syscall::IpcRecv, &recv);
    assert!(matches!(got, Ok(Step::Done(_))));
    assert!(runs_on(&w.server.thread, &c_sc));
    assert_eq!(env.preempts, preempts + 1);
    // Prazo vencido de quem chamou também devolve a doação.
    assert!(crate::ipc::cancel(&w.client.thread, Error::TimedOut));
    assert!(runs_on(&w.server.thread, &s_sc));
    // E o Reply destruído.
    assert!(blocked(&w.client.begin(&mut env, Syscall::IpcCall, &call)));
    let got = w.server.begin(&mut env, Syscall::IpcRecv, &recv);
    assert!(matches!(got, Ok(Step::Done(_))));
    assert!(runs_on(&w.server.thread, &c_sc));
    delete(&w.server, w.s_target >> 32);
    assert!(runs_on(&w.server.thread, &s_sc));
    assert_eq!(finish(&w.client.thread), Err(Error::PeerClosed));
}
