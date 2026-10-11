//! Testes no host da entrega de faltas de usuário.

use alloc::sync::Arc;

use kabi::fault::{PAGE_FAULT, WORDS};
use kabi::ipc::{MsgInfo, recv_target};
use kabi::{Error, Handle, ObjectType, Rights, Syscall};

use super::{Fault, Kill, handle};
use crate::cap::{MemoryQuota, Object, obj_create};
use crate::ipc::ops::finish;
use crate::ipc::ops::tests::{Fake, Proc, regs};
use crate::sys::Env;
use crate::thread::Thread;

const FALTA: Fault = Fault {
    vector: PAGE_FAULT,
    error: 4,
    addr: 0,
    rip: 0x40_0010,
    rsp: 0x50_1000,
    rflags: 0x202,
};

/// Ambiente que, quando a thread que faltou cede a CPU, faz o tratador
/// responder com `answer` (ou não responder, com `None`).
struct Tratador {
    fake: Fake,
    server: Proc,
    reply: Handle,
    answer: Option<u64>,
}

impl Tratador {
    fn respond(&mut self) {
        let Some(label) = self.answer else { return };
        let me = self.fake.current.replace(Arc::clone(&self.server.thread));
        let send = regs(u64::from(self.reply.raw()), label, &[]);
        let done = self.server.begin(&mut self.fake, Syscall::IpcSend, &send);
        assert!(done.is_ok(), "a resposta chega a quem faltou");
        self.fake.current = me;
    }
}

impl Env for Tratador {
    fn preempt(&mut self) {
        self.fake.preempt();
    }
    fn wake(&mut self, thread: Arc<Thread>, value: u64) {
        self.fake.wake(thread, value);
    }
    fn current(&self) -> Option<Arc<Thread>> {
        self.fake.current()
    }
    fn block(&mut self) {
        self.respond();
    }
    fn read_u32(&mut self, addr: u64) -> Option<u32> {
        self.fake.read_u32(addr)
    }
    fn now(&self) -> u64 {
        self.fake.now()
    }
    fn block_until(&mut self, _deadline: u64) {
        self.respond();
    }
    fn handoff(&mut self, to: Arc<Thread>, _deadline: u64) {
        self.fake.handoffs.push(to);
        self.respond();
    }
    fn read_buffer(&mut self, thread: &Thread, at: usize, out: &mut [u64]) -> bool {
        self.fake.read_buffer(thread, at, out)
    }
    fn write_buffer(&mut self, thread: &Thread, at: usize, data: &[u64]) -> bool {
        self.fake.write_buffer(thread, at, data)
    }
}

/// Quem falta (com o endpoint de exceções com `rights` e badge 0xFA) e o
/// tratador, já esperando no endpoint.
fn cenario(rights: Rights, answer: Option<u64>) -> (Proc, Tratador, Object) {
    let quota = MemoryQuota::root(64 << 20);
    let ep = obj_create(&quota, ObjectType::Endpoint, 0).unwrap();
    let reply = obj_create(&quota, ObjectType::Reply, 0).unwrap();
    let (faulty, server) = (Proc::new(&quota), Proc::new(&quota));
    let h = faulty.give(&ep, rights, 0xFA);
    faulty.thread.set_exception_handler(h);
    let s_ep = server.give(&ep, Rights::RECV, 0);
    let s_reply = server.give(&reply, Rights::SEND, 0);
    let mut env = Fake::default();
    let recv = regs(recv_target(s_ep, s_reply), 0, &[]);
    assert!(server.begin(&mut env, Syscall::IpcRecv, &recv).is_ok());
    env.current = Some(Arc::clone(&faulty.thread));
    let t = Tratador {
        fake: env,
        server,
        reply: s_reply,
        answer,
    };
    (faulty, t, ep)
}

#[test]
fn sem_endpoint_a_thread_e_encerrada() {
    let quota = MemoryQuota::root(64 << 20);
    let p = Proc::new(&quota);
    let mut env = Fake {
        current: Some(Arc::clone(&p.thread)),
        ..Fake::default()
    };
    assert_eq!(handle(&p.thread, &FALTA, &mut env), Err(Kill::NoHandler));
    // Handle que não resolve, ou capability que não é de endpoint.
    p.thread.set_exception_handler(Handle::new(9, 0).unwrap());
    let got = handle(&p.thread, &FALTA, &mut env);
    assert_eq!(got, Err(Kill::BadHandler(Error::InvalidHandle)));
    let ntfy = obj_create(&quota, ObjectType::Notification, 0).unwrap();
    p.thread
        .set_exception_handler(p.give(&ntfy, Rights::SIGNAL, 0));
    let got = handle(&p.thread, &FALTA, &mut env);
    assert_eq!(got, Err(Kill::BadHandler(Error::WrongType)));
}

#[test]
fn tratador_recebe_a_falta_e_retoma_a_thread() {
    let (faulty, mut env, _ep) = cenario(Rights::SEND, Some(0));
    assert_eq!(handle(&faulty.thread, &FALTA, &mut env), Ok(()));
    let got = finish(&env.server.thread).unwrap();
    assert_eq!((got.badge, got.label), (0xFA, PAGE_FAULT));
    assert_eq!(got.info, MsgInfo::words(WORDS).to_raw());
    assert_eq!(got.words, [4, 0, 0x40_0010, 0x50_1000, 0x202, 0]);
    // Só registradores: troca direta para o tratador.
    assert!(Arc::ptr_eq(&env.fake.handoffs[0], &env.server.thread));
}

#[test]
fn recusa_ou_falta_de_resposta_encerram() {
    let (faulty, mut env, _ep) = cenario(Rights::SEND, Some(1));
    assert_eq!(
        handle(&faulty.thread, &FALTA, &mut env),
        Err(Kill::Refused(1))
    );
    let (faulty, mut env, _ep) = cenario(Rights::RECV, Some(0));
    let got = handle(&faulty.thread, &FALTA, &mut env);
    assert_eq!(got, Err(Kill::BadHandler(Error::AccessDenied)));
    // Ninguém responde: a espera termina sem resposta (no kernel, com
    // `PeerClosed` quando o endpoint ou o `Reply` morre).
    let (faulty, mut env, _ep) = cenario(Rights::SEND, None);
    let got = handle(&faulty.thread, &FALTA, &mut env);
    assert!(matches!(got, Err(Kill::Unanswered(_))));
}
