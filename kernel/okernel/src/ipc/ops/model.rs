//! As invariantes de `docs/spec/tla/Ipc.tla` conferidas sobre a
//! implementação: 3 clientes (só `c1` com `GRANT`) e 2 servidores num
//! endpoint, como em `Ipc.cfg`, em execuções aleatórias reprodutíveis. A
//! cada passo, uma thread pronta faz a próxima operação do seu papel (ou
//! termina a espera, se alguém a acordou), e o estado é conferido contra
//! `NoDoubleQueue`, `NoMissedRendezvous`, `CallerBlocked`, `ReplyOnce` e
//! `GrantRequired`. No fim, sem novas chamadas, toda chamada é respondida
//! (`CallAnswered`).

use alloc::sync::Arc;
use alloc::vec::Vec;

use kabi::ipc::{MsgInfo, recv_target};
use kabi::{Error, Handle, ObjectType, Rights, Syscall};

use super::tests::{Fake, Proc, regs};
use super::{Regs, Step, finish};
use crate::cap::{MemoryQuota, Object, obj_create};
use crate::thread::Thread;

/// Operação em andamento de uma thread bloqueada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Send,
    Call,
    Recv,
}

struct Actor {
    proc: Proc,
    client: bool,
    granted: bool,
    /// Handle do endpoint (cliente) ou `recv_target` (servidor).
    target: u64,
    /// Cliente: capability a transferir. Servidor: o `Reply`.
    extra: Handle,
    reply: Option<Object>,
    /// Bloqueada nessa operação.
    waiting: Option<Op>,
    /// Acordada, falta `finish`.
    woken: bool,
    /// Respostas recebidas na chamada atual.
    answers: u32,
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

fn setup(quota: &Arc<MemoryQuota>) -> (Object, Vec<Actor>) {
    let ep = obj_create(quota, ObjectType::Endpoint, 0).unwrap();
    let mut actors = Vec::new();
    for i in 0..3u64 {
        let proc = Proc::new(quota);
        let granted = i == 0;
        let rights = if granted {
            Rights::SEND | Rights::GRANT
        } else {
            Rights::SEND
        };
        let target = u64::from(proc.give(&ep, rights, i + 1).raw());
        let ntfy = obj_create(quota, ObjectType::Notification, 0).unwrap();
        let extra = proc.give(&ntfy, Rights::SIGNAL, 0);
        actors.push(Actor {
            proc,
            client: true,
            granted,
            target,
            extra,
            reply: None,
            waiting: None,
            woken: false,
            answers: 0,
        });
    }
    for _ in 0..2 {
        let proc = Proc::new(quota);
        let reply = obj_create(quota, ObjectType::Reply, 0).unwrap();
        let r = proc.give(&reply, Rights::SEND, 0);
        let target = recv_target(proc.give(&ep, Rights::RECV, 0), r);
        actors.push(Actor {
            proc,
            client: false,
            granted: false,
            target,
            extra: r,
            reply: Some(reply),
            waiting: None,
            woken: false,
            answers: 0,
        });
    }
    (ep, actors)
}

fn same(a: &Arc<Thread>, b: &Arc<Thread>) -> bool {
    Arc::ptr_eq(a, b)
}

/// Confere as invariantes da spec no estado atual.
fn check(ep: &Object, actors: &[Actor]) {
    let (senders, receivers) = ep.as_endpoint().unwrap().snapshot();
    // NoMissedRendezvous.
    assert!(senders.is_empty() || receivers.is_empty());
    for a in actors {
        let t = &a.proc.thread;
        let in_s = senders.iter().filter(|s| same(s, t)).count();
        let in_r = receivers.iter().filter(|r| same(r, t)).count();
        let slot = t.ipc().lock();
        // NoDoubleQueue: no máximo uma vez, numa fila, exatamente quando
        // o estado diz.
        assert!(in_s + in_r <= 1);
        assert_eq!(in_s == 1, slot.sending());
        assert_eq!(in_r == 1, slot.receiving());
        if a.client {
            // CallerBlocked: espera resposta <=> um servidor guarda o Reply.
            let holders = actors
                .iter()
                .filter_map(|s| s.reply.as_ref())
                .filter(|r| r.as_reply().unwrap().holds(t))
                .count();
            assert_eq!(slot.awaiting_reply(), holders == 1);
            assert!(holders <= 1);
            // ReplyOnce.
            assert!(a.answers <= 1);
        }
    }
}

/// Recebeu uma mensagem: só `c1` (com `GRANT`) transfere capability.
fn received(a: &Actor, out: &super::Out) {
    let info = MsgInfo::try_from(out.info).unwrap();
    if info.caps > 0 {
        assert_eq!(out.badge, 1, "GrantRequired");
    }
    assert!(!a.client);
}

/// Um passo da thread `i`; falso se ela não pôde andar.
fn step(i: usize, actors: &mut [Actor], env: &mut Fake, rng: &mut Rng, calls: bool) -> bool {
    let a = &mut actors[i];
    if a.waiting.is_some() && !a.woken {
        return false;
    }
    if let Some(op) = a.waiting.take() {
        a.woken = false;
        let out = finish(&a.proc.thread);
        match op {
            Op::Call => {
                assert!(out.is_ok());
                a.answers += 1;
            }
            Op::Send => assert!(out.is_ok()),
            Op::Recv => received(a, &out.unwrap()),
        }
        return true;
    }
    let (call, regs) = if a.client {
        if !calls {
            return false;
        }
        a.answers = 0;
        let cap = rng.pick(2) == 0;
        let call = if rng.pick(2) == 0 {
            Syscall::IpcCall
        } else {
            Syscall::IpcSend
        };
        let mut r = regs(a.target, 0, &[]);
        if cap {
            env.buffer(&a.proc.thread)[0] = u64::from(a.extra.raw());
            r.info = MsgInfo {
                caps: 1,
                ..MsgInfo::default()
            }
            .to_raw();
        }
        (call, r)
    } else {
        let pending = a.reply.as_ref().unwrap().as_reply().unwrap().pending();
        match (pending, rng.pick(3)) {
            (true, 0) => (Syscall::IpcRecv, regs(a.target, 0, &[])),
            (true, 1) => (Syscall::IpcSend, regs(u64::from(a.extra.raw()), 0, &[])),
            _ => (Syscall::IpcReplyRecv, regs(a.target, 0, &[])),
        }
    };
    let result = a.proc.begin(env, call, &regs);
    let wants_cap = MsgInfo::try_from(regs.info).unwrap().caps > 0;
    match (call, result) {
        (Syscall::IpcRecv, Err(e)) => assert_eq!(e, Error::Busy),
        (_, Err(e)) => {
            assert!(a.client && wants_cap && !a.granted);
            assert_eq!(e, Error::AccessDenied);
        }
        (_, Ok(Step::Done(out))) => {
            if matches!(call, Syscall::IpcRecv | Syscall::IpcReplyRecv) {
                received(a, &out);
            }
        }
        (_, Ok(Step::Block { handoff, .. })) => {
            // A troca direta do caminho rápido acorda a outra thread.
            env.handoffs.extend(handoff);
            a.waiting = Some(match call {
                Syscall::IpcCall => Op::Call,
                Syscall::IpcSend => Op::Send,
                _ => Op::Recv,
            });
        }
    }
    true
}

/// Marca como acordadas as threads que o ambiente acordou desde `seen`.
fn collect_wakes(actors: &mut [Actor], env: &Fake, seen: &mut (usize, usize)) {
    let fresh = env.woken[seen.0..].iter().chain(&env.handoffs[seen.1..]);
    for t in fresh {
        let a = actors.iter_mut().find(|a| same(&a.proc.thread, t)).unwrap();
        // Ninguém é acordado duas vezes nem sem estar esperando.
        assert!(a.waiting.is_some() && !a.woken, "despertar indevido");
        assert!(matches!(
            a.proc.thread.ipc().lock().blocked,
            crate::ipc::Blocked::None
        ));
        a.woken = true;
    }
    *seen = (env.woken.len(), env.handoffs.len());
}

fn run(seed: u64, steps: usize) {
    let quota = MemoryQuota::root(256 << 20);
    let (ep, mut actors) = setup(&quota);
    let mut env = Fake::default();
    let mut rng = Rng(seed);
    let mut cursor = (0, 0);
    let n = actors.len();
    for _ in 0..steps {
        let i = rng.pick(n);
        step(i, &mut actors, &mut env, &mut rng, true);
        collect_wakes(&mut actors, &env, &mut cursor);
        check(&ep, &actors);
    }
    // CallAnswered: sem chamadas novas, os servidores esvaziam tudo.
    let mut progressed = true;
    while progressed {
        progressed = false;
        for i in 0..n {
            progressed |= step(i, &mut actors, &mut env, &mut rng, false);
            collect_wakes(&mut actors, &env, &mut cursor);
            check(&ep, &actors);
        }
    }
    for a in actors.iter().filter(|a| a.client) {
        assert_eq!(a.waiting, None, "chamada sem resposta (semente {seed})");
    }
    let (s, _) = ep.as_endpoint().unwrap().queued();
    assert_eq!(s, 0);
}

#[test]
fn invariantes_da_spec_ipc() {
    for seed in 1..=300u64 {
        run(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), 400);
    }
}

#[test]
fn regs_de_teste_validos() {
    let r: Regs = regs(1, 2, &[3]);
    assert_eq!(MsgInfo::try_from(r.info).unwrap().words, 1);
}
