//! Testes de ciclo de vida (T-348; ADR 0035): eventos de morte de thread e
//! de processo, encerramento (`cap_delete` com `DESTROY` e `EXIT_GROUP`) e
//! o limite de threads.
//!
//! Os processos filhos não carregam ELF: rodam trechos de código de máquina
//! escritos à mão numa página de código compartilhada ([`Code`]), mapeada
//! só para execução no espaço de cada filho, com uma página de dados zerada
//! (a palavra do futex). Cada trecho recebe o que precisa em `rdi`.

use alloc::vec::Vec;

use ostd::cap::{self, Death, create, delete, mint};
use ostd::kabi::exit::{CAUSE_EXITED, CAUSE_FAULTED, CAUSE_KILLED};
use ostd::kabi::sched::CpuMask;
use ostd::kabi::vm::{EXEC, PAGE_SIZE, WRITE};
use ostd::kabi::{Error, Handle, ObjectType, Rights, Syscall};
use ostd::sys::syscall;
use ostd::thread;
use ostd::vm::{self, Mapping, SELF};

use crate::{Ctx, Outcome, child_quota, quota_pages};

/// Onde o código e os dados ficam no espaço de cada filho.
const CODE_VA: u64 = 0x40_0000;
const DATA_VA: u64 = 0x50_0000;
/// Onde o `utest` mapeia a página de código para escrevê-la.
const SCRATCH_VA: u64 = 0x7200_0000;

/// Os trechos, com o deslocamento de cada um na página.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stub {
    /// `thread_exit(rdi, 0)`.
    Exit = 0x00,
    /// `thread_exit(rdi, EXIT_GROUP)`.
    ExitGroup = 0x10,
    /// Gira para sempre sem entrar no kernel.
    Spin = 0x20,
    /// `ud2`: falta fatal (vetor 6).
    Fault = 0x30,
    /// `ntfy_wait(rdi)` em laço.
    NtfyWait = 0x40,
    /// `futex_wait(rdi, 0)` em laço.
    FutexWait = 0x50,
    /// `ipc_call(rdi)` (mensagem vazia, sem prazo) em laço.
    IpcCall = 0x60,
}

/// Código de máquina de cada trecho.
const STUBS: &[(Stub, &[u8])] = &[
    // xor esi, esi; mov eax, 33; syscall; ud2
    (
        Stub::Exit,
        &[0x31, 0xF6, 0xB8, 0x21, 0, 0, 0, 0x0F, 0x05, 0x0F, 0x0B],
    ),
    // mov esi, 1; mov eax, 33; syscall; ud2
    (
        Stub::ExitGroup,
        &[
            0xBE, 1, 0, 0, 0, 0xB8, 0x21, 0, 0, 0, 0x0F, 0x05, 0x0F, 0x0B,
        ],
    ),
    // jmp $
    (Stub::Spin, &[0xEB, 0xFE]),
    // ud2
    (Stub::Fault, &[0x0F, 0x0B]),
    // 1: mov eax, 23; syscall; jmp 1b
    (
        Stub::NtfyWait,
        &[0xB8, 0x17, 0, 0, 0, 0x0F, 0x05, 0xEB, 0xF7],
    ),
    // 1: xor esi, esi; mov eax, 29; syscall; jmp 1b
    (
        Stub::FutexWait,
        &[0x31, 0xF6, 0xB8, 0x1D, 0, 0, 0, 0x0F, 0x05, 0xEB, 0xF5],
    ),
    // 1: mov eax, 20; syscall; jmp 1b
    (
        Stub::IpcCall,
        &[0xB8, 0x14, 0, 0, 0, 0x0F, 0x05, 0xEB, 0xF7],
    ),
];

/// A página de código e a de dados, para mapear nos filhos.
struct Code {
    code: Handle,
    data: Handle,
}

impl Code {
    fn new(ctx: &Ctx) -> Result<Self, &'static str> {
        const _: () = assert!(Syscall::ThreadExit as u32 == 0x21);
        const _: () = assert!(Syscall::NtfyWait as u32 == 0x17);
        const _: () = assert!(Syscall::FutexWait as u32 == 0x1D);
        const _: () = assert!(Syscall::IpcCall as u32 == 0x14);
        let code = create(ctx.quota, ObjectType::MemoryObject, PAGE_SIZE).map_err(|_| "código")?;
        let data = create(ctx.quota, ObjectType::MemoryObject, PAGE_SIZE).map_err(|_| "dados")?;
        let this = Self { code, data };
        let mut map =
            Mapping::new(SELF, code, SCRATCH_VA, PAGE_SIZE, WRITE).map_err(|_| "vm_map")?;
        let bytes = map.bytes_mut().ok_or("não gravável")?;
        for &(stub, text) in STUBS {
            let at = stub as usize;
            bytes[at..at + text.len()].copy_from_slice(text);
        }
        Ok(this)
    }
}

impl Drop for Code {
    fn drop(&mut self) {
        let _ = (delete(self.code), delete(self.data));
    }
}

/// Um processo filho: a tabela (com `DESTROY`), uma cópia sem `DESTROY`
/// para ler o registro e ligar o evento, o espaço e as threads.
struct Kid {
    cspace: Option<Handle>,
    watch: Handle,
    aspace: Handle,
    threads: Vec<Handle>,
}

impl Kid {
    /// Tabela e espaço novos, com o código e os dados mapeados; `limit` é o
    /// limite de threads vivas (0 = sem).
    fn new(q: Handle, code: &Code, limit: u64) -> Result<Self, &'static str> {
        let cspace = create(q, ObjectType::CapSpace, limit).map_err(|_| "create(cspace)")?;
        let watch = mint(cspace, Rights::MANAGE | Rights::BIND, 0, None).map_err(|_| "mint")?;
        let aspace = create(q, ObjectType::AddressSpace, 0).map_err(|_| "create(aspace)")?;
        let kid = Self {
            cspace: Some(cspace),
            watch,
            aspace,
            threads: Vec::new(),
        };
        vm::map(aspace, code.code, CODE_VA, 0, PAGE_SIZE, EXEC).map_err(|_| "map(código)")?;
        vm::map(aspace, code.data, DATA_VA, 0, PAGE_SIZE, WRITE).map_err(|_| "map(dados)")?;
        Ok(kid)
    }

    /// Copia `h` para a tabela do filho com `rights`.
    fn give(&self, h: Handle, rights: Rights) -> Result<Handle, &'static str> {
        mint(h, rights, 0, Some(self.watch)).map_err(|_| "mint no filho")
    }

    /// Cria uma thread do filho (sem iniciar) em `stub`; com `cpu`, só roda
    /// nela.
    fn thread(&mut self, q: Handle, cpu: Option<usize>) -> Result<Handle, &'static str> {
        let t = create(q, ObjectType::Thread, 0).map_err(|_| "create(thread)")?;
        self.threads.push(t);
        let sc = create(q, ObjectType::SchedContext, 0).map_err(|_| "create(sc)")?;
        let period = 1_000_000;
        let prio = thread::DEFAULT_PRIORITY;
        let configured = match cpu {
            Some(c) => thread::sched_configure_on(sc, period, period, prio, &CpuMask::only(c)),
            None => thread::sched_configure(sc, period, period, prio),
        };
        let bound = configured.and_then(|()| thread::sched_bind(sc, t));
        let _ = delete(sc);
        bound.map_err(|_| "sched")?;
        let cs = self.cspace.ok_or("processo encerrado")?;
        thread::bind(t, cs, self.aspace).map_err(|_| "thread_configure")?;
        Ok(t)
    }

    /// Cria e inicia uma thread em `stub` com `arg` em `rdi`.
    fn run(
        &mut self,
        q: Handle,
        stub: Stub,
        arg: u64,
        cpu: Option<usize>,
    ) -> Result<Handle, &'static str> {
        let t = self.thread(q, cpu)?;
        start(t, stub, arg).map_err(|_| "thread_start")?;
        Ok(t)
    }

    /// `cap_delete(DESTROY)` da tabela.
    fn destroy(&mut self) -> Outcome {
        let cs = self.cspace.take().ok_or("já encerrado")?;
        cap::destroy(cs).map_err(|_| "DESTROY do processo")
    }
}

impl Drop for Kid {
    fn drop(&mut self) {
        for &t in &self.threads {
            let _ = delete(t);
        }
        if let Some(cs) = self.cspace {
            let _ = delete(cs);
        }
        let _ = (delete(self.watch), delete(self.aspace));
    }
}

fn start(t: Handle, stub: Stub, arg: u64) -> Result<(), Error> {
    let rsp = DATA_VA + PAGE_SIZE - 8;
    thread::start(t, CODE_VA + stub as u64, rsp, [arg, 0, 0])
}

/// Registro de morte de `h`, ou zeros enquanto vive.
fn death(h: Handle) -> Result<(u8, u64), &'static str> {
    let d = cap::death(h).map_err(|_| "sys_info(2)")?;
    Ok(d.map_or((0, 0), |Death { cause, code, .. }| (cause, code)))
}

fn ntfy_wait(n: Handle) -> Result<u64, &'static str> {
    syscall(Syscall::NtfyWait, [u64::from(n.raw()), 0, 0, 0, 0, 0])
        .map(|[bits, ..]| bits)
        .map_err(|_| "ntfy_wait")
}

fn ntfy_poll(n: Handle) -> Result<u64, &'static str> {
    syscall(Syscall::NtfyPoll, [u64::from(n.raw()), 0, 0, 0, 0, 0])
        .map(|[bits, ..]| bits)
        .map_err(|_| "ntfy_poll")
}

/// Cede a vez por uns `ms` milissegundos (para os filhos rodarem e
/// bloquearem).
fn settle(ms: u64) {
    let until = ostd::time::now_ns() + ms * 1_000_000;
    while ostd::time::now_ns() < until {
        thread::yield_now();
    }
}

/// Outra CPU ligada para os filhos girarem, se houver.
fn other_cpu() -> Option<usize> {
    let (online, _) = thread::cpus().ok()?;
    (online > 1).then_some(1)
}

/// Espera até todos os bits de `want` chegarem em `n`; a cada despertar
/// confere `check` com o que chegou até ali.
fn collect(n: Handle, want: u64, mut check: impl FnMut(u64) -> Outcome) -> Outcome {
    let mut got = 0;
    while got & want != want {
        got |= ntfy_wait(n)?;
        check(got)?;
    }
    if got & !want != 0 {
        return Err("evento a mais");
    }
    Ok(())
}

/// Cem processos criados e encerrados, em lotes de 20, sem perder evento
/// (critério de aceite da T-348). Cada um morre de um jeito: saída normal,
/// `EXIT_GROUP` com outra thread girando, `DESTROY` com threads girando
/// (uma noutra CPU, se houver), falta fatal e `DESTROY` com a thread
/// bloqueada numa notificação, num futex ou em `ipc_call`. Confere o evento
/// de cada thread e de cada processo (o do processo só depois dos das
/// threads dele), o registro de morte e que a cota volta inteira.
pub fn cem_processos(ctx: &Ctx) -> Outcome {
    const BATCH: usize = 20;
    let code = Code::new(ctx)?;
    let q = child_quota(ctx, 8 << 20)?;
    let before = quota_pages(q)?;
    let result = (|| {
        let ev = create(ctx.quota, ObjectType::Notification, 0).map_err(|_| "ntfy")?;
        let wait_on = create(ctx.quota, ObjectType::Notification, 0).map_err(|_| "ntfy")?;
        let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "endpoint")?;
        let outcome = (|| {
            for round in 0..100 / BATCH {
                lote(q, &code, round, BATCH, ev, wait_on, ep)?;
            }
            Ok(())
        })();
        let _ = (delete(ev), delete(wait_on), delete(ep));
        outcome
    })();
    let back = back_to(q, before);
    let _ = delete(q);
    result?;
    back
}

/// A cota `q` volta a cobrir `before` páginas (os objetos do kernel voltam
/// quando a última referência some, logo depois da morte).
fn back_to(q: Handle, before: usize) -> Outcome {
    for _ in 0..10_000 {
        if quota_pages(q)? == before {
            return Ok(());
        }
        thread::yield_now();
    }
    Err("a cota não voltou ao que era depois de os processos morrerem")
}

#[allow(clippy::too_many_lines, reason = "um lote, tipo a tipo")]
fn lote(
    q: Handle,
    code: &Code,
    round: usize,
    batch: usize,
    ev: Handle,
    wait_on: Handle,
    ep: Handle,
) -> Outcome {
    let far = other_cpu();
    let mut kids = Vec::new();
    // Bits: processo i em i; as threads dele em 20 + 2i e 21 + 2i.
    let mut want = 0u64;
    for i in 0..batch {
        let mut kid = Kid::new(q, code, 0)?;
        let pbit = 1u64 << i;
        cap::bind_notify(kid.watch, ev, pbit).map_err(|_| "bind(processo)")?;
        want |= pbit;
        let code_i = (round * batch + i) as u64;
        let how = (round * batch + i) % 7;
        let plan: &[(Stub, u64, Option<usize>)] = match how {
            0 => &[(Stub::Exit, code_i, None)],
            1 => &[(Stub::Spin, 0, far), (Stub::ExitGroup, code_i, None)],
            2 => &[(Stub::Spin, 0, None), (Stub::Spin, 0, far)],
            3 => &[(Stub::Fault, 0, None)],
            4 => &[(Stub::NtfyWait, 0, None)],
            5 => &[(Stub::FutexWait, DATA_VA, None)],
            _ => &[(Stub::IpcCall, 0, None)],
        };
        let arg_for = |stub: Stub, arg: u64, kid: &Kid| -> Result<u64, &'static str> {
            Ok(match stub {
                Stub::NtfyWait => u64::from(kid.give(wait_on, Rights::WAIT)?.raw()),
                Stub::IpcCall => u64::from(kid.give(ep, Rights::SEND)?.raw()),
                _ => arg,
            })
        };
        // Cria todas antes de iniciar: a primeira pode encerrar o processo.
        let mut ready = Vec::new();
        for (j, &(stub, arg, cpu)) in plan.iter().enumerate() {
            let t = kid.thread(q, cpu)?;
            let tbit = 1u64 << (20 + 2 * i + j);
            cap::bind_notify(t, ev, tbit).map_err(|_| "bind(thread)")?;
            want |= tbit;
            ready.push((t, stub, arg_for(stub, arg, &kid)?));
        }
        for (t, stub, arg) in ready {
            start(t, stub, arg).map_err(|_| "thread_start")?;
        }
        kids.push((kid, how, code_i));
    }
    // Dá tempo para girarem e bloquearem; então encerra os que não morrem
    // sozinhos.
    settle(2);
    for (kid, how, _) in &mut kids {
        if matches!(how, 2 | 4 | 5 | 6) {
            kid.destroy()?;
        }
    }
    collect(ev, want, |got| {
        // O evento do processo só depois dos das threads dele.
        for (i, (kid, ..)) in kids.iter().enumerate() {
            let threads = ((1u64 << kid.threads.len()) - 1) << (20 + 2 * i);
            if got & (1 << i) != 0 && got & threads != threads {
                return Err("evento do processo antes do de uma thread dele");
            }
        }
        Ok(())
    })?;
    for (kid, how, code_i) in &kids {
        let (pcause, pcode) = death(kid.watch)?;
        let threads: Vec<(u8, u64)> = kid
            .threads
            .iter()
            .map(|&t| death(t))
            .collect::<Result<_, _>>()?;
        let ok = match how {
            0 => (pcause, pcode) == (CAUSE_EXITED, *code_i) && threads == [(CAUSE_EXITED, *code_i)],
            1 => {
                (pcause, pcode) == (CAUSE_EXITED, *code_i)
                    && threads == [(CAUSE_KILLED, 0), (CAUSE_EXITED, *code_i)]
            }
            2 => pcause == CAUSE_KILLED && threads == [(CAUSE_KILLED, 0); 2],
            3 => (pcause, pcode) == (CAUSE_FAULTED, 6) && threads == [(CAUSE_FAULTED, 6)],
            _ => pcause == CAUSE_KILLED && threads == [(CAUSE_KILLED, 0)],
        };
        if !ok {
            return Err("registro de morte errado");
        }
    }
    // Ligar depois da morte sinaliza já, tanto processo quanto thread.
    let (kid, ..) = &kids[0];
    cap::bind_notify(kid.watch, ev, 1 << 62).map_err(|_| "religar processo")?;
    cap::bind_notify(kid.threads[0], ev, 1 << 63).map_err(|_| "religar thread")?;
    if ntfy_poll(ev)? != 3 << 62 {
        return Err("ligar depois da morte devia sinalizar já");
    }
    Ok(())
}

/// O encerramento de quem espera em `ipc_call` (ADR 0035, item 4): o
/// servidor recebeu a chamada; encerrado o processo do cliente, a resposta
/// é recusada (`PeerClosed`, `Reply` sem chamador) e o servidor segue. Um
/// `Endpoint` destruído responde `PeerClosed` a quem tem cópia dele.
pub fn encerrado_em_ipc_call(ctx: &Ctx) -> Outcome {
    let code = Code::new(ctx)?;
    let q = child_quota(ctx, 1 << 20)?;
    let ev = create(ctx.quota, ObjectType::Notification, 0).map_err(|_| "ntfy")?;
    let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "endpoint")?;
    let reply = create(ctx.quota, ObjectType::Reply, 0).map_err(|_| "reply")?;
    let result = (|| {
        let mut kid = Kid::new(q, &code, 0)?;
        cap::bind_notify(kid.watch, ev, 1).map_err(|_| "bind")?;
        let their_ep = kid.give(ep, Rights::SEND)?;
        let t = kid.run(q, Stub::IpcCall, u64::from(their_ep.raw()), None)?;
        let deadline = ostd::time::now_ns() + 5_000_000_000;
        ostd::ipc::recv(ep, reply, deadline).map_err(|_| "a chamada não chegou")?;
        kid.destroy()?;
        if ntfy_wait(ev)? != 1 {
            return Err("evento do processo");
        }
        if death(t)? != (CAUSE_KILLED, 0) {
            return Err("a thread devia morrer Killed");
        }
        let answer = ostd::ipc::send(reply, &ostd::ipc::Message::new(9, &[]), 0);
        if answer != Err(Error::PeerClosed) {
            return Err("responder a um chamador encerrado devia dar PeerClosed");
        }
        // O servidor segue: o endpoint ainda atende (sem ninguém, TimedOut).
        if ostd::ipc::recv(ep, reply, 1) != Err(Error::TimedOut) {
            return Err("o servidor devia seguir atendendo");
        }
        // DESTROY do endpoint: a cópia que sobra recebe PeerClosed.
        let copy = mint(ep, Rights::SEND | Rights::RECV, 0, None).map_err(|_| "mint")?;
        cap::destroy(ep).map_err(|_| "DESTROY do endpoint")?;
        let got = ostd::ipc::recv(copy, reply, 1);
        let _ = delete(copy);
        if got != Err(Error::PeerClosed) {
            return Err("endpoint destruído devia dar PeerClosed");
        }
        Ok(())
    })();
    let _ = (delete(ev), delete(ep), delete(reply), delete(q));
    result
}

/// O limite de threads vivas do `CapSpace` (ADR 0035, item 5), a recusa de
/// iniciar thread num processo encerrado e as recusas de `obj_bind_notify`
/// e de `cap_delete`.
pub fn limite_e_recusas(ctx: &Ctx) -> Outcome {
    let code = Code::new(ctx)?;
    let q = child_quota(ctx, 1 << 20)?;
    let ev = create(ctx.quota, ObjectType::Notification, 0).map_err(|_| "ntfy")?;
    let result = (|| {
        let mut kid = Kid::new(q, &code, 2)?;
        let a = kid.run(q, Stub::Spin, 0, None)?;
        let _b = kid.run(q, Stub::Spin, 0, None)?;
        let c = kid.thread(q, None)?;
        if start(c, Stub::Spin, 0) != Err(Error::QuotaExceeded) {
            return Err("a terceira thread devia passar do limite");
        }
        // Uma morre: a terceira cabe. A thread encerrada por DESTROY dela.
        let a_copy = mint(
            a,
            Rights::READ_STATE | Rights::BIND | Rights::DESTROY,
            0,
            None,
        )
        .map_err(|_| "mint")?;
        cap::bind_notify(a_copy, ev, 1).map_err(|_| "bind")?;
        cap::destroy(a_copy).map_err(|_| "DESTROY da thread")?;
        if ntfy_wait(ev)? != 1 || death(a)? != (CAUSE_KILLED, 0) {
            return Err("a thread encerrada devia morrer Killed");
        }
        // A contagem desce na morte, vista pelo evento.
        start(c, Stub::Spin, 0).map_err(|_| "a terceira devia caber agora")?;
        // Recusas: a3 não zero, objeto sem evento, flags desconhecidas,
        // DESTROY sem o direito ou de tipo sem encerramento.
        let bind_a3 = syscall(
            Syscall::ObjBindNotify,
            [u64::from(kid.watch.raw()), u64::from(ev.raw()), 1, 1, 0, 0],
        );
        if bind_a3.map(drop) != Err(Error::InvalidArgument) {
            return Err("obj_bind_notify com a3 devia dar InvalidArgument");
        }
        if cap::bind_notify(ev, ev, 1) != Err(Error::AccessDenied) {
            return Err("notificação não tem BIND");
        }
        let del = |h: Handle, flags| {
            syscall(Syscall::CapDelete, [u64::from(h.raw()), flags, 0, 0, 0, 0]).map(drop)
        };
        if del(c, 2) != Err(Error::InvalidArgument) {
            return Err("cap_delete com flag desconhecida devia dar InvalidArgument");
        }
        if cap::destroy(kid.watch) != Err(Error::AccessDenied) {
            return Err("DESTROY sem o direito devia dar AccessDenied");
        }
        if cap::destroy(ev) != Err(Error::NotSupported) {
            return Err("DESTROY de notificação devia dar NotSupported");
        }
        // Desligar (bits = 0): o fim do processo não sinaliza ev.
        cap::bind_notify(kid.watch, ev, 2).map_err(|_| "bind")?;
        cap::bind_notify(kid.watch, ev, 0).map_err(|_| "desligar")?;
        kid.destroy()?;
        for _ in 0..10_000 {
            if kid
                .threads
                .iter()
                .all(|&t| death(t).is_ok_and(|(c, _)| c != 0))
            {
                break;
            }
            thread::yield_now();
        }
        if death(kid.watch)? != (CAUSE_KILLED, 0) {
            return Err("o processo devia morrer Killed");
        }
        if ntfy_poll(ev)? != 0 {
            return Err("desligado não devia sinalizar");
        }
        Ok(())
    })();
    let _ = (delete(ev), delete(q));
    result
}

/// `join` de uma thread encerrada por outra, bloqueada ou girando, devolve
/// `Killed`; o evento ligado pelo `handle` também chega; e uma thread
/// iniciada num processo encerrado é recusada com `PeerClosed`.
pub fn join_de_encerradas(ctx: &Ctx) -> Outcome {
    use ostd::sync::{Condvar, Mutex};
    let ev = create(ctx.quota, ObjectType::Notification, 0).map_err(|_| "ntfy")?;
    let result = (|| {
        let spinner = thread::spawn(|| {
            loop {
                core::hint::spin_loop();
            }
        });
        let gate = alloc::sync::Arc::new((Mutex::new(false), Condvar::new()));
        let theirs = alloc::sync::Arc::clone(&gate);
        let sleeper = thread::spawn(move || {
            let (m, cv) = &*theirs;
            let mut g = m.lock();
            while !*g {
                g = cv.wait(g);
            }
            7u64
        });
        cap::bind_notify(sleeper.handle(), ev, 1 << 5).map_err(|_| "bind")?;
        settle(2);
        spinner.kill().map_err(|_| "kill(girando)")?;
        sleeper.kill().map_err(|_| "kill(bloqueada)")?;
        if ntfy_wait(ev)? != 1 << 5 {
            return Err("o evento ligado pelo handle devia chegar");
        }
        let killed = |d: Result<u64, Death>| d.err().map(|d| (d.cause, d.code));
        if killed(spinner.join_status()) != Some((CAUSE_KILLED, 0)) {
            return Err("join da que girava devia dar Killed");
        }
        if killed(sleeper.join_status()) != Some((CAUSE_KILLED, 0)) {
            return Err("join da bloqueada devia dar Killed");
        }
        // Encerrar duas vezes, ou depois da morte: nada muda.
        Ok(())
    })();
    let _ = delete(ev);
    result
}

/// Uma thread largada sem `join` devolve a região quando morre: a cota
/// filha volta inteira depois de outra `spawn` recolher as órfãs.
pub fn largada_devolve_regiao(ctx: &Ctx) -> Outcome {
    use core::sync::atomic::{AtomicBool, Ordering};
    static GO: AtomicBool = AtomicBool::new(false);
    let q = child_quota(ctx, 1 << 20)?;
    let before = quota_pages(q)?;
    let result = (|| {
        GO.store(false, Ordering::SeqCst);
        let h = thread::Builder::new()
            .quota(q)
            .spawn(|| {
                while !GO.load(Ordering::SeqCst) {
                    thread::yield_now();
                }
            })
            .map_err(|_| "spawn")?;
        drop(h);
        GO.store(true, Ordering::SeqCst);
        settle(1);
        // `join` de outra recolhe as órfãs mortas.
        let other = thread::Builder::new()
            .quota(q)
            .spawn(|| 1u64)
            .map_err(|_| "spawn")?;
        if other.join() != Ok(1) {
            return Err("join");
        }
        back_to(q, before)
    })();
    let _ = delete(q);
    result
}

/// `EXIT_GROUP` com flag desconhecida é recusado antes de encerrar nada; a
/// thread segue.
pub fn exit_recusa_flags(_: &Ctx) -> Outcome {
    let group_unknown = syscall(
        Syscall::ThreadExit,
        [0, ostd::kabi::exit::GROUP | 2, 0, 0, 0, 0],
    );
    if group_unknown.map(drop) != Err(Error::InvalidArgument) {
        return Err("EXIT_GROUP com flag desconhecida devia dar InvalidArgument");
    }
    if syscall(Syscall::ThreadExit, [0, 2, 0, 0, 0, 0]).map(drop) != Err(Error::InvalidArgument) {
        return Err("flag desconhecida devia dar InvalidArgument");
    }
    Ok(())
}

/// Uma thread nova num processo encerrado é recusada (`PeerClosed`).
pub fn partida_em_processo_encerrado(ctx: &Ctx) -> Outcome {
    let code = Code::new(ctx)?;
    let q = child_quota(ctx, 1 << 20)?;
    let result = (|| {
        let mut kid = Kid::new(q, &code, 0)?;
        let alive = kid.run(q, Stub::Spin, 0, None)?;
        let late = kid.thread(q, None)?;
        kid.destroy()?;
        if start(late, Stub::Spin, 0) != Err(Error::PeerClosed) {
            return Err("thread_start num processo encerrado devia dar PeerClosed");
        }
        for _ in 0..10_000 {
            if death(alive)?.0 != 0 {
                break;
            }
            thread::yield_now();
        }
        if death(alive)? != (CAUSE_KILLED, 0) || death(kid.watch)? != (CAUSE_KILLED, 0) {
            return Err("encerrados deviam morrer Killed");
        }
        Ok(())
    })();
    let _ = delete(q);
    result
}
