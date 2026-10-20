//! `utest`: o harness de testes de usuário (T-332).
//!
//! Com `test=user` na linha de comando, o kernel inicia este serviço do
//! bootfs no lugar do `root`, com as mesmas capabilities iniciais: a cota
//! raiz em `rdi` e o próprio espaço em `rsi`. Ele roda cada teste de
//! [`TESTS`] no anel 3 e escreve o relatório na serial, no mesmo estilo do
//! `ktest` do kernel:
//!
//! ```text
//! utest: início, N testes
//! utest: ok nome
//! utest: FALHOU nome: motivo
//! utest: fim: P ok, F falharam
//! ```
//!
//! O `cargo xtask test user` confere esse relatório (e só passa com
//! `0 falharam`). Para provar que uma falha derruba o comando sem deixar
//! um teste quebrado na suíte, o teste [`proposital`] só existe se o
//! `utest` for compilado com `UTEST_FALHA=1` (`cargo xtask test user
//! --falha-proposital`).
//!
//! Para acrescentar um teste, escreva uma `fn(&Ctx) -> Result<(), &'static
//! str>` e a ponha em [`TESTS`].

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::cap::{create, delete};
use ostd::ipc::{self, Message};
use ostd::kabi::ipc::FLAG_NONBLOCK;
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;

ostd::entry!(main);

/// Capabilities iniciais que os testes podem usar.
struct Ctx {
    /// Cota raiz.
    quota: Handle,
}

/// Resultado de um teste: `Err` com o motivo da falha.
type Outcome = Result<(), &'static str>;

/// Um teste: nome (como aparece na serial) e função.
struct Test {
    name: &'static str,
    run: fn(&Ctx) -> Outcome,
}

/// Os testes, na ordem em que rodam.
const TESTS: &[Test] = &[
    Test {
        name: "cap.criar_e_apagar",
        run: criar_e_apagar,
    },
    Test {
        name: "ipc.sem_par",
        run: ipc_sem_par,
    },
    Test {
        name: "time.monotonico",
        run: monotonico,
    },
    #[cfg(utest_falha)]
    Test {
        name: "proposital",
        run: proposital,
    },
];

/// Criar um endpoint na cota e apagá-lo; apagar de novo é erro.
fn criar_e_apagar(ctx: &Ctx) -> Outcome {
    let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "create falhou")?;
    delete(ep).map_err(|_| "delete falhou")?;
    match delete(ep) {
        Err(_) => Ok(()),
        Ok(()) => Err("apagar duas vezes devia falhar"),
    }
}

/// Sem ninguém no endpoint, receber com prazo vencido dá `TimedOut` e
/// enviar sem bloquear dá `WouldBlock`.
fn ipc_sem_par(ctx: &Ctx) -> Outcome {
    let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "create(endpoint)")?;
    let reply = create(ctx.quota, ObjectType::Reply, 0).map_err(|_| "create(reply)")?;
    let timed_out = ipc::recv(ep, reply, 1) == Err(Error::TimedOut);
    let mut msg = Message::new(1, &[2, 3]);
    msg.info.flags = FLAG_NONBLOCK;
    let would_block = ipc::send(ep, &msg, 0) == Err(Error::WouldBlock);
    let _ = (delete(ep), delete(reply));
    match (timed_out, would_block) {
        (true, true) => Ok(()),
        (false, _) => Err("recv devia dar TimedOut"),
        (_, false) => Err("send devia dar WouldBlock"),
    }
}

/// O relógio não anda para trás.
fn monotonico(_: &Ctx) -> Outcome {
    let a = ostd::time::now_ns();
    let b = ostd::time::now_ns();
    if a > 0 && b >= a {
        Ok(())
    } else {
        Err("o relógio andou para trás")
    }
}

/// Falha de propósito (só com `UTEST_FALHA=1`): prova que o `xtask`
/// derruba o comando quando um teste falha.
#[cfg(utest_falha)]
fn proposital(_: &Ctx) -> Outcome {
    Err("falha proposital (UTEST_FALHA=1)")
}

fn main(start: Start) -> ! {
    let ctx = Ctx {
        quota: Handle::from_raw(u32::try_from(start.args[0]).unwrap_or(0)),
    };
    ostd::debug::print_fmt(format_args!("utest: início, {} testes", TESTS.len()));
    let mut passed = 0usize;
    for test in TESTS {
        match (test.run)(&ctx) {
            Ok(()) => {
                passed += 1;
                ostd::debug::print_fmt(format_args!("utest: ok {}", test.name));
            }
            Err(why) => {
                ostd::debug::print_fmt(format_args!("utest: FALHOU {}: {why}", test.name));
            }
        }
    }
    ostd::debug::print_fmt(format_args!(
        "utest: fim: {passed} ok, {} falharam",
        TESTS.len() - passed
    ));
    ostd::thread::exit()
}
