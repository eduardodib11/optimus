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
//! O `utest` também é o primeiro processo a usar o alocador global do `ostd`
//! (T-334): `Box`, `Vec` e `String` funcionam porque a função principal
//! registra a cota em [`ostd::rt::init`] antes de alocar (o alocador mapeia
//! no próprio espaço com `aspace = 0`, T-333).
//!
//! Para acrescentar um teste, escreva uma `fn(&Ctx) -> Result<(), &'static
//! str>` e a ponha em [`TESTS`].

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use ostd::cap::{create, delete};
use ostd::ipc::{self, Message};
use ostd::kabi::ipc::FLAG_NONBLOCK;
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::{Env, Start};

ostd::entry!(main);

/// Capabilities iniciais que os testes podem usar.
struct Ctx {
    /// Cota raiz.
    quota: Handle,
}

/// Bloco com alinhamento de página.
#[repr(align(4096))]
struct PageAligned([u8; 64]);

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
    Test {
        name: "alloc.global",
        run: alocador_global,
    },
    Test {
        name: "alloc.sem_memoria",
        run: alocador_sem_memoria,
    },
    Test {
        name: "alloc.janela_reaproveitada",
        run: alocador_reaproveita_janela,
    },
    Test {
        name: "tls.configurar_e_recusar",
        run: tls_configurar,
    },
    Test {
        name: "vm.proprio_espaco_sem_handle",
        run: vm_proprio_espaco,
    },
    Test {
        name: "thread.exit_recusa_flags",
        run: exit_recusa_flags,
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

/// O alocador global: `Box`, `Vec` que cresce por `realloc` (passando de
/// bloco pequeno a grande), um bloco enorme (segmento próprio), `String`,
/// alinhamento de página e, depois de soltar tudo, nenhum bloco a mais vivo.
fn alocador_global(_: &Ctx) -> Outcome {
    let before = ostd::alloc::stats();
    {
        let boxed = Box::new([7u64; 100]);
        if boxed.iter().any(|&w| w != 7) {
            return Err("Box corrompido");
        }
        let mut v: Vec<u32> = Vec::new();
        for i in 0..50_000u32 {
            v.push(i.wrapping_mul(2_654_435_761));
        }
        if v.iter()
            .zip(0..)
            .any(|(&w, i): (&u32, u32)| w != i.wrapping_mul(2_654_435_761))
        {
            return Err("Vec corrompido depois de crescer");
        }
        let mut big: Vec<u8> = Vec::with_capacity(3 << 20);
        big.resize(3 << 20, 0xAB);
        big[0] = 1;
        big[(3 << 20) - 1] = 2;
        if big[0] != 1 || big[1 << 20] != 0xAB || big[(3 << 20) - 1] != 2 {
            return Err("bloco enorme corrompido");
        }
        let mut text = String::new();
        for _ in 0..1000 {
            text.push_str("optimus ");
        }
        if text.len() != 8000 || !text.starts_with("optimus optimus") {
            return Err("String corrompida");
        }
        let aligned = Box::new(PageAligned([9; 64]));
        if !(&raw const *aligned).addr().is_multiple_of(4096) || aligned.0[63] != 9 {
            return Err("alinhamento de página não respeitado");
        }
        let small: Vec<Box<u64>> = (0..5000u64).map(Box::new).collect();
        if small.iter().zip(0..).any(|(b, i)| **b != i) {
            return Err("blocos pequenos corrompidos");
        }
        let during = ostd::alloc::stats();
        if during.live_blocks < before.live_blocks + 5000 {
            return Err("stats não vê os blocos vivos");
        }
    }
    let after = ostd::alloc::stats();
    if after.live_blocks == before.live_blocks && after.live_bytes == before.live_bytes {
        Ok(())
    } else {
        Err("vazou memória ao soltar tudo")
    }
}

/// Memória esgotada: o pedido que a cota não cobre devolve erro (nulo no
/// alocador) e o alocador continua servindo.
fn alocador_sem_memoria(_: &Ctx) -> Outcome {
    let mut v: Vec<u8> = Vec::new();
    // 1 TiB: passa da cota do processo.
    if v.try_reserve_exact(1 << 40).is_ok() {
        return Err("1 TiB devia falhar");
    }
    let mut w: Vec<u64> = Vec::new();
    w.try_reserve_exact(1000)
        .map_err(|_| "alocação pequena falhou depois do erro")?;
    w.push(1);
    Ok(())
}

/// Blocos enormes alocados e liberados em laço reaproveitam a mesma faixa da
/// janela de endereços, em vez de avançar por ela.
fn alocador_reaproveita_janela(_: &Ctx) -> Outcome {
    let mut first = 0;
    for i in 0..50 {
        let mut big: Vec<u8> = Vec::with_capacity(3 << 20);
        big.resize(3 << 20, 1);
        let addr = big.as_ptr().addr();
        if i == 0 {
            first = addr;
        } else if addr != first {
            return Err("a faixa liberada não foi reaproveitada");
        }
    }
    Ok(())
}

/// `thread_configure` com `CONFIGURE_TLS` (T-333): na própria thread
/// (`thread = 0`) e noutra pela capability; recusa endereço não canônico, da
/// metade do kernel, TLS junto com o buffer de IPC, ligação com `thread =
/// 0` e handle inválido.
fn tls_configurar(ctx: &Ctx) -> Outcome {
    use ostd::kabi::Syscall;
    use ostd::kabi::thread::{CONFIGURE_IPC_BUFFER, CONFIGURE_TLS};
    use ostd::kabi::vm::USER_END;
    use ostd::thread::{SELF, set_tls};
    let va = 0x7000_0000;
    set_tls(SELF, va).map_err(|_| "TLS da própria thread")?;
    set_tls(SELF, USER_END - 1).map_err(|_| "TLS no fim da metade de usuário")?;
    for bad in [
        USER_END,
        0x0000_8000_0000_1000,
        0xffff_8000_0000_0000,
        u64::MAX,
    ] {
        if set_tls(SELF, bad) != Err(Error::InvalidArgument) {
            return Err("TLS fora da metade de usuário devia ser recusado");
        }
    }
    let raw = |args| ostd::sys::syscall(Syscall::ThreadConfigure, args).map(drop);
    if raw([0, 0, 0, va, 0, CONFIGURE_TLS | CONFIGURE_IPC_BUFFER]) != Err(Error::InvalidArgument) {
        return Err("TLS junto com o buffer de IPC devia ser recusado");
    }
    if raw([0, 1, 1, va, 0, CONFIGURE_TLS]) != Err(Error::InvalidArgument) {
        return Err("thread = 0 não liga CapSpace nem AddressSpace");
    }
    if set_tls(Handle::from_raw(0x00ab_cdef), va) != Err(Error::InvalidHandle) {
        return Err("handle inválido devia dar InvalidHandle");
    }
    let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "create(endpoint)")?;
    let not_thread = set_tls(ep, va).is_err();
    let other = create(ctx.quota, ObjectType::Thread, 0).map_err(|_| "create(thread)")?;
    let on_other = set_tls(other, va);
    let _ = (delete(ep), delete(other));
    set_tls(SELF, 0).map_err(|_| "tirar o TLS")?;
    match (not_thread, on_other) {
        (true, Ok(())) => Ok(()),
        (false, _) => Err("TLS num endpoint devia falhar"),
        (_, Err(_)) => Err("TLS noutra thread pela capability falhou"),
    }
}

/// `vm_map` e `vm_unmap` com `aspace = 0` (T-333): o espaço de quem chama,
/// sem handle.
fn vm_proprio_espaco(ctx: &Ctx) -> Outcome {
    use ostd::kabi::vm::{PAGE_SIZE, WRITE};
    use ostd::vm::{Mapping, SELF};
    let va = 0x7100_0000;
    let object = create(ctx.quota, ObjectType::MemoryObject, PAGE_SIZE).map_err(|_| "create")?;
    let result = (|| {
        let mut m = Mapping::new(SELF, object, va, PAGE_SIZE, WRITE).map_err(|_| "vm_map(0)")?;
        let bytes = m.bytes_mut().ok_or("não gravável")?;
        bytes[0] = 0x5a;
        bytes[4095] = 0xa5;
        if m.bytes()[0] != 0x5a || m.bytes()[4095] != 0xa5 {
            return Err("a página mapeada não guardou os bytes");
        }
        drop(m);
        // O `Drop` desmapeou com `aspace = 0`: mapear de novo funciona.
        let again = Mapping::new(SELF, object, va, PAGE_SIZE, 0).map_err(|_| "vm_map de novo")?;
        drop(again);
        Ok(())
    })();
    let _ = delete(object);
    result
}

/// `thread_exit` com `EXIT_GROUP` volta `NotSupported` até a T-348, e com
/// flag desconhecida, `InvalidArgument`; nos dois casos a thread segue.
fn exit_recusa_flags(_: &Ctx) -> Outcome {
    use ostd::kabi::Syscall;
    if ostd::thread::exit_group(1) != Error::NotSupported {
        return Err("EXIT_GROUP devia dar NotSupported");
    }
    if ostd::sys::syscall(Syscall::ThreadExit, [0, 2, 0, 0, 0, 0]).map(drop)
        != Err(Error::InvalidArgument)
    {
        return Err("flag desconhecida devia dar InvalidArgument");
    }
    Ok(())
}

/// Falha de propósito (só com `UTEST_FALHA=1`): prova que o `xtask`
/// derruba o comando quando um teste falha.
#[cfg(utest_falha)]
fn proposital(_: &Ctx) -> Outcome {
    Err("falha proposital (UTEST_FALHA=1)")
}

fn main(start: Start) -> ! {
    let handle = |raw: u64| Handle::from_raw(u32::try_from(raw).unwrap_or(0));
    let ctx = Ctx {
        quota: handle(start.args[0]),
    };
    ostd::rt::init(Env { quota: ctx.quota });
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
