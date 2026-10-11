//! `root`: o primeiro processo de usuário (SDD v1.0, seção 7.2).
//!
//! O kernel o carrega do bootfs (T-211) e lhe entrega as capabilities
//! iniciais: a cota raiz em `rdi`, o próprio espaço em `rsi` e, em `rdx`,
//! a própria thread e uma cópia só de leitura do bootfs (ADR 0029). Nesta
//! versão ele se anuncia, confere o IPC sem par do outro lado, carrega o
//! `hello` do bootfs e conversa com ele (T-212): a saudação pelo buffer de
//! IPC e as idas e voltas que a entrada `hello.rounds` do bootfs pedir
//! (padrão [`DEFAULT_ROUNDS`]). Dividir a memória em cotas e iniciar o
//! `svcmgr` vêm nas próximas tarefas.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::cap::create;
use ostd::ipc::{self, Buffer, Message, Received};
use ostd::kabi::ipc::FLAG_NONBLOCK;
use ostd::kabi::vm::PAGE_SIZE;
use ostd::kabi::{Error, Handle, ObjectType, Rights, handle_pair, split_handle_pair};
use ostd::process::{self, Spec};
use ostd::rt::Start;
use ostd::vm::Mapping;

#[path = "../../hello/src/proto.rs"]
mod proto;

ostd::entry!(main);

/// Idas e voltas com o `hello` quando o bootfs não diz quantas.
const DEFAULT_ROUNDS: u64 = 1000;
/// Onde o `root` mapeia o bootfs.
const BOOTFS_VA: u64 = 0x4000_0000;
/// Faixa dos mapeamentos temporários do carregador.
const SCRATCH_VA: u64 = 0x8000_0000;
/// Cota do `hello`.
const HELLO_QUOTA: u64 = 4 << 20;
/// Prioridade do `hello`: a mesma do `root`, para a troca direta do
/// caminho rápido valer nos dois sentidos.
const HELLO_PRIORITY: u8 = 150;

/// Capabilities iniciais.
#[derive(Clone, Copy)]
struct Boot {
    quota: Handle,
    aspace: Handle,
    thread: Handle,
    bootfs: Handle,
}

/// Sem ninguém no endpoint, receber com prazo vencido dá `TimedOut` e
/// enviar sem bloquear dá `WouldBlock` (T-208).
fn ipc_alone(quota: Handle) -> Result<(), Error> {
    let ep = create(quota, ObjectType::Endpoint, 0)?;
    let reply = create(quota, ObjectType::Reply, 0)?;
    if ipc::recv(ep, reply, 1) != Err(Error::TimedOut) {
        return Err(Error::InvalidArgument);
    }
    let mut msg = Message::new(1, &[2, 3]);
    msg.info.flags = FLAG_NONBLOCK;
    if ipc::send(ep, &msg, 0) != Err(Error::WouldBlock) {
        return Err(Error::InvalidArgument);
    }
    let _ = (ostd::cap::delete(ep), ostd::cap::delete(reply));
    Ok(())
}

/// Número decimal em ASCII, com espaços em volta.
fn decimal(bytes: &[u8]) -> Option<u64> {
    core::str::from_utf8(bytes).ok()?.trim().parse().ok()
}

/// Mapeia o bootfs inteiro (o tamanho vem do cabeçalho OBFS).
fn map_bootfs(b: Boot) -> Result<Mapping, Error> {
    let len = {
        let head = Mapping::new(b.aspace, b.bootfs, BOOTFS_VA, PAGE_SIZE, 0)?;
        let field = head.bytes().get(32..40).ok_or(Error::InvalidArgument)?;
        u64::from_le_bytes(field.try_into().map_err(|_| Error::InvalidArgument)?)
    };
    Mapping::new(b.aspace, b.bootfs, BOOTFS_VA, len, 0)
}

/// Carrega o `hello`, dá a ele o endpoint e o inicia; devolve o endpoint
/// (para receber) e as voltas pedidas.
fn spawn_hello(b: Boot) -> Result<(Handle, u64), Error> {
    let fs_map = map_bootfs(b)?;
    let fs = obfs::Image::parse(fs_map.bytes()).map_err(|_| Error::InvalidArgument)?;
    let elf = fs.find("hello").ok_or(Error::InvalidArgument)?;
    let rounds = fs
        .find("hello.rounds")
        .and_then(|e| decimal(e.data))
        .unwrap_or(DEFAULT_ROUNDS);
    let child = process::load(&Spec {
        elf: elf.data,
        quota: b.quota,
        quota_bytes: HELLO_QUOTA,
        own_aspace: b.aspace,
        scratch_va: SCRATCH_VA,
        priority: HELLO_PRIORITY,
    })?;
    let ep = create(b.quota, ObjectType::Endpoint, 0)?;
    let ep_child = child.give(ep, Rights::SEND, proto::BADGE)?;
    let exception = child.give(ep, Rights::SEND, proto::EXCEPTION_BADGE)?;
    let thread = child.give(child.thread, Rights::WRITE_STATE, 0)?;
    let aspace = child.give(child.aspace, Rights::MAP | Rights::UNMAP, 0)?;
    let quota = child.give(child.quota, Rights::CREATE, 0)?;
    ostd::thread::set_exception_handler(child.thread, Some(exception))?;
    child.start([
        handle_pair(ep_child, thread),
        handle_pair(aspace, quota),
        rounds,
    ])?;
    Ok((ep, rounds))
}

/// A saudação do `hello`, lida do buffer de IPC.
fn greeting(m: &Received, buffer: &mut Buffer) {
    let len = usize::try_from(m.msg.words[0]).unwrap_or(0);
    let words = &buffer.get().words[..usize::from(m.msg.info.buffer_words)];
    let mut bytes = [0u8; 256];
    for (dst, w) in bytes.chunks_mut(8).zip(words) {
        dst.copy_from_slice(&w.to_le_bytes());
    }
    let text = core::str::from_utf8(&bytes[..len.min(words.len() * 8)]).unwrap_or("?");
    ostd::debug::print("root: o hello disse:");
    ostd::debug::print(text);
}

/// Atende o `hello` até a despedida; `Ok` se as voltas conferiram.
fn serve(b: Boot, ep: Handle, rounds: u64, buffer: &mut Buffer) -> Result<(), Error> {
    let reply = create(b.quota, ObjectType::Reply, 0)?;
    let (mut next, mut bad, mut t0) = (0u64, 0u64, 0);
    let mut m = ipc::recv(ep, reply, 0)?;
    loop {
        if m.badge == proto::EXCEPTION_BADGE {
            ostd::debug::print_fmt(format_args!(
                "root: exceção no hello: rótulo {:#x}",
                m.msg.label
            ));
            return Err(Error::Cancelled);
        }
        let answer = match m.msg.label {
            proto::HELLO => {
                greeting(&m, buffer);
                Message::new(proto::HELLO, &[])
            }
            proto::PING => {
                if next == 0 {
                    t0 = ostd::time::now_ns();
                }
                let mut words = m.msg.words;
                let ok = m.msg.info.words == 6
                    && (0..).zip(words).all(|(k, w)| w == proto::word(next, k));
                bad += u64::from(!ok);
                next += 1;
                for w in &mut words {
                    *w = w.wrapping_add(1);
                }
                Message::new(proto::PONG, &words)
            }
            proto::BYE => {
                ipc::send(reply, &Message::new(proto::BYE, &[]), 0)?;
                let ns = ostd::time::now_ns() - t0;
                let [done, errors, ..] = m.msg.words;
                ostd::debug::print_fmt(format_args!(
                    "root: {} ns por ida e volta com o hello",
                    ns / rounds.max(1)
                ));
                return if done == rounds && next == rounds && bad == 0 && errors == 0 {
                    ostd::debug::print_fmt(format_args!(
                        "root: hello: {rounds} idas e voltas sem erro"
                    ));
                    Ok(())
                } else {
                    ostd::debug::print_fmt(format_args!(
                        "root: hello: {next}/{rounds} voltas, {bad}+{errors} erros"
                    ));
                    Err(Error::InvalidArgument)
                };
            }
            _ => {
                bad += 1;
                Message::new(0, &[])
            }
        };
        m = ipc::reply_recv(ep, reply, &answer, 0)?;
    }
}

fn hello(b: Boot) -> Result<(), Error> {
    let mut buffer = Buffer::new(b.quota, b.aspace, b.thread, ipc::DEFAULT_BUFFER_VA)?;
    let (ep, rounds) = spawn_hello(b)?;
    serve(b, ep, rounds, &mut buffer)
}

fn main(start: Start) -> ! {
    let [quota, aspace, rdx] = start.args;
    let (thread, bootfs) = split_handle_pair(rdx);
    let handle = |raw: u64| Handle::from_raw(u32::try_from(raw).unwrap_or(0));
    let boot = Boot {
        quota: handle(quota),
        aspace: handle(aspace),
        thread,
        bootfs,
    };
    ostd::debug::print("root: iniciado");
    match ipc_alone(boot.quota) {
        Ok(()) => ostd::debug::print("root: IPC sem par: TimedOut e WouldBlock"),
        Err(_) => ostd::debug::print("root: IPC sem par falhou"),
    }
    if let Err(e) = hello(boot) {
        ostd::debug::print_fmt(format_args!("root: conversa com o hello falhou: {e:?}"));
    }
    ostd::thread::exit()
}
