//! `root`: o primeiro processo de usuário (SDD v1.0, seção 7.2).
//!
//! O kernel o carrega do bootfs (T-211) e lhe entrega as capabilities
//! iniciais (por ora, só a cota raiz, cujo handle chega no primeiro valor
//! de [`Start`]). Nesta versão ele se anuncia, confere o IPC do `ostd` sem
//! par do outro lado e termina; dividir a memória em cotas e iniciar o
//! `svcmgr` vêm nas próximas tarefas.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use ostd::ipc::{self, Message};
use ostd::kabi::ipc::FLAG_NONBLOCK;
use ostd::kabi::{Error, Handle, ObjectType, Syscall};
use ostd::rt::Start;

ostd::entry!(main);

/// Cria um objeto de `ty` na cota `quota`.
fn create(quota: u64, ty: ObjectType) -> Result<Handle, Error> {
    let [h, ..] = ostd::sys::syscall(Syscall::ObjCreate, [quota, ty.to_raw(), 0, 0, 0, 0])?;
    u32::try_from(h)
        .map(Handle::from_raw)
        .map_err(|_| Error::InvalidHandle)
}

/// Sem ninguém no endpoint, receber com prazo vencido dá `TimedOut` e
/// enviar sem bloquear dá `WouldBlock` (T-208).
fn ipc_alone(quota: u64) -> Result<(), Error> {
    let ep = create(quota, ObjectType::Endpoint)?;
    let reply = create(quota, ObjectType::Reply)?;
    if ipc::recv(ep, reply, 1) != Err(Error::TimedOut) {
        return Err(Error::InvalidArgument);
    }
    let mut msg = Message::new(1, &[2, 3]);
    msg.info.flags = FLAG_NONBLOCK;
    if ipc::send(ep, &msg, 0) != Err(Error::WouldBlock) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn main(start: Start) -> ! {
    ostd::debug::print("root: iniciado");
    match ipc_alone(start.args[0]) {
        Ok(()) => ostd::debug::print("root: IPC sem par: TimedOut e WouldBlock"),
        Err(_) => ostd::debug::print("root: IPC sem par falhou"),
    }
    ostd::thread::exit()
}
