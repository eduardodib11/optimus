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
use ostd::ipc::{self, Buffer, Message};
use ostd::kabi::ipc::FLAG_NONBLOCK;
use ostd::kabi::vm::PAGE_SIZE;
use ostd::kabi::{Error, Handle, ObjectType, Rights, handle_pair, split_handle_pair};
use ostd::process::{self, Spec};
use ostd::rt::Start;
use ostd::vm::Mapping;

#[path = "../../hello/src/proto.rs"]
mod proto;

#[path = "hello_servidor.rs"]
mod hello_servidor;

ostd::entry!(main);

/// Idas e voltas com o `hello` quando o bootfs não diz quantas.
const DEFAULT_ROUNDS: u64 = 1000;
/// Onde o `root` mapeia o bootfs.
const BOOTFS_VA: u64 = 0x4000_0000;
/// Onde o `root` mapeia a tabela de handles de partida (ADR 0036, item 5).
const TABLE_VA: u64 = 0x5000_0000;
/// Faixa dos mapeamentos temporários do carregador.
const SCRATCH_VA: u64 = 0x8000_0000;
/// Cota do `hello`.
const HELLO_QUOTA: u64 = 4 << 20;
/// Badge da `DebugLog` que o `root` dá ao `hello`: "hell" em ASCII.
const HELLO_LOG_BADGE: u64 = 0x6865_6c6c;
/// Prioridade do `hello`: a mesma do `root`, para a troca direta do
/// caminho rápido valer nos dois sentidos.
const HELLO_PRIORITY: u8 = 150;
/// Cota de partida do `svcmgr` (ADR 0034, item 2): fixa, 8 MiB no M3.
const SVCMGR_QUOTA: u64 = 8 << 20;
/// Prioridade do `svcmgr`: 200, faixa de drivers, por exceção (ADR 0034).
const SVCMGR_PRIORITY: u8 = 200;
/// Badge com que o `root` identifica o `svcmgr` no próprio endpoint.
const ROOT_BADGE: u64 = 1;
/// Rótulo do "olá" do `svcmgr` ao `root`.
const LABEL_OLA: u64 = 1;
/// Respostas do `root` ao `svcmgr`.
const LABEL_OK: u64 = 0;
const LABEL_ACCESS_DENIED: u64 = 1;
/// Quanto o `root` espera o primeiro contato do `svcmgr`, em ns.
const SVCMGR_WAIT_NS: u64 = 2_000_000_000;

/// Capabilities iniciais.
#[derive(Clone, Copy)]
struct Boot {
    quota: Handle,
    aspace: Handle,
    thread: Handle,
    bootfs: Handle,
    /// `DebugLog` da tabela de partida, 0 se a tabela não a trouxer.
    log: Handle,
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
    // A `DebugLog` vai com `WRITE` e um badge próprio do `hello`. Em
    // `args[2]`, a parte alta leva o handle dela e a baixa, as voltas.
    let small = u32::try_from(rounds).map_err(|_| Error::InvalidArgument)?;
    let log = if b.log.raw() == 0 {
        0
    } else {
        child.give(b.log, Rights::WRITE, HELLO_LOG_BADGE)?.raw()
    };
    ostd::thread::set_exception_handler(child.thread, Some(exception))?;
    child.start([
        handle_pair(ep_child, thread),
        handle_pair(aspace, quota),
        (u64::from(log) << 32) | u64::from(small),
    ])?;
    Ok((ep, rounds))
}

/// Estado do atendimento ao `hello`: a implementação do protocolo OIDL
/// (`idl/optimus/hello.oidl`) e as contagens que o `root` confere no fim.
struct Atende {
    next: u64,
    bad: u64,
    t0: u64,
    feitas: u64,
    erros: u64,
    encerrou: bool,
}

#[allow(clippy::many_single_char_names, reason = "nomes do IDL: a..f")]
impl hello_servidor::Hello for Atende {
    fn saudacao(&mut self, _ctx: &hello_servidor::Contexto, texto: &str) -> Result<u64, u8> {
        ostd::debug::print("root: o hello disse:");
        ostd::debug::print(texto);
        Ok(texto.len() as u64)
    }

    fn ping(
        &mut self,
        _ctx: &hello_servidor::Contexto,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) -> Result<hello_servidor::Seis, u8> {
        if self.next == 0 {
            self.t0 = ostd::time::now_ns();
        }
        let ok = [a, b, c, d, e, f]
            .iter()
            .enumerate()
            .all(|(k, &w)| w == proto::word(self.next, k as u64));
        self.bad += u64::from(!ok);
        self.next += 1;
        Ok(hello_servidor::Seis {
            w0: a.wrapping_add(1),
            w1: b.wrapping_add(1),
            w2: c.wrapping_add(1),
            w3: d.wrapping_add(1),
            w4: e.wrapping_add(1),
            w5: f.wrapping_add(1),
        })
    }

    fn bye(&mut self, _ctx: &hello_servidor::Contexto, voltas: u64, erros: u64) -> Result<(), u8> {
        self.feitas = voltas;
        self.erros = erros;
        self.encerrou = true;
        Ok(())
    }
}

/// Atende o `hello` até a despedida; `Ok` se as voltas conferiram.
fn serve(b: Boot, ep: Handle, rounds: u64, buffer: &mut Buffer) -> Result<(), Error> {
    let reply = create(b.quota, ObjectType::Reply, 0)?;
    let mut st = Atende {
        next: 0,
        bad: 0,
        t0: 0,
        feitas: 0,
        erros: 0,
        encerrou: false,
    };
    let mut corpo = [0u8; 256];
    let mut saida = [0u8; 64];
    let mut rec = ipc::recv_corpo(ep, reply, buffer, &mut corpo, 0)?;
    loop {
        if rec.badge == proto::EXCEPTION_BADGE {
            ostd::debug::print_fmt(format_args!(
                "root: exceção no hello: rótulo {:#x}",
                rec.rotulo
            ));
            return Err(Error::Cancelled);
        }
        let entrada = hello_servidor::Entrada {
            rotulo: rec.rotulo,
            badge: rec.badge,
            corpo: &corpo[..rec.corpo],
            caps: &[],
        };
        let despacho = hello_servidor::despacha_hello(&mut st, 0, &entrada, &mut saida, &mut []);
        let Some(d) = despacho else {
            return Err(Error::InvalidArgument);
        };
        let resposta = &saida[..d.corpo];
        if st.encerrou {
            ipc::responde_corpo(reply, buffer, d.rotulo, resposta, 0)?;
            break;
        }
        rec = ipc::responde_recebe_corpo(ep, reply, buffer, d.rotulo, resposta, &mut corpo, 0)?;
    }
    let ns = ostd::time::now_ns() - st.t0;
    ostd::debug::print_fmt(format_args!(
        "root: {} ns por ida e volta com o hello",
        ns / rounds.max(1)
    ));
    if st.feitas == rounds && st.next == rounds && st.bad == 0 && st.erros == 0 {
        ostd::debug::print_fmt(format_args!("root: hello: {rounds} idas e voltas sem erro"));
        Ok(())
    } else {
        ostd::debug::print_fmt(format_args!(
            "root: hello: {}/{rounds} voltas, {}+{} erros",
            st.next, st.bad, st.erros
        ));
        Err(Error::InvalidArgument)
    }
}

fn hello(b: Boot) -> Result<(), Error> {
    let mut buffer = Buffer::new(b.quota, b.aspace, b.thread, ipc::DEFAULT_BUFFER_VA)?;
    let (ep, rounds) = spawn_hello(b)?;
    serve(b, ep, rounds, &mut buffer)
}

/// Acha o bootfs na tabela de handles de partida, lendo-a só por leitura.
fn bootfs_from_table(aspace: Handle, table: Handle) -> Result<Handle, Error> {
    table_entry(aspace, table, ostd::kabi::startup::KIND_BOOTFS)
}

/// Handle da primeira entrada do tipo `kind` na tabela de partida.
fn table_entry(aspace: Handle, table: Handle, kind: u32) -> Result<Handle, Error> {
    use ostd::kabi::startup::{ENTRY_BYTES, HEADER_BYTES, MAGIC, MAX_ENTRIES};
    let map = Mapping::new(aspace, table, TABLE_VA, PAGE_SIZE, 0)?;
    let bytes = map.bytes();
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    };
    if word(0) != Some(MAGIC) {
        return Err(Error::InvalidArgument);
    }
    let count = word(4).ok_or(Error::InvalidArgument)? as usize;
    if count > MAX_ENTRIES {
        return Err(Error::InvalidArgument);
    }
    for i in 0..count {
        let at = HEADER_BYTES + i * ENTRY_BYTES;
        if word(at) == Some(kind) {
            let raw = word(at + 4).ok_or(Error::InvalidArgument)?;
            return Ok(Handle::from_raw(raw));
        }
    }
    Err(Error::InvalidArgument)
}

/// Carrega o `svcmgr` do bootfs com a própria cota de partida, dá a ele o
/// endpoint do `root` (badge [`ROOT_BADGE`]), o bootfs só de leitura e a
/// cota, e o inicia. Devolve o endpoint para atender o primeiro contato.
///
/// A capability da thread do `svcmgr` não vai para o `CapSpace` dele (ADR
/// 0034, item 2): a thread já guarda a tabela, e a tabela guardar a thread
/// fecharia o ciclo da ADR 0029, que deixaria o processo inteiro preso na
/// cota depois da saída. Para mexer em si mesmo, o `svcmgr` usa
/// `thread = 0` (ADR 0039, item 3).
fn spawn_svcmgr(b: Boot) -> Result<Handle, Error> {
    let fs_map = map_bootfs(b)?;
    let fs = obfs::Image::parse(fs_map.bytes()).map_err(|_| Error::InvalidArgument)?;
    let elf = fs.find("svcmgr").ok_or(Error::InvalidArgument)?;
    let child = process::load(&Spec {
        elf: elf.data,
        quota: b.quota,
        quota_bytes: SVCMGR_QUOTA,
        own_aspace: b.aspace,
        scratch_va: SCRATCH_VA,
        priority: SVCMGR_PRIORITY,
    })?;
    let ep = create(b.quota, ObjectType::Endpoint, 0)?;
    let ep_child = child.give(ep, Rights::SEND, ROOT_BADGE)?;
    let bootfs = child.give(b.bootfs, Rights::READ | Rights::MAP, 0)?;
    let quota = child.give(child.quota, Rights::CREATE, 0)?;
    child.start([u64::from(ep_child.raw()), handle_pair(bootfs, quota), 0])?;
    Ok(ep)
}

/// Atende o primeiro contato do `svcmgr` no endpoint do `root`. Só o badge
/// [`ROOT_BADGE`] é aceito; qualquer outro recebe `AccessDenied` e o
/// atendimento termina com erro.
fn atende_svcmgr(b: Boot, ep: Handle) -> Result<(), Error> {
    let reply = create(b.quota, ObjectType::Reply, 0)?;
    let deadline = ostd::time::now_ns() + SVCMGR_WAIT_NS;
    let rec = ipc::recv(ep, reply, deadline)?;
    if rec.badge != ROOT_BADGE || rec.msg.label != LABEL_OLA {
        ipc::send(reply, &Message::new(LABEL_ACCESS_DENIED, &[]), 0)?;
        ostd::debug::print("root: chamada recusada no endpoint do svcmgr");
        return Err(Error::AccessDenied);
    }
    ipc::send(reply, &Message::new(LABEL_OK, &[]), 0)?;
    ostd::debug::print("root: o svcmgr se anunciou e foi aceito");
    Ok(())
}

/// Cria o `svcmgr` e atende o contato dele.
fn svcmgr(b: Boot) -> Result<(), Error> {
    let ep = spawn_svcmgr(b)?;
    atende_svcmgr(b, ep)
}

fn main(start: Start) -> ! {
    let [quota, aspace, rdx] = start.args;
    let (thread, table) = split_handle_pair(rdx);
    let handle = |raw: u64| Handle::from_raw(u32::try_from(raw).unwrap_or(0));
    if let Ok(log) = table_entry(handle(aspace), table, ostd::kabi::startup::KIND_DEBUG_LOG) {
        ostd::debug::set_log(log);
    }
    let bootfs = match bootfs_from_table(handle(aspace), table) {
        Ok(h) => h,
        Err(e) => {
            ostd::debug::print_fmt(format_args!("root: tabela de partida inválida: {e:?}"));
            ostd::thread::exit()
        }
    };
    let boot = Boot {
        quota: handle(quota),
        aspace: handle(aspace),
        thread,
        bootfs,
        log: table_entry(handle(aspace), table, ostd::kabi::startup::KIND_DEBUG_LOG)
            .unwrap_or(Handle::from_raw(0)),
    };
    ostd::rt::init(ostd::rt::Env { quota: boot.quota });
    ostd::debug::print("root: iniciado");
    match ipc_alone(boot.quota) {
        Ok(()) => ostd::debug::print("root: IPC sem par: TimedOut e WouldBlock"),
        Err(_) => ostd::debug::print("root: IPC sem par falhou"),
    }
    if let Err(e) = hello(boot) {
        ostd::debug::print_fmt(format_args!("root: conversa com o hello falhou: {e:?}"));
    }
    if let Err(e) = svcmgr(boot) {
        ostd::debug::print_fmt(format_args!("root: svcmgr: {e:?}"));
    }
    ostd::thread::exit()
}
