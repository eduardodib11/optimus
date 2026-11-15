//! `keyd` (T-518 e T-527; ADR 0053 e 0054): o serviço que guarda as chaves
//! do sistema. Primeiro monta a semente do gerador de bytes:
//!
//! 1. lê 72 bytes do kernel (três chamadas de `sys_info` de entropia), que
//!    são obrigatórios: sem eles o `keyd` não cria chave nenhuma (item 1);
//! 2. pede 64 bytes ao `EntropySource` do virtio-rng, se o driver existir e
//!    estiver saudável (itens 2, 3 e 5);
//! 3. mistura as duas fontes e a chave atual no [`Drbg`] (item 4).
//!
//! A imagem normal não registra nada da semente. A de teste (`xtask test`,
//! `OPTIMUS_KTEST_DEBUG`) registra impressões digitais de 64 bits
//! (BLAKE3 truncado) da contribuição virtio e da semente (item 6).
//!
//! Depois serve o contrato `Keyring` (`idl/optimus/keyd.oidl`, T-527): cria
//! o cabeçalho de chaves de um volume e o desbloqueia no boot. A senha é
//! pedida e lida no console (item 4), nunca passa pelo contrato, e nada dela
//! nem das chaves vai ao log (item 6).

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

use optcrypt::argon2::Block;
use optcrypt::drbg::Drbg;
use optcrypt::keyring::{self, KEY_LEN, Slot, VolumeKeys};
use optcrypt::secret::{Secret, wipe};
use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType};
use ostd::rt::Start;
use ostd::svc::Session;
use ostd::sync::Mutex;

mod console_cliente;
mod entropy_cliente;
mod keyd_servidor;

use console_cliente::ConsoleCliente;
use entropy_cliente::EntropySourceCliente;
use keyd_servidor::{Contexto, ID_KEYRING, KeydError, Keyring};

ostd::entry!(main);

/// `kind` das capabilities de origem do kernel no descritor (ADR 0034).
const KIND_KERNEL: u8 = 5;
/// Imagem de teste: só ela mostra impressões digitais (ADR 0054, item 6).
const TESTE: bool = option_env!("OPTIMUS_KTEST_DEBUG").is_some();
/// Bytes do kernel na semente (três chamadas de 24 bytes).
const KERNEL_BYTES: usize = 72;
/// Bytes pedidos ao virtio-rng.
const VIRTIO_BYTES: u8 = 64;
/// Quanto esperar o driver partir. Sem o dispositivo o driver nunca parte.
const WAIT_NS: u64 = 2_000_000_000;
const TRY_NS: u64 = 10_000_000;
/// Prazo de cada `connect`: curto, para sair logo se o `svcmgr` desligar.
const CALL_NS: u64 = 100_000_000;

fn hash(text: &[u8]) -> u32 {
    let h = optcrypt::blake3::hash(text);
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// `interface_id(nome, 1)` (ADR 0033).
fn interface_id(name: &[u8]) -> u32 {
    let mut full = [0u8; 64];
    full[..name.len()].copy_from_slice(name);
    full[name.len()..name.len() + 2].copy_from_slice(b"@1");
    hash(&full[..name.len() + 2])
}

/// Cede a vez até passar `TRY_NS` (sem notificação nem timer: veja o `drvcli`).
fn pause() {
    let until = ostd::time::now_ns().saturating_add(TRY_NS);
    while ostd::time::now_ns() < until {
        ostd::thread::yield_now();
    }
}

/// Espera o driver partir: `connect` devolve `NotRunning` até ele chamar `ready`.
fn connect(s: &mut Session, name: &[u8]) -> Option<Handle> {
    let iid = interface_id(name);
    let until = ostd::time::now_ns().saturating_add(WAIT_NS);
    while ostd::time::now_ns() < until {
        let call_until = ostd::time::now_ns().saturating_add(CALL_NS);
        match s.connect_svc_until(iid, 0, call_until) {
            Ok(Ok(h)) => return Some(h),
            Err(Error::TimedOut) | Ok(Err(_)) => {}
            Err(_) => return None,
        }
        pause();
    }
    None
}

/// Os 64 bytes do virtio-rng; `None` se não há driver ou ele falhou.
fn virtio(s: &mut Session, out: &mut [u8; VIRTIO_BYTES as usize]) -> Option<usize> {
    let ep = connect(s, b"optimus.dev.EntropySource")?;
    match EntropySourceCliente::new(ep).read(&mut s.buffer, VIRTIO_BYTES) {
        Ok(Ok(bytes)) => {
            let b = bytes.as_slice();
            out[..b.len()].copy_from_slice(b);
            Some(b.len())
        }
        _ => None,
    }
}

/// Impressão digital de 64 bits (BLAKE3 truncado) para o log de teste.
fn fingerprint(data: &[u8]) -> u64 {
    let h = optcrypt::blake3::hash(data);
    u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
}

/// Memória de trabalho máxima do Argon2id que o `keyd` aceita, em KiB: a
/// cota dele. O perfil Lite (64 MiB, ADR 0053) exige um orçamento de memória
/// próprio para o `keyd` (ADR futura); até lá o `keyd` recusa com `Memory`.
const MAX_WORK_KIB: u32 = 256;
/// Blocos de 1 KiB da memória de trabalho.
const WORK_BLOCKS: usize = MAX_WORK_KIB as usize;
/// Parâmetros do slot de senha que o `keyd` cria (provisórios, veja acima).
/// A imagem de teste usa custo mínimo para caber na janela do `svcmgr` sob TCG.
const PW_M_KIB: u32 = if TESTE { 32 } else { 256 };
const PW_T: u32 = if TESTE { 1 } else { 3 };
/// Tentativas de senha por chamada de `unlock`.
const MAX_TRIES: u32 = 3;
/// Prazo de cada byte digitado, em ms.
const KEY_TIMEOUT_MS: u32 = 120_000;
/// Segundos da espera após senha errada (ADR 0053, item 4). A imagem de
/// teste usa 10 ms no lugar de 1 s, para caber na janela do `svcmgr`.
const DELAY_UNIT_NS: u64 = if TESTE { 10_000_000 } else { 1_000_000_000 };
/// Bytes de uma linha digitada (senha ou chave de recuperação em base32).
const LINE: usize = 72;
/// Slots (senha e recuperação) que `create_volume` devolve.
const SLOT_BYTES: usize = keyring::SLOT_LEN;
const MAX_SLOTS: usize = 8;

/// O serviço: o gerador, o console e as respostas em andamento.
struct Keyd<'a> {
    session: &'a mut Session,
    drbg: Drbg,
    console: Option<Handle>,
    failures: u32,
    out: [u8; 2 * SLOT_BYTES],
    keys: [u8; 3 * KEY_LEN],
}

/// Uma linha digitada: segredo, zerada ao sair de escopo.
struct Line {
    bytes: [u8; LINE],
    len: usize,
}

impl Line {
    fn text(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for Line {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl Keyd<'_> {
    /// O console, com a espera do `connect`.
    fn console(&mut self) -> Result<ConsoleCliente, KeydError> {
        if self.console.is_none() {
            self.console = connect(self.session, b"optimus.console.Console");
        }
        self.console
            .map(ConsoleCliente::new)
            .ok_or(KeydError::NoConsole)
    }

    fn say(&mut self, text: &str) -> Result<(), KeydError> {
        let c = self.console()?;
        match c.write(&mut self.session.buffer, text) {
            Ok(Ok(_)) => Ok(()),
            _ => Err(KeydError::NoConsole),
        }
    }

    /// Lê uma linha, sem eco, byte a byte (o console devolve o que chegou).
    fn read_line(&mut self) -> Result<Line, KeydError> {
        let c = self.console()?;
        let mut line = Line {
            bytes: [0; LINE],
            len: 0,
        };
        loop {
            let Ok(Ok(b)) = c.read(&mut self.session.buffer, 1, KEY_TIMEOUT_MS) else {
                return Err(KeydError::Cancelled);
            };
            let Some(&ch) = b.as_slice().first() else {
                continue;
            };
            match ch {
                b'\n' => return Ok(line),
                b'\r' => {}
                _ if line.len < LINE => {
                    line.bytes[line.len] = ch;
                    line.len += 1;
                }
                _ => return Err(KeydError::Cancelled),
            }
        }
    }

    fn pause(ns: u64) {
        let until = ostd::time::now_ns().saturating_add(ns);
        while ostd::time::now_ns() < until {
            ostd::thread::yield_now();
        }
    }

    fn random<const N: usize>(&mut self) -> Result<[u8; N], KeydError> {
        let mut b = [0u8; N];
        self.drbg.fill(&mut b).map_err(|_| KeydError::NoEntropy)?;
        Ok(b)
    }
}

/// UUID (32 caracteres hexadecimais) em 16 bytes.
fn parse_uuid(text: &str) -> Result<[u8; keyring::UUID_LEN], KeydError> {
    let mut u = [0u8; keyring::UUID_LEN];
    match keyring::from_hex(text.as_bytes(), &mut u) {
        Ok(n) if n == u.len() => Ok(u),
        _ => Err(KeydError::BadSlot),
    }
}

/// Memória de trabalho do Argon2id: fica no `.bss` do `keyd` (o heap do
/// `ostd` pede segmentos de 2 MiB, mais que a cota dele); o Argon2id zera o
/// que usou.
static WORK: Mutex<[Block; WORK_BLOCKS]> = Mutex::new([[0u64; 128]; WORK_BLOCKS]);

/// KEK de senha com a memória de trabalho do [`WORK`].
fn kek_password(pwd: &[u8], slot: &Slot) -> Result<Secret<KEY_LEN>, KeydError> {
    if slot.m_kib > MAX_WORK_KIB {
        return Err(KeydError::Memory);
    }
    let mut work = WORK.lock();
    keyring::kek_password(pwd, slot, &mut work[..]).map_err(|_| KeydError::BadSlot)
}

impl Keyring for Keyd<'_> {
    fn create_volume(&mut self, _ctx: &Contexto, uuid: &str) -> Result<&[u8], KeydError> {
        let uuid = parse_uuid(uuid)?;
        if !self.drbg.is_seeded() {
            return Err(KeydError::NoEntropy);
        }
        self.say("keyd: senha nova: ")?;
        let a = self.read_line()?;
        self.say("\nkeyd: repita a senha: ")?;
        let b = self.read_line()?;
        self.say("\n")?;
        if a.len == 0 || !optcrypt::secret::ct_eq(a.text(), b.text()) {
            return Err(KeydError::Cancelled);
        }
        let mut master = Secret::<KEY_LEN>::take(&mut self.random::<KEY_LEN>()?);
        let mut recovery = Secret::<KEY_LEN>::take(&mut self.random::<KEY_LEN>()?);
        let (salt_pw, nonce_pw) = (self.random()?, self.random()?);
        let (salt_rc, nonce_rc) = (self.random()?, self.random()?);
        // Slot de senha: a KEK sai do Argon2id com os parâmetros do slot.
        let shell = Slot {
            kind: keyring::KIND_PASSWORD,
            m_kib: PW_M_KIB,
            t: PW_T,
            salt: salt_pw,
            nonce: nonce_pw,
            wrapped: [0; KEY_LEN],
            tag: [0; 16],
        };
        let kek = kek_password(a.text(), &shell)?;
        let s0 = keyring::wrap(
            &master,
            &kek,
            &uuid,
            0,
            keyring::KIND_PASSWORD,
            PW_M_KIB,
            PW_T,
            salt_pw,
            nonce_pw,
        )
        .map_err(|_| KeydError::BadSlot)?;
        let kek = keyring::kek_recovery(&recovery, &salt_rc);
        let s1 = keyring::wrap(
            &master,
            &kek,
            &uuid,
            1,
            keyring::KIND_RECOVERY,
            0,
            0,
            salt_rc,
            nonce_rc,
        )
        .map_err(|_| KeydError::BadSlot)?;
        // A chave de recuperação aparece uma vez, só no console.
        let text = keyring::recovery_encode(&recovery);
        self.say("keyd: chave de recuperação (anote, não aparece de novo): ")?;
        let shown = core::str::from_utf8(text.expose()).map_err(|_| KeydError::Cancelled)?;
        let r = self.say(shown);
        let _ = self.say("\n");
        r?;
        master = Secret::zeroed();
        recovery = Secret::zeroed();
        let _ = (&master, &recovery);
        self.out[..SLOT_BYTES].copy_from_slice(&s0.to_bytes());
        self.out[SLOT_BYTES..].copy_from_slice(&s1.to_bytes());
        Ok(&self.out)
    }

    fn unlock(&mut self, _ctx: &Contexto, uuid: &str, slots: &str) -> Result<&[u8], KeydError> {
        let uuid = parse_uuid(uuid)?;
        let mut raw = [0u8; MAX_SLOTS * SLOT_BYTES];
        let n = keyring::from_hex(slots.as_bytes(), &mut raw).map_err(|_| KeydError::BadSlot)?;
        if n == 0 || !n.is_multiple_of(SLOT_BYTES) {
            return Err(KeydError::BadSlot);
        }
        let mut parsed = [Slot::EMPTY; MAX_SLOTS];
        let count = n / SLOT_BYTES;
        for (dst, chunk) in parsed.iter_mut().zip(raw[..n].chunks_exact(SLOT_BYTES)) {
            let arr: &[u8; SLOT_BYTES] = chunk.try_into().map_err(|_| KeydError::BadSlot)?;
            *dst = Slot::from_bytes(arr).map_err(|_| KeydError::BadSlot)?;
        }
        let parsed = &parsed[..count];
        for _ in 0..MAX_TRIES {
            self.say("keyd: senha: ")?;
            let line = self.read_line()?;
            self.say("\n")?;
            if let Some(master) = open_any(parsed, &uuid, &line)? {
                self.failures = 0;
                let k = VolumeKeys::derive(&master, &uuid);
                self.keys[..KEY_LEN].copy_from_slice(k.cab.expose());
                self.keys[KEY_LEN..2 * KEY_LEN].copy_from_slice(k.meta.expose());
                self.keys[2 * KEY_LEN..].copy_from_slice(k.nome.expose());
                return Ok(&self.keys);
            }
            // Senha errada: a espera dobra a cada erro (ADR 0053, item 4).
            self.failures = self.failures.saturating_add(1);
            Self::pause(u64::from(keyring::retry_delay_secs(self.failures)) * DELAY_UNIT_NS);
        }
        Err(KeydError::WrongPassword)
    }
}

/// Tenta a linha digitada nos slots: senha nos de senha e, se ela for uma
/// chave de recuperação válida, nos de recuperação.
fn open_any(
    slots: &[Slot],
    uuid: &[u8; keyring::UUID_LEN],
    line: &Line,
) -> Result<Option<Secret<KEY_LEN>>, KeydError> {
    let recovery = keyring::recovery_decode(line.text()).ok();
    for (i, slot) in slots.iter().enumerate() {
        let Ok(index) = u8::try_from(i) else { break };
        let kek = match slot.kind {
            keyring::KIND_PASSWORD => kek_password(line.text(), slot)?,
            keyring::KIND_RECOVERY => match &recovery {
                Some(r) => keyring::kek_recovery(r, &slot.salt),
                None => continue,
            },
            _ => continue,
        };
        if let Ok(master) = keyring::unwrap(slot, &kek, uuid, index) {
            return Ok(Some(master));
        }
    }
    Ok(None)
}

/// Atende o contrato `Keyring` em `ep` até o endpoint ser revogado.
fn serve(ep: Handle, quota: Handle, svc: &mut Keyd<'_>) -> Error {
    let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let (mut corpo, mut saida) = ([0u8; 1700], [0u8; 224]);
    let mut rec = match ipc::recv(ep, reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    loop {
        let ctx = Contexto { badge: rec.badge };
        let resp = if let Some((rotulo, w)) =
            keyd_servidor::despacha_keyring_palavras(svc, rec.msg.label, &rec.msg.words, &ctx)
        {
            Ok(Message::new(rotulo, &w))
        } else {
            match ipc::copia(&mut svc.session.buffer, &rec.msg, &mut corpo) {
                Ok(n) => {
                    let entrada = keyd_servidor::Entrada {
                        rotulo: rec.msg.label,
                        badge: rec.badge,
                        corpo: &corpo[..n],
                        caps: &[],
                    };
                    match keyd_servidor::despacha_keyring(svc, 0, &entrada, &mut saida, &mut []) {
                        Some(d) => ipc::monta(&mut svc.session.buffer, d.rotulo, &saida[..d.corpo]),
                        None => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
                    }
                }
                Err(_) => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
            }
        };
        let Ok(resp) = resp else {
            return Error::InvalidArgument;
        };
        rec = match ipc::reply_recv(ep, reply, &resp, 0) {
            Ok(r) => r,
            Err(e) => return e,
        };
    }
}

fn run(s: &mut Session) {
    let mut kernel = [0u8; KERNEL_BYTES];
    if ostd::rand::secure_fill(&mut kernel).is_err() {
        // Sem a fonte do kernel, nenhuma chave nasce (ADR 0054, item 1).
        ostd::debug::print("keyd: sem entropia do kernel; não cria chaves");
        return;
    }
    let mut dev = [0u8; VIRTIO_BYTES as usize];
    let got = virtio(s, &mut dev).unwrap_or(0);
    if got == 0 {
        ostd::debug::print("keyd: sem virtio-rng; semente só do kernel");
    }
    let mut drbg = Drbg::new();
    if drbg.reseed(&kernel, &dev[..got]).is_err() {
        ostd::debug::print("keyd: falha ao semear");
        return;
    }
    if TESTE {
        let mut seed = [0u8; 32];
        let _ = drbg.fill(&mut seed);
        ostd::debug::print_fmt(format_args!(
            "keyd: contribuição virtio={:016x}",
            fingerprint(&dev[..got])
        ));
        ostd::debug::print_fmt(format_args!("keyd: semente={:016x}", fingerprint(&seed)));
    }
    ostd::debug::print("keyd: gerador semeado");
    let Some(ep) = s.boot.provided(ID_KEYRING).map(Handle::from_raw) else {
        ostd::debug::print("keyd: descritor sem o endpoint do Keyring");
        return;
    };
    let quota = Handle::from_raw(s.boot.quota().unwrap_or(0));
    let mut svc = Keyd {
        session: s,
        drbg,
        console: None,
        failures: 0,
        out: [0; 2 * SLOT_BYTES],
        keys: [0; 3 * KEY_LEN],
    };
    ostd::debug::print("keyd: contrato Keyring pronto");
    let e = serve(ep, quota, &mut svc);
    ostd::debug::print_fmt(format_args!("keyd: encerrado ({e:?})"));
}

fn main(start: Start) -> ! {
    let Ok(mut s) = Session::start(start.args) else {
        ostd::thread::exit()
    };
    if let Some(c) = s
        .boot
        .caps()
        .iter()
        .find(|c| c.kind == KIND_KERNEL && c.name_hash == hash(b"debug"))
    {
        ostd::debug::set_log(Handle::from_raw(c.handle));
    }
    let _ = s.ready();
    run(&mut s);
    ostd::thread::exit()
}
