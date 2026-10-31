//! Testes de `ostd::ring` (T-339; ADR 0036, item 1): modelo em um processo
//! (dois mapeamentos do mesmo objeto), par que mente e o aceite do backlog,
//! produtor e consumidor em processos distintos (o `utest` carrega uma cópia
//! de si mesmo do bootfs, que entra no modo [`CHILD_FLAG`]).
//!
//! Itens do aceite: [`ITEMS`] (10⁷; `UTEST_RING_ITEMS` no ambiente de
//! compilação troca o número, para rodar mais curto em TCG).

#![allow(clippy::cast_possible_truncation, reason = "bytes de padrão")]

use alloc::vec::Vec;

use ostd::cap::{bind_notify, create, delete};
use ostd::kabi::{Error, Handle, ObjectType, Rights, handle_pair, split_handle_pair};
use ostd::process::{self, Spec};
use ostd::ring::{Consumer, MAX_PAYLOAD, PopError, Producer, PushError, object_bytes};
use ostd::rt::{Env, Start};
use ostd::vm::{Mapping, SELF};

use crate::{Ctx, Outcome};

const DATA_LEN: u32 = 64 << 10;
const KIND: u16 = 7;
/// Bit do anel na `Notification` e bit da morte do filho.
const RING_BIT: u64 = 1;
const DEATH_BIT: u64 = 2;
/// Marca de `rdx` do filho (o do pai é um par de handles de 32 bits):
/// o resto de `rdx` é o número de itens.
pub const CHILD_FLAG: u64 = 1 << 63;
const VA_A: u64 = 0x2000_0000;
const VA_B: u64 = 0x2100_0000;
const BOOTFS_VA: u64 = 0x4000_0000;
const SCRATCH_VA: u64 = 0x8000_0000;
const CHILD_QUOTA: u64 = 8 << 20;

/// Itens do aceite entre dois processos.
const ITEMS: u64 = match option_env!("UTEST_RING_ITEMS") {
    Some(s) => parse(s),
    None => 10_000_000,
};

const fn parse(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut n = 0u64;
    let mut i = 0;
    while i < b.len() {
        n = n * 10 + (b[i] - b'0') as u64;
        i += 1;
    }
    n
}

fn sys<T>(r: Result<T, Error>, what: &'static str) -> Result<T, &'static str> {
    r.map_err(|_| what)
}

fn new_ring(ctx: &Ctx) -> Result<(Handle, Handle), &'static str> {
    let object = sys(
        create(ctx.quota, ObjectType::MemoryObject, object_bytes(DATA_LEN)),
        "create(MemoryObject)",
    )?;
    let ntfy = sys(
        create(ctx.quota, ObjectType::Notification, 0),
        "create(Notification)",
    )?;
    Ok((object, ntfy))
}

/// Um processo, dois mapeamentos: ordem, enchimento no fim do vetor, cheio
/// com descarte contado e o anel que volta a servir depois de esvaziado.
pub fn modelo(ctx: &Ctx) -> Outcome {
    let (object, ntfy) = new_ring(ctx)?;
    let mut cons = sys(
        Consumer::create(object, VA_A, DATA_LEN, KIND, ntfy),
        "Consumer::create",
    )?;
    let mut prod = sys(
        Producer::open(object, VA_B, DATA_LEN, ntfy, RING_BIT),
        "Producer::open",
    )?;
    let mut buf = [0u8; MAX_PAYLOAD];
    if cons.pop(&mut buf) != Ok(None) {
        return Err("anel novo devia estar vazio");
    }
    // Tamanhos variados (cruzam o fim do vetor muitas vezes), em rodadas
    // até encher: o que entrou sai igual e na ordem.
    let (mut next_in, mut next_out, mut accepted) = (0u64, 0u64, 0u64);
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for round in 0..200 {
        loop {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = (seed >> 33) as usize % 600;
            let payload: Vec<u8> = (0..len)
                .map(|i| (next_in as u8).wrapping_add(i as u8))
                .collect();
            match prod.push(KIND, &payload) {
                Ok(()) => {
                    next_in += 1;
                    accepted += 1;
                }
                Err(PushError::Full) => break,
                Err(_) => return Err("push inesperado"),
            }
        }
        let drain = if round % 3 == 0 { u64::MAX } else { 5 };
        let mut n = 0;
        while n < drain {
            let Some((kind, len)) = cons.pop(&mut buf).map_err(|_| "pop falhou")? else {
                break;
            };
            let ok = kind == KIND
                && buf[..len]
                    .iter()
                    .enumerate()
                    .all(|(i, &b)| b == (next_out as u8).wrapping_add(i as u8));
            if !ok {
                return Err("registro fora de ordem ou alterado");
            }
            next_out += 1;
            n += 1;
        }
    }
    while cons.pop(&mut buf).map_err(|_| "pop falhou")?.is_some() {
        next_out += 1;
    }
    if next_out != accepted || next_in != accepted {
        return Err("perdeu ou inventou registros");
    }
    if prod.dropped() == 0 || prod.dropped() != cons.dropped() {
        return Err("descarte por anel cheio não contado");
    }
    if prod.push(0, &[]) != Err(PushError::Invalid)
        || prod.push(KIND, &[0; MAX_PAYLOAD + 1]) != Err(PushError::Invalid)
    {
        return Err("push devia recusar kind 0 e carga grande");
    }
    let mut small = [0u8; 4];
    prod.push(KIND, &[1; 16]).map_err(|_| "push de 16")?;
    if cons.pop(&mut small) != Err(PopError::BufferTooSmall(16)) {
        return Err("buffer pequeno devia ser recusado");
    }
    Ok(())
}

/// O par mente: `tail` além do tamanho torna o anel inválido do lado do
/// consumidor, e `head` além de `tail` do lado do produtor.
pub fn par_que_mente(ctx: &Ctx) -> Outcome {
    let (object, ntfy) = new_ring(ctx)?;
    let mut cons = sys(
        Consumer::create(object, VA_A, DATA_LEN, KIND, ntfy),
        "Consumer::create",
    )?;
    let mut prod = sys(
        Producer::open(object, VA_B, DATA_LEN, ntfy, RING_BIT),
        "Producer::open",
    )?;
    // Escreve direto no cabeçalho por um terceiro mapeamento do objeto.
    let mut evil = sys(
        Mapping::new(
            SELF,
            object,
            VA_B + (1 << 20),
            object_bytes(DATA_LEN),
            ostd::kabi::vm::WRITE,
        ),
        "map",
    )?;
    let bytes = evil.bytes_mut().ok_or("mapeamento sem escrita")?;
    bytes[64..72].copy_from_slice(&(u64::from(DATA_LEN) + 8).to_le_bytes());
    let mut buf = [0u8; 16];
    if cons.pop(&mut buf) != Err(PopError::Corrupt) || cons.pop(&mut buf) != Err(PopError::Corrupt)
    {
        return Err("tail corrompido devia invalidar o anel");
    }
    let bytes = evil.bytes_mut().ok_or("mapeamento sem escrita")?;
    bytes[64..72].copy_from_slice(&0u64.to_le_bytes());
    bytes[128..136].copy_from_slice(&u64::MAX.to_le_bytes());
    let mut full = Err(PushError::Full);
    for _ in 0..(DATA_LEN / 16 + 2) {
        full = prod.push(KIND, &[0; 8]);
        if full != Ok(()) {
            break;
        }
    }
    if full != Err(PushError::Corrupt) {
        return Err("head corrompido devia invalidar o anel");
    }
    Ok(())
}

/// Aceite: [`ITEMS`] números em ordem entre dois processos; o produtor
/// repete o `push` quando o anel está cheio (o descarte é contado, não
/// perdido: o item volta a ser oferecido).
pub fn dois_processos(ctx: &Ctx) -> Outcome {
    let (object, ntfy) = new_ring(ctx)?;
    let mut cons = sys(
        Consumer::create(object, VA_A, DATA_LEN, KIND, ntfy),
        "Consumer::create",
    )?;
    let fs_len = {
        let head = sys(
            Mapping::new(SELF, ctx.bootfs, BOOTFS_VA, 4096, 0),
            "map bootfs",
        )?;
        let field = head.bytes().get(32..40).ok_or("cabeçalho do bootfs")?;
        u64::from_le_bytes(field.try_into().map_err(|_| "cabeçalho do bootfs")?)
    };
    let fs_map = sys(
        Mapping::new(SELF, ctx.bootfs, BOOTFS_VA, fs_len, 0),
        "map bootfs",
    )?;
    let fs = obfs::Image::parse(fs_map.bytes()).map_err(|_| "bootfs inválido")?;
    let elf = fs.find("utest").ok_or("utest fora do bootfs")?;
    let child = sys(
        process::load(&Spec {
            elf: elf.data,
            quota: ctx.quota,
            quota_bytes: CHILD_QUOTA,
            own_aspace: SELF,
            scratch_va: SCRATCH_VA,
            priority: 150,
        }),
        "process::load",
    )?;
    let c_quota = sys(child.give(child.quota, Rights::CREATE, 0), "give quota")?;
    let c_ring = sys(
        child.give(object, Rights::MAP | Rights::READ | Rights::WRITE, 0),
        "give anel",
    )?;
    let c_ntfy = sys(child.give(ntfy, Rights::SIGNAL, 0), "give ntfy")?;
    sys(
        bind_notify(child.thread, ntfy, DEATH_BIT),
        "bind_notify(morte)",
    )?;
    sys(
        child.start([
            handle_pair(c_quota, c_ntfy),
            handle_pair(c_ring, c_ring),
            CHILD_FLAG | ITEMS,
        ]),
        "start",
    )?;
    let mut buf = [0u8; 16];
    let (mut next, mut dead) = (0u64, false);
    while next < ITEMS {
        match cons.pop(&mut buf).map_err(|_| "pop falhou")? {
            Some((KIND, 8)) => {
                let v = u64::from_le_bytes(buf[..8].try_into().unwrap_or([0; 8]));
                if v != next {
                    return Err("perda ou reordenação");
                }
                next += 1;
            }
            Some(_) => return Err("registro inesperado"),
            None if dead => return Err("filho morreu antes do fim"),
            None => dead = cons.wait().map_err(|_| "wait falhou")? & DEATH_BIT != 0,
        }
    }
    if cons.pop(&mut buf) != Ok(None) {
        return Err("sobrou registro depois do último");
    }
    ostd::debug::print_fmt(format_args!(
        "utest: anel: {ITEMS} itens em ordem, {} descartes por anel cheio",
        cons.dropped()
    ));
    let _ = delete(ntfy);
    Ok(())
}

/// Modo filho: produz `0..n` no anel.
pub fn child(start: &Start) -> ! {
    let (quota, ntfy) = split_handle_pair(start.args[0]);
    let (ring, _) = split_handle_pair(start.args[1]);
    let n = start.args[2] & !CHILD_FLAG;
    ostd::rt::init(Env { quota });
    let Ok(mut prod) = Producer::open(ring, VA_A, DATA_LEN, ntfy, RING_BIT) else {
        ostd::process::abort("utest anel: filho não abriu o anel");
    };
    for i in 0..n {
        while let Err(e) = prod.push(KIND, &i.to_le_bytes()) {
            if e != PushError::Full {
                ostd::process::abort("utest anel: push falhou no filho");
            }
            ostd::thread::yield_now();
        }
    }
    ostd::thread::exit()
}
