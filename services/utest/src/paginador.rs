//! Testes do `memd` (T-361; ADR 0038, item 3): o tratador de faltas roda na
//! thread do teste e atende as faltas de uma thread cliente do mesmo
//! processo, que tem o endpoint dele como endpoint de exceções.

#![allow(
    clippy::cast_possible_truncation,
    reason = "índices pequenos em x86-64"
)]
use memd::{Decision, Denial, Kind, MemError, NULL_LIMIT, Pager};
use ostd::cap::{create, delete, mint};
use ostd::kabi::exit::CAUSE_FAULTED;
use ostd::kabi::fault::PAGE_FAULT;
use ostd::kabi::vm::{PAGE_SIZE, WRITE};
use ostd::kabi::{ObjectType, Rights};
use ostd::mem;
use ostd::thread::Builder;
use ostd::vm::{Mapping, SELF};

use crate::{Ctx, Outcome, child_quota};

/// Badge do endpoint de exceções: o `id` do "processo" cliente.
const OWNER: u64 = 0x2a;
/// Onde o objeto gerenciado é mapeado.
const VA: u64 = 0x2_0000_0000;
/// Onde o teste de acesso inválido mapeia o objeto dele: o cliente morre
/// sem desmapear, então o teste desmapeia depois do `join`.
const VA_INVALID: u64 = 0x3_0000_0000;
/// Heap gerenciado de 64 MiB.
const HEAP: u64 = 64 << 20;
/// Páginas tocadas, uma a cada MiB.
const TOUCHED: u64 = 64;

/// Endpoint, `Reply` e a capability de envio com o badge do cliente.
struct Wire {
    ep: ostd::kabi::Handle,
    reply: ostd::kabi::Handle,
    exc: ostd::kabi::Handle,
}

impl Wire {
    fn new(ctx: &Ctx) -> Result<Self, &'static str> {
        let ep = create(ctx.quota, ObjectType::Endpoint, 0).map_err(|_| "create(ep)")?;
        let reply = create(ctx.quota, ObjectType::Reply, 0).map_err(|_| "create(reply)")?;
        let exc = mint(ep, Rights::SEND, OWNER, None).map_err(|_| "mint")?;
        Ok(Self { ep, reply, exc })
    }
}

impl Drop for Wire {
    fn drop(&mut self) {
        let _ = (delete(self.exc), delete(self.ep), delete(self.reply));
    }
}

/// Aceite da T-361: um heap de 64 MiB tocado esparsamente consome só as
/// páginas tocadas, e o conteúdo escrito volta na leitura.
pub fn heap_esparso(ctx: &Ctx) -> Outcome {
    let q = child_quota(ctx, 4 << 20)?;
    let obj = mem::create_lazy(q, HEAP).map_err(|_| "create_lazy")?;
    let verdict = heap_com(ctx, obj);
    let _ = (delete(obj), delete(q));
    verdict
}

fn heap_com(ctx: &Ctx, obj: ostd::kabi::Handle) -> Outcome {
    let mut map = Mapping::new(SELF, obj, VA, HEAP, WRITE).map_err(|_| "vm_map")?;
    let wire = Wire::new(ctx)?;
    let mut pager = Pager::new();
    let owner = memd::owner_of(OWNER);
    pager
        .manage(owner, obj, VA, HEAP, Kind::Heap)
        .map_err(|_| "manage")?;
    if pager.manage(owner, obj, VA + PAGE_SIZE, PAGE_SIZE, Kind::Anon)
        != Err(MemError::InvalidArgument)
    {
        return Err("manage sobreposto devia dar InvalidArgument");
    }
    let before = mem::stats().map_err(|_| "sys_info(3)")?.lazy_committed;
    let client = Builder::new()
        .exception_endpoint(wire.exc)
        .spawn(move || {
            let bytes = map.bytes_mut().expect("gravável");
            let step = (HEAP / TOUCHED) as usize;
            for i in 0..TOUCHED as usize {
                bytes[i * step + 8] = i as u8;
            }
            (0..TOUCHED as usize).all(|i| bytes[i * step + 8] == i as u8)
        })
        .map_err(|_| "spawn")?;
    memd::serve(&mut pager, wire.ep, wire.reply, |p| {
        p.served + p.denied >= TOUCHED
    })
    .map_err(|_| "serve")?;
    let ok = client.join().map_err(|_| "o cliente morreu")?;
    let after = mem::stats().map_err(|_| "sys_info(3)")?.lazy_committed;
    if !ok {
        return Err("o conteúdo não voltou");
    }
    if pager.served != TOUCHED || pager.denied != 0 {
        return Err("o memd devia atender exatamente as páginas tocadas");
    }
    let used = after.saturating_sub(before);
    ostd::debug::print_fmt(format_args!(
        "utest: memd: heap de 64 MiB, {TOUCHED} páginas tocadas, {used} comprometidas"
    ));
    if !(TOUCHED..=TOUCHED + 8).contains(&used) {
        return Err("o heap esparso comprometeu páginas demais");
    }
    Ok(())
}

/// Acesso fora das regiões encerra a thread (`Faulted`, vetor 14), e as
/// regras de negação valem para nulo, proteção e execução.
pub fn acesso_invalido_encerra(ctx: &Ctx) -> Outcome {
    let q = child_quota(ctx, 1 << 20)?;
    let obj = mem::create_lazy(q, 2 * PAGE_SIZE).map_err(|_| "create_lazy")?;
    let verdict = invalido_com(ctx, obj);
    let _ = (delete(obj), delete(q));
    verdict
}

fn invalido_com(ctx: &Ctx, obj: ostd::kabi::Handle) -> Outcome {
    let mut map =
        Mapping::new(SELF, obj, VA_INVALID, 2 * PAGE_SIZE, WRITE).map_err(|_| "vm_map")?;
    let wire = Wire::new(ctx)?;
    let mut pager = Pager::new();
    let owner = memd::owner_of(OWNER);
    // Só a primeira página é gerenciada; a segunda fica fora.
    pager
        .manage(owner, obj, VA_INVALID, PAGE_SIZE, Kind::Stack)
        .map_err(|_| "manage")?;
    let rules = [
        (0x10, 0b110, Denial::Null),
        (VA_INVALID, 0b111, Denial::Protection),
        (VA_INVALID, 0b1_0100, Denial::Exec),
        (VA_INVALID + PAGE_SIZE, 0b110, Denial::Unmanaged),
    ];
    for (addr, err, want) in rules {
        if pager.decide(owner, PAGE_FAULT, err, addr) != Decision::Deny(want) {
            return Err("regra de negação errada");
        }
    }
    if pager.decide(owner, 6, 0, VA_INVALID) != Decision::Deny(Denial::NotPageFault)
        || pager.decide(owner + 1, PAGE_FAULT, 0b110, VA_INVALID)
            != Decision::Deny(Denial::Unmanaged)
        || NULL_LIMIT != 0x1_0000
    {
        return Err("exceção comum ou outro processo deviam ser negados");
    }
    let client = Builder::new()
        .exception_endpoint(wire.exc)
        .spawn(move || {
            let bytes = map.bytes_mut().expect("gravável");
            bytes[0] = 1;
            bytes[PAGE_SIZE as usize] = 2;
        })
        .map_err(|_| "spawn")?;
    memd::serve(&mut pager, wire.ep, wire.reply, |p| p.denied >= 1).map_err(|_| "serve")?;
    let joined = client.join_status();
    let _ = ostd::vm::unmap(SELF, VA_INVALID, 2 * PAGE_SIZE);
    match joined {
        Err(d)
            if d.cause == CAUSE_FAULTED
                && d.code == PAGE_FAULT
                && d.aux == VA_INVALID + PAGE_SIZE => {}
        _ => return Err("o cliente devia morrer Faulted no endereço fora da região"),
    }
    if pager.served != 1
        || pager.last_denial.map(|(_, a, d)| (a, d))
            != Some((VA_INVALID + PAGE_SIZE, Denial::Unmanaged))
    {
        return Err("contagem do memd errada");
    }
    Ok(())
}
