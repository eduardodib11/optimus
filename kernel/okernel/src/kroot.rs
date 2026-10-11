//! O processo `root` a partir do bootfs (T-211; SDD v1.0, seções 5.3 e 7.2).
//!
//! O optboot entrega o bootfs já verificado em `BootInfo.bootfs`, numa faixa
//! `Bootfs` do mapa de memória que o mapa direto cobre. O kernel acha a
//! entrada `root`, confere de novo o BLAKE3 dela, valida o ELF com
//! `oelf` (segmentos só na faixa de usuário, W^X) e monta o processo: um
//! `CapSpace` com a cota raiz, um `AddressSpace` com cada segmento copiado
//! para um `MemoryObject` próprio e uma pilha, e uma thread no anel 3 com
//! um `SchedContext` sem limite de prioridade [`ROOT_PRIORITY`].
//!
//! A thread começa em `e_entry` com os handles iniciais em `rdi` (cota
//! raiz), `rsi` (o próprio `AddressSpace`) e `rdx` (a própria thread).

use alloc::sync::Arc;

use kabi::boot::MemKind;
use kabi::vm::{EXEC, PAGE_SIZE, WRITE};
use kabi::{Handle, ObjectType};
use okernel::cap::{Cap, SharedCapSpace};
use okernel::sched::Params;
use okernel::thread::{RunState, Thread};
use okernel::vm::vm_map;

use crate::arch::x86_64::cpu;
use crate::kthread::{self, UserEntry};
use crate::{bootinfo, kcap, kmem, ktime};

mod tests;
pub use tests::TESTS;

/// Nome do `root` no bootfs.
pub const ROOT_NAME: &str = "root";
/// Topo da pilha da thread inicial (uma página de guarda acima, sem mapa).
pub const STACK_TOP: u64 = 0x0000_7fff_ffff_0000;
/// Tamanho da pilha da thread inicial.
pub const STACK_BYTES: u64 = 64 << 10;
/// Prioridade do `root` (serviços de sistema, seção 6.6).
pub const ROOT_PRIORITY: u64 = 150;
/// Quanto o boot espera o `root` terminar antes de desistir.
const RUN_LIMIT_NS: u64 = 10_000_000_000;

/// O processo criado.
pub struct Process {
    /// Tabela de capabilities (cota raiz, espaço e thread).
    pub cspace: Arc<SharedCapSpace>,
    /// A thread inicial, já iniciada.
    pub thread: Arc<Thread>,
    /// Handles da cota, do espaço e da thread no `cspace`.
    pub handles: [Handle; 3],
}

/// A imagem do bootfs, se a `BootInfo` a trouxer numa faixa `Bootfs`.
pub fn bootfs() -> Option<&'static [u8]> {
    let info = bootinfo::get()?;
    let r = info.bootfs;
    let end = r.base.checked_add(r.len)?;
    let map = bootinfo::memory_map(info)?;
    let inside = map
        .iter()
        .any(|m| m.kind() == MemKind::Bootfs && m.base <= r.base && end <= m.end());
    if r.len == 0 || !inside {
        return None;
    }
    let len = usize::try_from(r.len).ok()?;
    // SAFETY: a faixa é `Bootfs` no mapa do optboot: nunca vai ao buddy,
    // ninguém a grava depois da entrega e o mapa direto a cobre
    // (`direct_map_limit` conta as faixas `Bootfs`).
    Some(unsafe {
        core::slice::from_raw_parts(
            kmem::direct(okernel::mm::PhysAddr(r.base)) as *const u8,
            len,
        )
    })
}

fn cap(space: &SharedCapSpace, h: Handle) -> Result<Cap, &'static str> {
    space.lock().get(h).cloned().map_err(|_| "handle")
}

/// Cria um `MemoryObject` de `len` bytes, copia `data` para ele a partir
/// do deslocamento de `va` na página e o mapeia na página de `va` com
/// `flags`; a capability do objeto some (a região guarda o objeto).
fn map_copy(
    p: &SharedCapSpace,
    quota: Handle,
    aspace: &Cap,
    (va, len, flags): (u64, u64, u64),
    data: &[u8],
) -> Result<(), &'static str> {
    let h = p
        .lock()
        .obj_create(quota, ObjectType::MemoryObject, len)
        .map_err(|_| "obj_create(MemoryObject)")?;
    let object = cap(p, h)?;
    let mo = object.object.as_memory_object().map_err(|_| "tipo")?;
    // Copia `data` para os bytes a partir de `va % 4 KiB`, página a página.
    let mut pos = va & (PAGE_SIZE - 1);
    let mut rest = data;
    while !rest.is_empty() {
        let off = pos % PAGE_SIZE;
        let n = rest
            .len()
            .min(usize::try_from(PAGE_SIZE - off).unwrap_or(0));
        let frame = mo.frame(pos / PAGE_SIZE).ok_or("frame")?;
        // SAFETY: frame recém-alocado do objeto, só dele, no mapa direto
        // (RW); `off + n` não passa da página.
        unsafe {
            core::ptr::copy_nonoverlapping(
                rest.as_ptr(),
                (kmem::direct(frame) + off) as *mut u8,
                n,
            );
        }
        pos += n as u64;
        rest = &rest[n..];
    }
    vm_map(aspace, &object, va & !(PAGE_SIZE - 1), 0, len, flags).map_err(|_| "vm_map")?;
    drop(p.lock().delete(h));
    Ok(())
}

/// Monta o processo do executável `elf` (já validado) e inicia a thread.
///
/// # Errors
///
/// O passo que falhou.
pub fn spawn(elf: &oelf::Elf<'_>) -> Result<Process, &'static str> {
    if elf.is_relocatable() {
        return Err("root relocável (PIE) ainda não é suportado");
    }
    let (cspace, quota) = kcap::root_cap_space().map_err(|_| "root_cap_space")?;
    let a = cspace
        .lock()
        .obj_create(quota, ObjectType::AddressSpace, 0)
        .map_err(|_| "obj_create(AddressSpace)")?;
    let aspace = cap(&cspace, a)?;
    for seg in elf.segments() {
        let start = seg.vaddr & !(PAGE_SIZE - 1);
        let end = (seg.vaddr + seg.memsz).next_multiple_of(PAGE_SIZE);
        let flags = if seg.flags.writable() {
            WRITE
        } else if seg.flags.executable() {
            EXEC
        } else {
            0
        };
        map_copy(
            &cspace,
            quota,
            &aspace,
            (seg.vaddr, end - start, flags),
            seg.data,
        )?;
    }
    map_copy(
        &cspace,
        quota,
        &aspace,
        (STACK_TOP - STACK_BYTES, STACK_BYTES, WRITE),
        &[],
    )?;
    let t = cspace
        .lock()
        .obj_create(quota, ObjectType::Thread, 0)
        .map_err(|_| "obj_create(Thread)")?;
    let sc = cspace
        .lock()
        .obj_create(quota, ObjectType::SchedContext, 0)
        .map_err(|_| "obj_create(SchedContext)")?;
    let thread = Arc::clone(cap(&cspace, t)?.object.as_thread().map_err(|_| "tipo")?);
    let sched = Arc::clone(
        cap(&cspace, sc)?
            .object
            .as_sched_context()
            .map_err(|_| "tipo")?,
    );
    drop(cspace.lock().delete(sc));
    let period = 1_000_000;
    sched.configure(Params::new(period, period, ROOT_PRIORITY).map_err(|_| "params")?);
    thread.bind_sched(sched).map_err(|_| "sched_bind")?;
    let space = Arc::clone(aspace.object.as_address_space().map_err(|_| "tipo")?);
    thread
        .configure(Arc::clone(&cspace), space)
        .map_err(|_| "thread_configure")?;
    let entry = UserEntry {
        rip: elf.entry(),
        rsp: STACK_TOP,
        args: [quota, a, t].map(|h| u64::from(h.raw())),
    };
    kthread::start(&thread, &entry).map_err(|_| "thread_start")?;
    Ok(Process {
        cspace,
        thread,
        handles: [quota, a, t],
    })
}

/// Acha, confere e inicia o `root` do bootfs `image`.
///
/// # Errors
///
/// O passo que falhou.
pub fn load(image: &[u8]) -> Result<Process, &'static str> {
    let fs = obfs::Image::parse(image).map_err(|_| "bootfs inválido")?;
    let entry = fs.find(ROOT_NAME).ok_or("bootfs sem root")?;
    if !entry.verify() {
        return Err("hash do root não confere");
    }
    let elf = oelf::Elf::parse_user(entry.data).map_err(|_| "ELF do root inválido")?;
    spawn(&elf)
}

/// Roda as prontas até `thread` terminar (ou o prazo vencer).
pub fn run_until_exit(thread: &Thread, limit_ns: u64) -> bool {
    let give_up = ktime::now_ns().saturating_add(limit_ns);
    while thread.state() != RunState::Exited && ktime::now_ns() < give_up {
        kthread::yield_now();
        if thread.state() != RunState::Exited {
            // Sem nada pronto: dorme até o próximo timer (armado aqui
            // também, para nunca dormir sem prazo).
            ktime::set_timer_at(ktime::now_ns() + 10_000_000);
            cpu::wait_for_interrupt();
        }
    }
    thread.state() == RunState::Exited
}

/// Boot normal: inicia o `root` do bootfs e espera ele terminar.
pub fn run() {
    let Some(image) = bootfs() else {
        warn!("okernel: sem bootfs; root não iniciado");
        return;
    };
    let process = match load(image) {
        Ok(p) => p,
        Err(e) => {
            error!("okernel: root não iniciado: {e}");
            return;
        }
    };
    info!(
        "okernel: root carregado do bootfs ({} KiB), iniciando no anel 3",
        image.len() >> 10
    );
    if run_until_exit(&process.thread, RUN_LIMIT_NS) {
        info!("okernel: root terminou");
    } else {
        error!(
            "okernel: root não terminou em {} s",
            RUN_LIMIT_NS / 1_000_000_000
        );
    }
}
