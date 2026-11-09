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
//! raiz), `rsi` (o próprio `AddressSpace`) e `rdx` (a própria thread nos
//! 32 bits baixos e, nos altos, uma cópia do bootfs num `MemoryObject` só
//! com `READ | MAP`, de onde o `root` carrega os outros serviços; ADR
//! 0029).

use alloc::sync::Arc;

use kabi::boot::MemKind;
use kabi::vm::{EXEC, PAGE_SIZE, WRITE};
use kabi::{Handle, ObjectType, Rights, handle_pair};
use okernel::cap::{Cap, Object, SharedCapSpace, default_rights};
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
/// Quanto o boot espera o `root` terminar antes de desistir (o cenário
/// `cargo xtask test hello` faz 10⁶ idas e voltas de IPC sob o TCG).
const RUN_LIMIT_NS: u64 = 1_200_000_000_000;

/// O processo criado.
pub struct Process {
    /// Tabela de capabilities (cota raiz, espaço e thread).
    pub cspace: Arc<SharedCapSpace>,
    /// A thread inicial, já iniciada.
    pub thread: Arc<Thread>,
    /// Handles da cota, do espaço, da thread e do bootfs no `cspace`.
    pub handles: [Handle; 4],
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

/// Cria um `MemoryObject` de `len` bytes e copia `data` para ele a partir
/// do byte `pos`; devolve o handle e a capability.
fn new_copy(
    p: &SharedCapSpace,
    quota: Handle,
    len: u64,
    mut pos: u64,
    data: &[u8],
) -> Result<(Handle, Cap), &'static str> {
    let h = p
        .lock()
        .obj_create(quota, ObjectType::MemoryObject, len)
        .map_err(|_| "obj_create(MemoryObject)")?;
    let object = cap(p, h)?;
    let mo = object.object.as_memory_object().map_err(|_| "tipo")?;
    // Copia página a página.
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
    Ok((h, object))
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
    let (h, object) = new_copy(p, quota, len, va & (PAGE_SIZE - 1), data)?;
    vm_map(aspace, &object, va & !(PAGE_SIZE - 1), 0, len, flags).map_err(|_| "vm_map")?;
    drop(p.lock().delete(h));
    Ok(())
}

/// Processo ainda sem threads: o `CapSpace` com a cota raiz e o
/// `AddressSpace` com os segmentos do executável e a pilha inicial.
pub(crate) struct Image {
    /// Tabela de capabilities.
    pub cspace: Arc<SharedCapSpace>,
    /// Handle da cota raiz.
    pub quota: Handle,
    /// Handle do `AddressSpace`.
    pub aspace: Handle,
    /// Capability do `AddressSpace`.
    pub aspace_cap: Cap,
}

/// Monta o `CapSpace` e o `AddressSpace` de `elf` (já validado), com a
/// pilha da thread inicial abaixo de [`STACK_TOP`].
///
/// # Errors
///
/// O passo que falhou.
pub(crate) fn image(elf: &oelf::Elf<'_>) -> Result<Image, &'static str> {
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
    let image = Image {
        cspace,
        quota,
        aspace: a,
        aspace_cap: aspace,
    };
    map_stack(&image, STACK_TOP)?;
    Ok(image)
}

/// Mapeia em `p` uma pilha de [`STACK_BYTES`] abaixo de `top`.
///
/// # Errors
///
/// O passo que falhou.
pub(crate) fn map_stack(p: &Image, top: u64) -> Result<(), &'static str> {
    map_zeros(p, top - STACK_BYTES, STACK_BYTES, WRITE)
}

/// Mapeia em `p` `len` bytes zerados em `va` com `flags` (um objeto novo,
/// cuja capability some; a região o guarda).
///
/// # Errors
///
/// O passo que falhou.
pub(crate) fn map_zeros(p: &Image, va: u64, len: u64, flags: u64) -> Result<(), &'static str> {
    map_copy(&p.cspace, p.quota, &p.aspace_cap, (va, len, flags), &[])
}

/// Cria uma thread configurada no processo `p`, com um `SchedContext`
/// próprio sem limite e prioridade `priority`, ainda sem iniciar.
///
/// # Errors
///
/// O passo que falhou.
pub(crate) fn new_thread(p: &Image, priority: u64) -> Result<(Handle, Arc<Thread>), &'static str> {
    let cspace = &p.cspace;
    let t = cspace
        .lock()
        .obj_create(p.quota, ObjectType::Thread, 0)
        .map_err(|_| "obj_create(Thread)")?;
    let sc = cspace
        .lock()
        .obj_create(p.quota, ObjectType::SchedContext, 0)
        .map_err(|_| "obj_create(SchedContext)")?;
    let thread = Arc::clone(cap(cspace, t)?.object.as_thread().map_err(|_| "tipo")?);
    let sched = Arc::clone(
        cap(cspace, sc)?
            .object
            .as_sched_context()
            .map_err(|_| "tipo")?,
    );
    drop(cspace.lock().delete(sc));
    let period = 1_000_000;
    sched.configure(Params::new(period, period, priority).map_err(|_| "params")?);
    thread.bind_sched(sched).map_err(|_| "sched_bind")?;
    let space = Arc::clone(p.aspace_cap.object.as_address_space().map_err(|_| "tipo")?);
    thread
        .configure(Arc::clone(cspace), space)
        .map_err(|_| "thread_configure")?;
    Ok((t, thread))
}

/// Monta o processo do executável `elf` (já validado), com uma cópia de
/// `fs` (o bootfs) só para leitura, e inicia a thread.
///
/// # Errors
///
/// O passo que falhou.
pub fn spawn(elf: &oelf::Elf<'_>, fs: &[u8]) -> Result<Process, &'static str> {
    let p = image(elf)?;
    let (quota, a) = (p.quota, p.aspace);
    let (t, thread) = new_thread(&p, ROOT_PRIORITY)?;
    let fs = read_only_copy(&p, fs)?;
    let table = start_table(&p, fs)?;
    let entry = UserEntry {
        rip: elf.entry(),
        rsp: STACK_TOP,
        args: [
            u64::from(quota.raw()),
            u64::from(a.raw()),
            handle_pair(t, table),
        ],
    };
    kthread::start(&thread, &entry).map_err(|_| "thread_start")?;
    Ok(Process {
        cspace: p.cspace,
        thread,
        handles: [quota, a, t, fs],
    })
}

/// Monta a tabela de handles de partida (ADR 0036, item 5; T-355) em `p`: o
/// bootfs, a `DebugLog` de depuração e as duas linhas de pressão de memória
/// (ADR 0038). Devolve o handle da tabela, somente leitura, no `CapSpace` de
/// `p`.
///
/// # Errors
///
/// O passo que falhou.
fn start_table(p: &Image, fs: Handle) -> Result<Handle, &'static str> {
    use kabi::startup::{
        ENTRY_BYTES, HEADER_BYTES, KIND_BOOTFS, KIND_DEBUG_LOG, KIND_KERNEL_LOG, KIND_PRESSURE,
        MAGIC,
    };
    let mut entries: [(u32, u32); kabi::startup::MAX_ENTRIES] =
        [(0, 0); kabi::startup::MAX_ENTRIES];
    let mut n = 0;
    let mut push = |kind: u32, handle: Handle| {
        entries[n] = (kind, handle.raw());
        n += 1;
    };
    push(KIND_BOOTFS, fs);
    let log = {
        let object = Object::DebugLog(Arc::new(okernel::cap::object::DebugLog));
        let rights = kabi::Rights::WRITE | kabi::Rights::BIND;
        p.cspace
            .lock()
            .insert(Cap {
                object,
                rights,
                badge: 0,
            })
            .map_err(|_| "cap(DebugLog)")?
    };
    push(KIND_DEBUG_LOG, log);
    let quota = kcap::root_quota().ok_or("root_quota")?;
    let lines = crate::kpressure::create(&quota).map_err(|_| "kpressure")?;
    for irq in lines {
        let rights = default_rights(ObjectType::Interrupt);
        let h = p
            .cspace
            .lock()
            .insert(Cap {
                object: Object::Interrupt(irq),
                rights,
                badge: 0,
            })
            .map_err(|_| "cap(pressure)")?;
        push(KIND_PRESSURE, h);
    }
    push(KIND_KERNEL_LOG, kernel_log(p)?);
    let (device_quota, ecam) = device_caps(p)?;
    push(kabi::startup::KIND_DEVICE_QUOTA, device_quota);
    if let Some(ecam) = ecam {
        push(kabi::startup::KIND_ECAM, ecam);
    }
    let mut bytes = [0u8; 4096];
    bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    let count = u32::try_from(n).map_err(|_| "entradas")?;
    bytes[4..8].copy_from_slice(&count.to_le_bytes());
    for (i, (kind, handle)) in entries[..n].iter().enumerate() {
        let at = HEADER_BYTES + i * ENTRY_BYTES;
        bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&handle.to_le_bytes());
    }
    read_only_copy(p, &bytes)
}

/// Orçamento da cota de dispositivo: só metadados (objetos de MMIO e,
/// na T-404, `Interrupt`).
const DEVICE_QUOTA_BYTES: u64 = 256 << 10;

/// A cota de dispositivo (paga pela cota raiz) e, se o MCFG tiver o grupo
/// 0 a partir do barramento 0, a janela ECAM criada com ela (ADR 0043,
/// item 1; T-402).
///
/// # Errors
///
/// O passo que falhou.
fn device_caps(p: &Image) -> Result<(Handle, Option<Handle>), &'static str> {
    let root = kcap::root_quota().ok_or("root_quota")?;
    let device = okernel::cap::MemoryQuota::device(&root, DEVICE_QUOTA_BYTES)
        .map_err(|_| "cota de dispositivo")?;
    let quota = p
        .cspace
        .lock()
        .insert(Cap {
            object: Object::MemoryQuota(device),
            rights: Rights::CREATE,
            badge: 0,
        })
        .map_err(|_| "cap(cota de dispositivo)")?;
    let found = bootinfo::get()
        .and_then(kabi::boot::BootInfo::acpi_rsdp)
        .and_then(|rsdp| okernel::acpi::mcfg(&mut ktime::DirectRead, rsdp).ok());
    let Some(e) = found else {
        warn!("okernel: sem MCFG; o pcid cai nas portas 0xCF8/0xCFC");
        return Ok((quota, None));
    };
    if e.start_bus != 0 {
        warn!(
            "okernel: ECAM começa no barramento {}; ignorada",
            e.start_bus
        );
        return Ok((quota, None));
    }
    let bytes = (u64::from(e.end_bus) + 1) << 20;
    let ecam = p
        .cspace
        .lock()
        .obj_create_device(quota, e.base, bytes)
        .map_err(|_| "ECAM")?;
    info!(
        "okernel: ECAM em {:#x}, barramentos 0 a {}",
        e.base, e.end_bus
    );
    Ok((quota, Some(ecam)))
}

/// Cria o anel do log do kernel (cobrado da cota raiz), passa o `klog` a
/// escrever nele e devolve em `p` uma capability só com `READ | MAP`.
///
/// # Errors
///
/// O passo que falhou.
fn kernel_log(p: &Image) -> Result<Handle, &'static str> {
    let len = crate::klogring::OBJECT_BYTES;
    let full = p
        .cspace
        .lock()
        .obj_create(p.quota, ObjectType::MemoryObject, len)
        .map_err(|_| "obj_create(anel do kernel)")?;
    let object = cap(&p.cspace, full)?;
    let mo = object.object.as_memory_object().map_err(|_| "tipo")?;
    drop(crate::klogring::install(Arc::clone(mo))?);
    let ro = p
        .cspace
        .lock()
        .mint(full, Rights::READ | Rights::MAP, None)
        .map_err(|_| "cap_mint(anel do kernel)")?;
    drop(p.cspace.lock().delete(full));
    Ok(ro)
}

/// Copia `data` para um `MemoryObject` novo em `p` e devolve um handle só
/// com `READ | MAP` para ele (a capability completa some).
///
/// # Errors
///
/// O passo que falhou.
fn read_only_copy(p: &Image, data: &[u8]) -> Result<Handle, &'static str> {
    let len = (data.len() as u64).next_multiple_of(PAGE_SIZE);
    let (full, _) = new_copy(&p.cspace, p.quota, len, 0, data)?;
    let fs = p
        .cspace
        .lock()
        .mint(full, Rights::READ | Rights::MAP, None)
        .map_err(|_| "cap_mint(bootfs)")?;
    drop(p.cspace.lock().delete(full));
    Ok(fs)
}

/// Acha, confere e inicia o `root` do bootfs `image`.
///
/// # Errors
///
/// O passo que falhou.
pub fn load(image: &[u8]) -> Result<Process, &'static str> {
    load_named(image, ROOT_NAME)
}

/// Como [`load`], com o serviço `name` do bootfs no lugar do `root`: ele
/// recebe as mesmas capabilities iniciais (`test=user` inicia o `utest`).
///
/// # Errors
///
/// O passo que falhou.
pub fn load_named(image: &[u8], name: &str) -> Result<Process, &'static str> {
    let fs = obfs::Image::parse(image).map_err(|_| "bootfs inválido")?;
    let entry = fs.find(name).ok_or("bootfs sem o serviço")?;
    if !entry.verify() {
        return Err("hash do serviço não confere");
    }
    let elf = oelf::Elf::parse_user(entry.data).map_err(|_| "ELF do serviço inválido")?;
    spawn(&elf, image)
}

/// Roda as prontas até `thread` terminar (ou o prazo vencer).
pub fn run_until_exit(thread: &Thread, limit_ns: u64) -> bool {
    let give_up = ktime::now_ns().saturating_add(limit_ns);
    while thread.state() != RunState::Exited && ktime::now_ns() < give_up {
        kthread::yield_now();
        if thread.state() != RunState::Exited && !kthread::idle_steal() {
            // Sem nada pronto: dorme até o próximo timer (armado aqui
            // também, para nunca dormir sem prazo, mas sem adiar um que já
            // está armado para antes, como o de um `Timer`).
            crate::kpressure::poll();
            ktime::arm_by(ktime::now_ns() + 10_000_000);
            cpu::wait_for_interrupt();
        }
    }
    thread.state() == RunState::Exited
}

/// Boot normal: inicia o `root` do bootfs e espera ele terminar.
pub fn run() {
    run_named(ROOT_NAME);
}

/// Inicia o serviço `name` do bootfs no lugar do `root` e espera ele
/// terminar (`test=user`, T-332).
pub fn run_named(name: &str) {
    let Some(image) = bootfs() else {
        warn!("okernel: sem bootfs; {name} não iniciado");
        return;
    };
    let process = match load_named(image, name) {
        Ok(p) => p,
        Err(e) => {
            error!("okernel: {name} não iniciado: {e}");
            return;
        }
    };
    info!(
        "okernel: {name} carregado do bootfs ({} KiB), iniciando no anel 3",
        image.len() >> 10
    );
    if run_until_exit(&process.thread, RUN_LIMIT_NS) {
        info!("okernel: {name} terminou");
    } else {
        error!(
            "okernel: {name} não terminou em {} s",
            RUN_LIMIT_NS / 1_000_000_000
        );
    }
}
