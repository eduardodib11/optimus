//! Testes de kernel de threads de usuário e syscalls (T-206) e do
//! escalonador (T-207, em `sched`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

use kabi::vm::{EXEC, PAGE_SIZE, WRITE};
use kabi::{Error, Handle, ObjectType};
use okernel::cap::{Cap, MemoryQuota, SharedCapSpace};
use okernel::sched::Params;
use okernel::thread::{RunState, Thread};
use okernel::vm::vm_map;

use super::{UserEntry, start, take_debug_log, yield_now};
use crate::arch::x86_64::{apic, cpu, probe};
use crate::kcap::{root_cap_space, root_quota};
use crate::ktest::{Outcome, Test};
use crate::kvm::activate;
use crate::{kmem, ktime};

mod sched;
mod smp;
mod smp_ipc;
mod sync;
mod tlb;

/// Testes de kernel de threads de usuário.
pub const TESTS: &[Test] = &[
    Test {
        name: "thread.duas_threads_de_usuario_alternam",
        run: alternam,
    },
    Test {
        name: "thread.start_recusa_rip_de_kernel",
        run: start_recusa,
    },
    Test {
        name: "thread.copias_de_usuario_so_na_metade_baixa",
        run: copias,
    },
    Test {
        name: "sched.sem_orcamento_espera_o_proximo_periodo",
        run: sched::sem_orcamento_espera,
    },
    Test {
        name: "ntfy.irq_acorda_thread_esperando",
        run: sync::irq_acorda,
    },
    Test {
        name: "futex.mutex_de_usuario_com_4_threads",
        run: sync::mutex_4_threads,
    },
    Test {
        name: "smp.thread_bloqueada_acorda_na_cpu_certa",
        run: smp::acorda_na_cpu_certa,
    },
    Test {
        name: "smp.dois_processos_alternam_em_cpus_distintas",
        run: smp::alternam_em_cpus_distintas,
    },
    Test {
        name: "smp.ipc_servidor_segue_quem_chama",
        run: smp_ipc::servidor_segue_quem_chama,
    },
    Test {
        name: "smp.ipc_dois_clientes_em_cpus_distintas",
        run: smp_ipc::dois_clientes_em_cpus_distintas,
    },
    Test {
        name: "smp.mutex_de_usuario_em_4_cpus",
        run: smp_ipc::mutex_de_usuario_em_4_cpus,
    },
    Test {
        name: "smp.destruicao_concorrente_acorda_com_peer_closed",
        run: smp_ipc::destruicao_concorrente_acorda_com_peer_closed,
    },
    Test {
        name: "smp.vm_unmap_faz_a_outra_cpu_faltar",
        run: tlb::unmap_faz_faltar,
    },
    Test {
        name: "smp.shootdown_sem_traducao_velha",
        run: tlb::sem_traducao_velha,
    },
    Test {
        name: "smp.shootdown_do_kernel_sem_traducao_velha",
        run: tlb::kernel_sem_traducao_velha,
    },
];

unsafe extern "C" {
    static user_test_start: u8;
    static user_test_end: u8;
    static user_alternate: u8;
}

/// Onde o teste mapeia o código (RX) e os dados (RW) do usuário.
pub const CODE_VA: u64 = 0x40_0000;
/// Páginas de dados, uma por thread.
pub const DATA_VA: u64 = 0x50_0000;
const VOLTAS: u64 = 8;

/// Um processo de teste: tabela de capabilities, espaço e o código de
/// `user.S` mapeado.
pub struct Process {
    /// Tabela de capabilities (com a cota raiz).
    pub cspace: Arc<SharedCapSpace>,
    /// Handle da cota.
    pub quota: Handle,
    /// Capability do espaço.
    pub aspace: Cap,
}

/// A capability `h` de `space`, clonada.
pub fn cap(space: &SharedCapSpace, h: Handle) -> Result<Cap, &'static str> {
    space.lock().get(h).cloned().map_err(|_| "handle")
}

/// Endereço de usuário de um símbolo de `user.S`.
pub fn user_symbol(sym: *const u8) -> u64 {
    let start = (&raw const user_test_start).addr();
    CODE_VA + (sym.addr() - start) as u64
}

/// Cria o processo: código RX em [`CODE_VA`] e `data_pages` páginas RW em
/// [`DATA_VA`].
pub fn process(data_pages: u64) -> Result<Process, &'static str> {
    let (cspace, quota) = root_cap_space().map_err(|_| "cspace")?;
    let start = (&raw const user_test_start).addr();
    let len = (&raw const user_test_end).addr() - start;
    ensure!(len as u64 <= PAGE_SIZE);
    let (a, code, data) = {
        let mut s = cspace.lock();
        let a = s.obj_create(quota, ObjectType::AddressSpace, 0);
        let c = s.obj_create(quota, ObjectType::MemoryObject, PAGE_SIZE);
        let d = s.obj_create(quota, ObjectType::MemoryObject, data_pages * PAGE_SIZE);
        (a, c, d)
    };
    let (a, code, data) = (
        cap(&cspace, a.map_err(|_| "aspace")?)?,
        cap(&cspace, code.map_err(|_| "code")?)?,
        cap(&cspace, data.map_err(|_| "data")?)?,
    );
    let frame = code
        .object
        .as_memory_object()
        .map_err(|_| "tipo")?
        .frame(0)
        .ok_or("frame")?;
    // SAFETY: `user.S` fica nos dados só de leitura do kernel, `len` bytes
    // a partir de `start`; o frame é do objeto recém-criado, no mapa direto.
    unsafe {
        core::ptr::copy_nonoverlapping(start as *const u8, kmem::direct(frame) as *mut u8, len);
    }
    ensure!(vm_map(&a, &code, CODE_VA, 0, PAGE_SIZE, EXEC).is_ok());
    ensure!(vm_map(&a, &data, DATA_VA, 0, data_pages * PAGE_SIZE, WRITE).is_ok());
    Ok(Process {
        cspace,
        quota,
        aspace: a,
    })
}

/// Cria uma thread no processo, configurada e ligada a um `SchedContext`
/// sem limite de prioridade 100, ainda sem iniciar; devolve o handle dela
/// também, para o teste apagá-la no fim.
pub fn thread(p: &Process) -> Result<(Handle, Arc<Thread>), &'static str> {
    let params = Params::new(1_000_000, 1_000_000, 100).map_err(|_| "params")?;
    thread_with(p, params)
}

/// Como [`thread`], com o `SchedContext` configurado com `params`.
pub fn thread_with(p: &Process, params: Params) -> Result<(Handle, Arc<Thread>), &'static str> {
    let (h, t) = bare_thread(p)?;
    let sc = p
        .cspace
        .lock()
        .obj_create(p.quota, ObjectType::SchedContext, 0)
        .map_err(|_| "obj_create(SchedContext)")?;
    let sc = Arc::clone(
        cap(&p.cspace, sc)?
            .object
            .as_sched_context()
            .map_err(|_| "tipo")?,
    );
    sc.configure(params);
    t.bind_sched(sc).map_err(|_| "bind")?;
    Ok((h, t))
}

/// Thread configurada, sem `SchedContext`.
fn bare_thread(p: &Process) -> Result<(Handle, Arc<Thread>), &'static str> {
    let h = p
        .cspace
        .lock()
        .obj_create(p.quota, ObjectType::Thread, 0)
        .map_err(|_| "obj_create(Thread)")?;
    let t = Arc::clone(cap(&p.cspace, h)?.object.as_thread().map_err(|_| "tipo")?);
    let aspace = Arc::clone(p.aspace.object.as_address_space().map_err(|_| "tipo")?);
    t.configure(Arc::clone(&p.cspace), aspace)
        .map_err(|_| "configure")?;
    Ok((h, t))
}

/// Um `MemoryObject` de uma página de um processo de teste, visto pelo
/// kernel pelo mapa direto.
pub struct Page {
    /// Handle do objeto, para o teste apagá-lo no fim.
    pub handle: Handle,
    /// Capability do objeto, para mapeá-lo.
    pub cap: Cap,
    base: u64,
}

impl Page {
    /// Cria a página em `p` (zerada).
    pub fn new(p: &Process) -> Result<Self, &'static str> {
        let handle = p
            .cspace
            .lock()
            .obj_create(p.quota, ObjectType::MemoryObject, PAGE_SIZE)
            .map_err(|_| "obj_create(MemoryObject)")?;
        let cap = cap(&p.cspace, handle)?;
        let frame = cap
            .object
            .as_memory_object()
            .map_err(|_| "tipo")?
            .frame(0)
            .ok_or("frame")?;
        Ok(Self {
            handle,
            cap,
            base: kmem::direct(frame),
        })
    }

    /// A palavra `i` da página.
    pub fn word(&self, i: usize) -> &AtomicU64 {
        assert!(i < 512);
        // SAFETY: o frame é do MemoryObject que `self.cap` mantém vivo; no
        // mapa direto, alinhado a 4 KiB, e só se acessa como atômicos (o
        // usuário que o mapeia também é parte do teste).
        unsafe { &*(self.base as *const AtomicU64).add(i) }
    }
}

/// Prazo de [`run_until_exit`].
const RUN_LIMIT_NS: u64 = 20_000_000_000;

/// Roda as prontas desta CPU até todas as `threads` saírem de vez
/// (terminadas e fora de qualquer CPU; as que acordaram noutra CPU rodam
/// lá) ou o prazo vencer.
pub fn run_until_exit(threads: &[Arc<Thread>]) -> Outcome {
    let give_up = ktime::now_ns() + RUN_LIMIT_NS;
    while ktime::now_ns() < give_up {
        if threads
            .iter()
            .all(|t| t.state() == RunState::Exited && !t.on_cpu())
        {
            return Ok(());
        }
        yield_now();
        crate::ksmp::ipi::poll();
    }
    Err("as threads não terminaram")
}

/// Espera (até 1 s, rodando as prontas) a cota voltar a `used`: a última
/// referência a uma thread que rodou noutra CPU é solta lá, logo depois da
/// troca que a tirou da CPU.
pub fn settled(quota: &MemoryQuota, used: u64) -> bool {
    let give_up = ktime::now_ns() + 1_000_000_000;
    while quota.used() != used {
        if ktime::now_ns() > give_up {
            return false;
        }
        yield_now();
        crate::ksmp::ipi::poll();
    }
    true
}

/// Apaga as capabilities das threads (quebra o ciclo thread ↔ `CapSpace`).
pub fn delete(p: &Process, handles: &[Handle]) -> Outcome {
    for &h in handles {
        let cap = p.cspace.lock().delete(h).map_err(|_| "delete")?;
        drop(cap);
    }
    Ok(())
}

fn alternam() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let p = process(2)?;
        let entry = user_symbol(&raw const user_alternate);
        let mut handles = Vec::new();
        let mut threads = Vec::new();
        for (i, letter) in b"AB".iter().copied().enumerate() {
            let (h, t) = thread(&p)?;
            let page = DATA_VA + i as u64 * PAGE_SIZE;
            let e = UserEntry {
                rip: entry,
                rsp: page + PAGE_SIZE,
                args: [u64::from(letter), VOLTAS, page],
            };
            ensure!(start(&t, &e).is_ok());
            ensure!(start(&t, &e) == Err(Error::Busy));
            handles.push(h);
            threads.push(t);
        }
        let _ = take_debug_log();
        let fires = apic::timer_fires().0;
        run_until_exit(&threads)?;
        let preempted = apic::timer_fires().0 - fires;
        let (log, len) = take_debug_log();
        let text = core::str::from_utf8(&log[..len]).unwrap_or("?");
        info!("ktest: · sequência impressa pelas threads: {text} ({preempted} disparos do timer)");
        let count = |c| log[..len].iter().map(|&b| u64::from(b == c)).sum::<u64>();
        ensure!(len as u64 == 2 * VOLTAS && count(b'A') == VOLTAS && count(b'B') == VOLTAS);
        // Só a preempção pelo timer (fatia de 5 ms vencida entre a impressão
        // e o yield) quebra a alternância; no TCG uma preempção do QEMU pelo
        // host basta para isso, então lá a ordem só é exigida sem disparo.
        let strict = preempted == 0 || !cpu::under_tcg();
        ensure!(!strict || log[..len].chunks(2).all(|pair| pair == b"AB"));
        delete(&p, &handles)?;
    }
    ensure!(settled(&quota, used0));
    Ok(())
}

fn start_recusa() -> Outcome {
    let p = process(1)?;
    let (h, t) = thread(&p)?;
    let kernel = start_recusa as *const () as u64;
    let bad = [
        (kernel, DATA_VA),
        (CODE_VA, kernel),
        (0, DATA_VA),
        (kabi::vm::USER_END, DATA_VA),
    ];
    for (rip, rsp) in bad {
        let e = UserEntry {
            rip,
            rsp,
            args: [0; 3],
        };
        ensure!(start(&t, &e) == Err(Error::InvalidArgument));
    }
    ensure!(t.state() == RunState::Inactive);
    // Sem `thread_configure`, também não.
    let lone = p
        .cspace
        .lock()
        .obj_create(p.quota, ObjectType::Thread, 0)
        .map_err(|_| "obj_create")?;
    let lone_t = Arc::clone(
        cap(&p.cspace, lone)?
            .object
            .as_thread()
            .map_err(|_| "tipo")?,
    );
    let e = UserEntry {
        rip: CODE_VA,
        rsp: DATA_VA,
        args: [0; 3],
    };
    ensure!(start(&lone_t, &e) == Err(Error::InvalidArgument));
    // Sem `SchedContext`, também não.
    let (bare, bare_t) = bare_thread(&p)?;
    ensure!(start(&bare_t, &e) == Err(Error::InvalidArgument));
    delete(&p, &[h, lone, bare])?;
    Ok(())
}

fn copias() -> Outcome {
    let p = process(1)?;
    let root = p
        .aspace
        .object
        .as_address_space()
        .map_err(|_| "tipo")?
        .lock()
        .root();
    // SAFETY: o espaço segue vivo (em `p`) até o CR3 voltar.
    let old = unsafe { activate(root) };
    let wrote = probe::copy_to_user(DATA_VA + 8, b"optimus");
    let mut back = [0u8; 7];
    let read = probe::copy_from_user(&mut back, DATA_VA + 8);
    // Página não mapeada, ponteiro de kernel e faixa que cruza a metade.
    let unmapped = probe::copy_from_user(&mut back, DATA_VA + PAGE_SIZE);
    let kernel = probe::copy_from_user(&mut back[..1], copias as *const () as u64);
    let across = probe::copy_to_user(kabi::vm::USER_END - 4, b"optimus");
    // SAFETY: o CR3 anterior era o do kernel.
    unsafe { cpu::write_cr3(old) };
    ensure!(wrote && read && &back == b"optimus");
    ensure!(!unmapped && !kernel && !across);
    Ok(())
}
