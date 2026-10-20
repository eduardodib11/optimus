//! Testes no host do despacho portável de syscalls.

use alloc::sync::Arc;

use kabi::vm::{PAGE_SIZE, WRITE};

use alloc::vec::Vec;

use super::*;
use crate::cap::{Cap, MemoryQuota, Object, default_rights};
use crate::platform;
use crate::sync::SpinLock;
use crate::vm::tests::platform as fake_platform;

fn setup() -> (Arc<MemoryQuota>, Arc<SharedCapSpace>, u64) {
    let root = MemoryQuota::root(64 << 20);
    let space = Arc::new(SpinLock::new(crate::cap::CapSpace::new(&root).unwrap()));
    let q = space
        .lock()
        .insert(Cap {
            object: Object::MemoryQuota(Arc::clone(&root)),
            rights: default_rights(ObjectType::MemoryQuota),
            badge: 0,
        })
        .unwrap();
    (root, space, u64::from(q.raw()))
}

/// Ambiente falso: conta preempções e guarda quem foi acordado; `user` é
/// a memória de usuário legível (endereço e bytes) e `changed`, as
/// máscaras avisadas por `affinity_changed`.
#[derive(Default)]
struct Fake {
    preempts: u32,
    woken: Vec<(Arc<Thread>, u64)>,
    current: Option<Arc<Thread>>,
    user: Vec<(u64, Vec<u8>)>,
    changed: Vec<CpuMask>,
    tls_loads: Vec<u64>,
}

impl Env for Fake {
    fn preempt(&mut self) {
        self.preempts += 1;
    }
    fn wake(&mut self, thread: Arc<Thread>, value: u64) {
        self.woken.push((thread, value));
    }
    fn current(&self) -> Option<Arc<Thread>> {
        self.current.clone()
    }
    fn block(&mut self) {}
    fn read_u32(&mut self, _addr: u64) -> Option<u32> {
        None
    }
    fn now(&self) -> u64 {
        0
    }
    fn block_until(&mut self, _deadline: u64) {}
    fn handoff(&mut self, to: Arc<Thread>, _deadline: u64) {
        self.woken.push((to, 0));
    }
    fn read_buffer(&mut self, _thread: &Thread, _at: usize, _out: &mut [u64]) -> bool {
        false
    }
    fn write_buffer(&mut self, _thread: &Thread, _at: usize, _data: &[u64]) -> bool {
        false
    }
    fn read_bytes(&mut self, addr: u64, out: &mut [u8]) -> bool {
        let Some((_, bytes)) = self.user.iter().find(|(at, _)| *at == addr) else {
            return false;
        };
        out.copy_from_slice(&bytes[..out.len()]);
        true
    }
    fn online_cpus(&self) -> CpuMask {
        CpuMask([0b1111, 0, 0, 0])
    }
    fn affinity_changed(&mut self, mask: CpuMask) {
        self.changed.push(mask);
    }
    fn load_tls(&mut self, va: u64) {
        self.tls_loads.push(va);
    }
}

fn call(space: &Arc<SharedCapSpace>, c: Syscall, a: [u64; 6]) -> Result<Values, Error> {
    invoke(space, c, a, 4, &mut Fake::default())
}

#[test]
fn mint_info_delete_e_revoke() {
    let (_root, space, q) = setup();
    let create = u64::from(Rights::CREATE.bits());
    let [h, ..] = call(&space, Syscall::CapMint, [q, create, 7, 0, 0, 0]).unwrap();
    let info = call(&space, Syscall::CapInfo, [h, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(info, [ObjectType::MemoryQuota.to_raw(), create, 7]);
    // Direitos inexistentes ou handle fora de 32 bits.
    assert_eq!(
        call(&space, Syscall::CapMint, [q, 1 << 40, 0, 0, 0, 0]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        call(&space, Syscall::CapInfo, [1 << 32, 0, 0, 0, 0, 0]),
        Err(Error::InvalidHandle)
    );
    for _ in 0..20 {
        call(&space, Syscall::CapMint, [h, create, 0, 0, 0, 0]).unwrap();
    }
    let mut env = Fake::default();
    invoke(&space, Syscall::CapRevoke, [h, 0, 0, 0, 0, 0], 4, &mut env).unwrap();
    assert!(env.preempts > 1, "revogação fatiada");
    assert_eq!(space.lock().len(), 2);
    call(&space, Syscall::CapDelete, [h, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(
        call(&space, Syscall::CapInfo, [h, 0, 0, 0, 0, 0]),
        Err(Error::InvalidHandle)
    );
}

#[test]
fn obj_create_e_vm_por_handles() {
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let ty = |t: ObjectType| t.to_raw();
    assert_eq!(
        call(&space, Syscall::ObjCreate, [q, 99, 0, 0, 0, 0]),
        Err(Error::InvalidArgument)
    );
    let [a, ..] = call(
        &space,
        Syscall::ObjCreate,
        [q, ty(ObjectType::AddressSpace), 0, 0, 0, 0],
    )
    .unwrap();
    let [m, ..] = call(
        &space,
        Syscall::ObjCreate,
        [q, ty(ObjectType::MemoryObject), 2 * PAGE_SIZE, 0, 0, 0],
    )
    .unwrap();
    let va = 0x40_0000;
    // O objeto sem MAP não mapeia.
    let read = u64::from((Rights::READ | Rights::WRITE).bits());
    let [m_ro, ..] = call(&space, Syscall::CapMint, [m, read, 0, 0, 0, 0]).unwrap();
    let map = |obj| call(&space, Syscall::VmMap, [a, obj, va, 0, PAGE_SIZE, WRITE]);
    assert_eq!(map(m_ro), Err(Error::AccessDenied));
    assert_eq!(map(a), Err(Error::WrongType));
    assert_eq!(map(m), Ok([0; 3]));
    assert_eq!(map(m), Err(Error::InvalidArgument));
    assert_eq!(
        call(&space, Syscall::VmProtect, [a, va, PAGE_SIZE, 0, 0, 0]),
        Ok([0; 3])
    );
    assert_eq!(
        call(&space, Syscall::VmUnmap, [a, va, PAGE_SIZE, 0, 0, 0]),
        Ok([0; 3])
    );
}

#[test]
fn as_outras_nao_sao_suportadas_aqui() {
    let (_root, space, _) = setup();
    for &c in Syscall::ALL {
        let handled = matches!(
            c,
            Syscall::CapMint
                | Syscall::CapDelete
                | Syscall::CapRevoke
                | Syscall::CapInfo
                | Syscall::ObjCreate
                | Syscall::VmMap
                | Syscall::VmUnmap
                | Syscall::VmProtect
                | Syscall::SchedConfigure
                | Syscall::SchedBind
                | Syscall::ThreadConfigure
        );
        // Precisam de capability válida ou da thread atual.
        let sync = matches!(
            c,
            Syscall::NtfySignal
                | Syscall::NtfyWait
                | Syscall::NtfyPoll
                | Syscall::ObjBindNotify
                | Syscall::IrqAck
                | Syscall::FutexWait
                | Syscall::FutexWake
        );
        if sync {
            assert_ne!(call(&space, c, [0; 6]), Ok([0; 3]), "{c:?}");
            continue;
        }
        if !handled {
            assert_eq!(call(&space, c, [0; 6]), Err(Error::NotSupported), "{c:?}");
        }
    }
}

#[test]
fn sched_configure_e_bind_conferem_direitos() {
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let create =
        |t: ObjectType| call(&space, Syscall::ObjCreate, [q, t.to_raw(), 0, 0, 0, 0]).unwrap()[0];
    let (sc, t) = (create(ObjectType::SchedContext), create(ObjectType::Thread));
    let ms = 1_000_000;
    let conf = |sc| {
        call(
            &space,
            Syscall::SchedConfigure,
            [sc, ms, 10 * ms, 120, 0, 0],
        )
    };
    let bind_only = u64::from(Rights::BIND.bits());
    let [sc_bind, ..] = call(&space, Syscall::CapMint, [sc, bind_only, 0, 0, 0, 0]).unwrap();
    assert_eq!(conf(sc_bind), Err(Error::AccessDenied));
    assert_eq!(conf(t), Err(Error::WrongType));
    assert_eq!(
        call(&space, Syscall::SchedConfigure, [sc, 2 * ms, ms, 1, 0, 0]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(conf(sc), Ok([0; 3]));
    let read = u64::from(Rights::READ_STATE.bits());
    let [t_ro, ..] = call(&space, Syscall::CapMint, [t, read, 0, 0, 0, 0]).unwrap();
    let bind = |sc, t| call(&space, Syscall::SchedBind, [sc, t, 0, 0, 0, 0]);
    assert_eq!(bind(sc, t_ro), Err(Error::AccessDenied));
    assert_eq!(bind(sc_bind, t), Ok([0; 3]));
    assert_eq!(bind(sc, t), Err(Error::Busy));
    let thread = space
        .lock()
        .get(Handle::from_raw(u32::try_from(t).unwrap()))
        .unwrap()
        .clone();
    let bound = thread.object.as_thread().unwrap().sched_context().unwrap();
    assert_eq!(bound.params().map(|p| p.priority), Some(120));
}

#[test]
fn sched_configure_com_mascara_de_afinidade() {
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let [sc, ..] = call(
        &space,
        Syscall::ObjCreate,
        [q, ObjectType::SchedContext.to_raw(), 0, 0, 0, 0],
    )
    .unwrap();
    let ms = 1_000_000;
    let mask_bytes = |m: CpuMask| m.0.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>();
    let mut env = Fake {
        user: alloc::vec![
            (0x10_000, mask_bytes(CpuMask::only(2).with(9))),
            (0x10_100, mask_bytes(CpuMask::only(5))),
            (0x10_200, mask_bytes(CpuMask::NONE)),
        ],
        ..Fake::default()
    };
    let mut conf = |r8, r9| {
        invoke(
            &space,
            Syscall::SchedConfigure,
            [sc, ms, 10 * ms, 7, r8, r9],
            4,
            &mut env,
        )
    };
    // r9 reservado; máscara sem CPU ligada (5 e nenhuma), desalinhada,
    // ilegível ou fora da metade de usuário.
    for (r8, r9) in [
        (0x10_000, 1),
        (0x10_100, 0),
        (0x10_200, 0),
        (0x10_004, 0),
        (0x20_000, 0),
        (USER_END - 8, 0),
        (8, 0),
    ] {
        assert_eq!(conf(r8, r9), Err(Error::InvalidArgument), "r8 {r8:#x}");
    }
    assert_eq!(conf(0x10_000, 0), Ok([0; 3]));
    // Sem máscara (r8 = 0), fica a que estava.
    assert_eq!(conf(0, 0), Ok([0; 3]));
    let obj = space
        .lock()
        .get(Handle::from_raw(u32::try_from(sc).unwrap()))
        .unwrap()
        .clone();
    let obj = obj.object.as_sched_context().unwrap();
    assert_eq!(obj.mask(), CpuMask::only(2).with(9));
    assert_eq!(obj.params().map(|p| p.priority), Some(7));
    assert_eq!(env.changed, [CpuMask::only(2).with(9)]);
    assert_eq!(env.preempts, 1);
}

#[test]
fn notificacao_por_handles() {
    platform::install(fake_platform(1000).1);
    let (root, space, q) = setup();
    let [n, ..] = call(
        &space,
        Syscall::ObjCreate,
        [q, ObjectType::Notification.to_raw(), 0, 0, 0, 0],
    )
    .unwrap();
    let signal_only = u64::from(Rights::SIGNAL.bits());
    let [ns, ..] = call(&space, Syscall::CapMint, [n, signal_only, 0b100, 0, 0, 0]).unwrap();
    assert_eq!(
        call(&space, Syscall::NtfyPoll, [ns, 0, 0, 0, 0, 0]),
        Err(Error::AccessDenied)
    );
    assert_eq!(
        call(&space, Syscall::NtfySignal, [n, 0, 0, 0, 0, 0]),
        Err(Error::InvalidArgument)
    );
    // O badge entra na palavra junto com os bits.
    call(&space, Syscall::NtfySignal, [ns, 1, 0, 0, 0, 0]).unwrap();
    assert_eq!(
        call(&space, Syscall::NtfyPoll, [n, 0, 0, 0, 0, 0]),
        Ok([0b101, 0, 0])
    );
    // Quem espera é acordado pelo sinal, com a palavra.
    let t = Arc::new(Thread::new(&root, fake_platform(1000).1).unwrap());
    let mut env = Fake {
        current: Some(Arc::clone(&t)),
        ..Fake::default()
    };
    invoke(&space, Syscall::NtfyWait, [n, 0, 0, 0, 0, 0], 4, &mut env).unwrap();
    assert_eq!(t.state(), crate::thread::RunState::Blocked);
    invoke(
        &space,
        Syscall::NtfySignal,
        [n, 0b10, 0, 0, 0, 0],
        4,
        &mut env,
    )
    .unwrap();
    assert_eq!(env.woken.len(), 1);
    assert!(Arc::ptr_eq(&env.woken[0].0, &t) && env.woken[0].1 == 0b10);
    assert_eq!(env.preempts, 1);
    // Interrupção ligada a um bit; obj_bind_notify confere tipos e direitos.
    let irq = space
        .lock()
        .insert(Cap {
            object: Object::Interrupt(Arc::new(
                crate::notify::Interrupt::new(&root, 0x40).unwrap(),
            )),
            rights: default_rights(ObjectType::Interrupt),
            badge: 0,
        })
        .unwrap();
    let irq = u64::from(irq.raw());
    let bind = |obj, ntfy| call(&space, Syscall::ObjBindNotify, [obj, ntfy, 3, 0, 0, 0]);
    assert_eq!(bind(n, n), Err(Error::AccessDenied));
    assert_eq!(bind(irq, irq), Err(Error::AccessDenied));
    assert_eq!(bind(irq, n), Ok([0; 3]));
    assert_eq!(bind(irq, n), Err(Error::Busy));
    assert_eq!(
        call(&space, Syscall::IrqAck, [irq, 0, 0, 0, 0, 0]),
        Ok([0; 3])
    );
    // obj_create não cria interrupções.
    assert_eq!(
        call(
            &space,
            Syscall::ObjCreate,
            [q, ObjectType::Interrupt.to_raw(), 0x40, 0, 0, 0]
        ),
        Err(Error::NotSupported)
    );
}

/// Cria um objeto de `ty` e devolve o handle cru.
fn create(space: &Arc<SharedCapSpace>, q: u64, ty: ObjectType) -> u64 {
    call(space, Syscall::ObjCreate, [q, ty.to_raw(), 0, 0, 0, 0]).unwrap()[0]
}

fn get(space: &SharedCapSpace, h: u64) -> Cap {
    let h = Handle::from_raw(u32::try_from(h).unwrap());
    space.lock().get(h).unwrap().clone()
}

#[test]
fn mint_para_outro_cap_space() {
    let (_root, space, q) = setup();
    let other = create(&space, q, ObjectType::CapSpace);
    let target = Arc::clone(get(&space, other).object.as_cap_space().unwrap());
    let send = u64::from(Rights::CREATE.bits());
    // Sem MANAGE no destino, nada é copiado.
    let no_manage = u64::from(Rights::NONE.bits());
    let [weak, ..] = call(&space, Syscall::CapMint, [other, no_manage, 0, 0, 0, 0]).unwrap();
    assert_eq!(
        call(&space, Syscall::CapMint, [q, send, 0, weak, 0, 0]),
        Err(Error::AccessDenied)
    );
    assert_eq!(
        call(&space, Syscall::CapMint, [q, send, 0, q, 0, 0]),
        Err(Error::AccessDenied)
    );
    let before = space.lock().len();
    let [h, ..] = call(&space, Syscall::CapMint, [q, send, 9, other, 0, 0]).unwrap();
    // A cópia está só no destino, com direitos reduzidos e o badge.
    assert_eq!(space.lock().len(), before);
    let copy = get(&target, h);
    assert_eq!((copy.rights, copy.badge), (Rights::CREATE, 9));
    assert!(copy.object.same(&get(&space, q).object));
    // Badge sobre capability com badge continua recusado, sem sobrar cópia.
    let [badged, ..] = call(&space, Syscall::CapMint, [q, send, 3, 0, 0, 0]).unwrap();
    let before = (space.lock().len(), target.lock().len());
    assert_eq!(
        call(&space, Syscall::CapMint, [badged, send, 4, other, 0, 0]),
        Err(Error::AccessDenied)
    );
    assert_eq!((space.lock().len(), target.lock().len()), before);
}

/// A cópia que `cap_mint` faz em outro `CapSpace` é filha remota da origem
/// (ADR 0029 sobre a árvore da ADR 0028): revogar a origem a apaga no
/// destino, com o que tiver sido derivado dela lá; apagar a origem sem
/// revogar não a apaga.
#[test]
fn revogar_a_origem_apaga_a_copia_de_cap_mint_no_destino() {
    let (_root, space, q) = setup();
    let other = create(&space, q, ObjectType::CapSpace);
    let target = Arc::clone(get(&space, other).object.as_cap_space().unwrap());
    let n = create(&space, q, ObjectType::Notification);
    let signal = u64::from(Rights::SIGNAL.bits());
    let info = |s: &Arc<SharedCapSpace>, h: u64| call(s, Syscall::CapInfo, [h, 0, 0, 0, 0, 0]);
    let [copy, ..] = call(&space, Syscall::CapMint, [n, signal, 5, other, 0, 0]).unwrap();
    let [grand, ..] = call(&target, Syscall::CapMint, [copy, signal, 0, 0, 0, 0]).unwrap();
    assert_eq!(
        info(&target, copy),
        Ok([ObjectType::Notification.to_raw(), signal, 5])
    );
    let before = target.lock().len();
    call(&space, Syscall::CapRevoke, [n, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(info(&target, copy), Err(Error::InvalidHandle));
    assert_eq!(info(&target, grand), Err(Error::InvalidHandle));
    assert_eq!(target.lock().len(), before - 2);
    // A origem segue valendo e pode copiar de novo.
    assert!(info(&space, n).is_ok());
    let [again, ..] = call(&space, Syscall::CapMint, [n, signal, 0, other, 0, 0]).unwrap();
    // Apagar a origem não leva a cópia (fica um marcador), mas revogar o
    // ancestral local da origem ainda a alcança.
    let [mid, ..] = call(&space, Syscall::CapMint, [n, signal, 0, 0, 0, 0]).unwrap();
    let [deep, ..] = call(&space, Syscall::CapMint, [mid, signal, 0, other, 0, 0]).unwrap();
    call(&space, Syscall::CapDelete, [mid, 0, 0, 0, 0, 0]).unwrap();
    assert!(info(&target, deep).is_ok());
    call(&space, Syscall::CapRevoke, [n, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(info(&target, again), Err(Error::InvalidHandle));
    assert_eq!(info(&target, deep), Err(Error::InvalidHandle));
}

#[test]
fn thread_configure_confere_tudo_antes() {
    use kabi::thread::{CONFIGURE_EXCEPTION, CONFIGURE_IPC_BUFFER};
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let t = create(&space, q, ObjectType::Thread);
    let cs = create(&space, q, ObjectType::CapSpace);
    let a = create(&space, q, ObjectType::AddressSpace);
    let thread = Arc::clone(get(&space, t).object.as_thread().unwrap());
    let conf = |args: [u64; 6]| call(&space, Syscall::ThreadConfigure, args);
    let buf = 0x50_0000;
    let both = CONFIGURE_IPC_BUFFER | CONFIGURE_EXCEPTION;
    assert_eq!(
        conf([t, cs, a, buf, 0, 1 << 5]),
        Err(Error::InvalidArgument)
    );
    assert_eq!(conf([t, cs, 0, buf, 0, both]), Err(Error::InvalidArgument));
    assert_eq!(conf([t, a, cs, buf, 0, both]), Err(Error::AccessDenied));
    assert_eq!(conf([cs, cs, a, buf, 0, both]), Err(Error::AccessDenied));
    // Buffer desalinhado: nada muda, nem a ligação.
    assert_eq!(
        conf([t, cs, a, buf + 8, 7, both]),
        Err(Error::InvalidArgument)
    );
    assert!(thread.aspace().is_none() && thread.ipc_buffer().is_none());
    let read = u64::from(Rights::READ_STATE.bits());
    let [t_ro, ..] = call(&space, Syscall::CapMint, [t, read, 0, 0, 0, 0]).unwrap();
    assert_eq!(conf([t_ro, cs, a, buf, 7, both]), Err(Error::AccessDenied));
    assert_eq!(conf([t, cs, a, buf, 7, both]), Ok([0; 3]));
    assert!(thread.aspace().is_some() && thread.cspace().is_some());
    assert_eq!(thread.ipc_buffer(), Some(buf));
    assert_eq!(thread.exception_handler(), Some(Handle::from_raw(7)));
    // Só o buffer muda; a exceção fica.
    assert_eq!(conf([t, 0, 0, 0, 0, CONFIGURE_IPC_BUFFER]), Ok([0; 3]));
    assert_eq!(thread.ipc_buffer(), None);
    assert_eq!(thread.exception_handler(), Some(Handle::from_raw(7)));
    // Depois da partida, religar dá Busy; buffer e exceção ainda mudam.
    thread.set_state(crate::thread::RunState::Running);
    assert_eq!(conf([t, cs, a, 0, 0, 0]), Err(Error::Busy));
    assert_eq!(conf([t, 0, 0, buf, 0, both]), Ok([0; 3]));
    assert_eq!(
        (thread.ipc_buffer(), thread.exception_handler()),
        (Some(buf), None)
    );
    thread.set_state(crate::thread::RunState::Exited);
}

#[test]
fn thread_configure_do_tls_e_da_propria_thread() {
    use kabi::thread::{CONFIGURE_EXCEPTION, CONFIGURE_IPC_BUFFER, CONFIGURE_TLS, SELF};
    use kabi::vm::USER_END;
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let me_h = create(&space, q, ObjectType::Thread);
    let other_h = create(&space, q, ObjectType::Thread);
    let me = Arc::clone(get(&space, me_h).object.as_thread().unwrap());
    let other = Arc::clone(get(&space, other_h).object.as_thread().unwrap());
    let mut env = Fake {
        current: Some(Arc::clone(&me)),
        ..Fake::default()
    };
    let conf =
        |args: [u64; 6], env: &mut Fake| invoke(&space, Syscall::ThreadConfigure, args, 4, env);
    let tls = 0x7000_1234;
    // A própria, sem capability: vale na hora (`load_tls`).
    assert_eq!(
        conf([SELF, 0, 0, tls, 0, CONFIGURE_TLS], &mut env),
        Ok([0; 3])
    );
    assert_eq!((me.tls(), env.tls_loads.as_slice()), (tls, &[tls][..]));
    // Pela capability da própria thread também vale na hora.
    assert_eq!(
        conf([me_h, 0, 0, 0, 0, CONFIGURE_TLS], &mut env),
        Ok([0; 3])
    );
    assert_eq!((me.tls(), env.tls_loads.as_slice()), (0, &[tls, 0][..]));
    // Outra thread, pela capability: grava sem tocar o MSR desta CPU.
    assert_eq!(
        conf([other_h, 0, 0, tls, 0, CONFIGURE_TLS], &mut env),
        Ok([0; 3])
    );
    assert_eq!((other.tls(), env.tls_loads.len()), (tls, 2));
    // Recusas: nada muda.
    for bad in [
        USER_END,
        0x0000_8000_0000_1000,
        0xffff_8000_0000_0000,
        u64::MAX,
    ] {
        assert_eq!(
            conf([SELF, 0, 0, bad, 0, CONFIGURE_TLS], &mut env),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            conf([other_h, 0, 0, bad, 0, CONFIGURE_TLS], &mut env),
            Err(Error::InvalidArgument)
        );
    }
    let both = CONFIGURE_TLS | CONFIGURE_IPC_BUFFER;
    assert_eq!(
        conf([SELF, 0, 0, 0x50_0000, 0, both], &mut env),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        conf([SELF, 1, 1, tls, 0, CONFIGURE_TLS], &mut env),
        Err(Error::InvalidArgument),
        "thread = 0 não liga CapSpace nem AddressSpace"
    );
    assert_eq!(
        conf([0x00ab_cdef, 0, 0, tls, 0, CONFIGURE_TLS], &mut env),
        Err(Error::InvalidHandle)
    );
    let read = u64::from(Rights::READ_STATE.bits());
    let [ro, ..] = call(&space, Syscall::CapMint, [other_h, read, 0, 0, 0, 0]).unwrap();
    assert_eq!(
        conf([ro, 0, 0, 0, 0, CONFIGURE_TLS], &mut env),
        Err(Error::AccessDenied)
    );
    assert_eq!((me.tls(), other.tls(), env.tls_loads.len()), (0, tls, 2));
    // Buffer e exceção na própria, sem capability.
    let flags = CONFIGURE_IPC_BUFFER | CONFIGURE_EXCEPTION;
    assert_eq!(
        conf([SELF, 0, 0, 0x50_0000, 9, flags], &mut env),
        Ok([0; 3])
    );
    assert_eq!(me.ipc_buffer(), Some(0x50_0000));
    assert_eq!(me.exception_handler(), Some(Handle::from_raw(9)));
    // Sem thread atual (o kernel), `thread = 0` não acha ninguém.
    assert_eq!(
        call(
            &space,
            Syscall::ThreadConfigure,
            [SELF, 0, 0, tls, 0, CONFIGURE_TLS]
        ),
        Err(Error::InvalidHandle)
    );
}

#[test]
fn vm_map_e_unmap_no_proprio_espaco() {
    use kabi::vm::SELF;
    platform::install(fake_platform(1000).1);
    let (_root, space, q) = setup();
    let t = create(&space, q, ObjectType::Thread);
    let cs = create(&space, q, ObjectType::CapSpace);
    let a = create(&space, q, ObjectType::AddressSpace);
    let [m, ..] = call(
        &space,
        Syscall::ObjCreate,
        [q, ObjectType::MemoryObject.to_raw(), PAGE_SIZE, 0, 0, 0],
    )
    .unwrap();
    let thread = Arc::clone(get(&space, t).object.as_thread().unwrap());
    let va = 0x40_0000;
    // Sem thread atual (ou sem espaço ligado), `aspace = 0` não acha nada.
    assert_eq!(
        call(&space, Syscall::VmMap, [SELF, m, va, 0, PAGE_SIZE, WRITE]),
        Err(Error::InvalidHandle)
    );
    let mut env = Fake {
        current: Some(Arc::clone(&thread)),
        ..Fake::default()
    };
    let sys = |c, args: [u64; 6], env: &mut Fake| invoke(&space, c, args, 4, env);
    assert_eq!(
        sys(Syscall::VmMap, [SELF, m, va, 0, PAGE_SIZE, WRITE], &mut env),
        Err(Error::InvalidHandle)
    );
    assert_eq!(
        sys(Syscall::ThreadConfigure, [t, cs, a, 0, 0, 0], &mut env),
        Ok([0; 3])
    );
    assert_eq!(
        sys(Syscall::VmMap, [SELF, m, va, 0, PAGE_SIZE, WRITE], &mut env),
        Ok([0; 3])
    );
    // O mapeamento está no espaço `a`: mapear lá de novo colide.
    assert_eq!(
        sys(Syscall::VmMap, [a, m, va, 0, PAGE_SIZE, WRITE], &mut env),
        Err(Error::InvalidArgument)
    );
    let aspace = thread.aspace().unwrap();
    assert!(aspace.lock().query(va).is_some());
    assert_eq!(
        sys(Syscall::VmUnmap, [SELF, va, PAGE_SIZE, 0, 0, 0], &mut env),
        Ok([0; 3])
    );
    assert!(aspace.lock().query(va).is_none());
    // Os direitos do objeto continuam valendo.
    let read = u64::from((Rights::READ | Rights::MAP).bits());
    let [m_ro, ..] = call(&space, Syscall::CapMint, [m, read, 0, 0, 0, 0]).unwrap();
    assert_eq!(
        sys(
            Syscall::VmMap,
            [SELF, m_ro, va, 0, PAGE_SIZE, WRITE],
            &mut env
        ),
        Err(Error::AccessDenied)
    );
    drop(aspace);
    thread.set_state(crate::thread::RunState::Exited);
}
