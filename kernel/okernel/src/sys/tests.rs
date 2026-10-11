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

/// Ambiente falso: conta preempções e guarda quem foi acordado.
#[derive(Default)]
struct Fake {
    preempts: u32,
    woken: Vec<(Arc<Thread>, u64)>,
    current: Option<Arc<Thread>>,
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
