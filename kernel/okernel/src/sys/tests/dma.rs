//! Testes no host de `dma_map` (T-403; ADR 0044): direitos e operações.

use kabi::dma::{ATTACH, DETACH, READ, UNMAP, WRITE};

use super::*;
use crate::mm::PhysAddr;

fn domain(space: &Arc<SharedCapSpace>, q: u64) -> u64 {
    let ty = ObjectType::DmaDomain.to_raw();
    call(space, Syscall::ObjCreate, [q, ty, 0, 0, 0, 0]).unwrap()[0]
}

fn dma(space: &Arc<SharedCapSpace>, a: [u64; 6]) -> Result<Values, Error> {
    call(space, Syscall::DmaMap, a)
}

#[test]
fn driver_mapeia_e_so_devmgr_liga() {
    platform::install(fake_platform(1000).1);
    let (root, space, q) = setup();
    let ty = ObjectType::MemoryObject.to_raw();
    let m = call(&space, Syscall::ObjCreate, [q, ty, 2 * PAGE_SIZE, 0, 0, 0]).unwrap()[0];
    // Domínio do driver (cota comum): `MAP`, sem `BIND`.
    let d = domain(&space, q);
    assert!(!get(&space, d).rights.contains(Rights::BIND));
    let phys = dma(&space, [d, m, 0x4000, 0, 2 * PAGE_SIZE, READ | WRITE]).unwrap()[0];
    let first = get(&space, m).object.as_memory_object().unwrap().frame(0);
    assert_eq!(Some(PhysAddr(phys)), first);
    assert_eq!(
        dma(&space, [d, 0, 0x1a, 0, 0, ATTACH]),
        Err(Error::AccessDenied)
    );
    // Flags estranhas, escrita sem leitura, `UNMAP` com objeto.
    for flags in [0, WRITE, READ | UNMAP, 1 << 5] {
        assert_eq!(
            dma(&space, [d, m, 0x8000, 0, PAGE_SIZE, flags]),
            Err(Error::InvalidArgument)
        );
    }
    assert_eq!(
        dma(&space, [d, m, 0x4000, 0, 2 * PAGE_SIZE, UNMAP]),
        Err(Error::InvalidArgument)
    );
    dma(&space, [d, 0, 0x4000, 0, 2 * PAGE_SIZE, UNMAP]).unwrap();
    // Domínio do `devmgr` (cota de dispositivo): `BIND`.
    let device = MemoryQuota::device(&root, 1 << 16).unwrap();
    let dq = space
        .lock()
        .insert(Cap {
            object: Object::MemoryQuota(device),
            rights: Rights::CREATE,
            badge: 0,
        })
        .unwrap();
    let b = domain(&space, u64::from(dq.raw()));
    assert!(get(&space, b).rights.contains(Rights::BIND | Rights::MAP));
    assert_eq!(
        dma(&space, [b, 0, 1 << 16, 0, 0, ATTACH]),
        Err(Error::InvalidArgument)
    );
    dma(&space, [b, 0, 0xb1a, 0, 0, ATTACH]).unwrap();
    dma(&space, [b, 0, 0xb1a, 0, 0, DETACH]).unwrap();
    assert_eq!(
        dma(&space, [b, 0, 0xb1a, 0, 0, DETACH]),
        Err(Error::InvalidArgument)
    );
    // Objeto sem `WRITE` não se mapeia para escrita.
    let ro = space
        .lock()
        .mint(handle(m).unwrap(), Rights::READ | Rights::MAP, None);
    let ro = u64::from(ro.unwrap().raw());
    assert_eq!(
        dma(&space, [d, ro, 0, 0, PAGE_SIZE, READ | WRITE]),
        Err(Error::AccessDenied)
    );
    dma(&space, [d, ro, 0, 0, PAGE_SIZE, READ]).unwrap();
}

#[test]
fn so_o_devmgr_liga_a_falta_de_dma_a_uma_notificacao() {
    platform::install(fake_platform(1000).1);
    let (root, space, q) = setup();
    let n = create(&space, q, ObjectType::Notification);
    let bind = |obj, bits| call(&space, Syscall::ObjBindNotify, [obj, n, bits, 0, 0, 0]);
    // Domínio do driver (sem `BIND`): recusado.
    let d = domain(&space, q);
    assert_eq!(bind(d, 1), Err(Error::AccessDenied));
    // Domínio do `devmgr`: liga, religa e desliga (máscara 0).
    let device = MemoryQuota::device(&root, 1 << 16).unwrap();
    let dq = space
        .lock()
        .insert(Cap {
            object: Object::MemoryQuota(device),
            rights: Rights::CREATE,
            badge: 0,
        })
        .unwrap();
    let b = domain(&space, u64::from(dq.raw()));
    bind(b, 1 << 3).unwrap();
    bind(b, 1 << 4).unwrap();
    bind(b, 0).unwrap();
    // Lixo nos argumentos extras.
    assert_eq!(
        call(&space, Syscall::ObjBindNotify, [b, n, 1, 7, 0, 0]),
        Err(Error::InvalidArgument)
    );
}
