//! Testes de kernel de objetos e capabilities.

use alloc::vec::Vec;

use kabi::{Error, ObjectType, Rights};
use okernel::cap::object::object_bytes;
use okernel::cap::{CapSpace, MemoryQuota, obj_create};

use super::{root_cap_space, root_quota};
use crate::kheap;
use crate::ktest::{Outcome, Test};

/// Testes de kernel de objetos e capabilities.
pub const TESTS: &[Test] = &[
    Test {
        name: "cap.obj_create_usa_o_heap_e_devolve",
        run: usa_o_heap,
    },
    Test {
        name: "cap.alem_da_cota_retorna_quota_exceeded",
        run: alem_da_cota,
    },
    Test {
        name: "cap.handle_antigo_retorna_invalid_handle",
        run: handle_antigo,
    },
    Test {
        name: "cap.capspace_cresce_e_devolve_a_cota",
        run: capspace_cresce,
    },
];

fn usa_o_heap() -> Outcome {
    let root = root_quota().ok_or("sem cota raiz")?;
    let (quota0, live0) = (root.used(), kheap::live_blocks());
    let objects: Vec<_> = (0..100)
        .map(|_| obj_create(&root, ObjectType::MemoryQuota, 1000))
        .collect::<Result<_, _>>()
        .map_err(|_| "obj_create falhou")?;
    let per_object = object_bytes::<MemoryQuota>();
    ensure!(root.used() == quota0 + 100 * (per_object + 1000));
    // Cada objeto é um bloco do heap (mais o do vetor que os guarda).
    ensure!(kheap::live_blocks() == live0 + 101);
    drop(objects);
    ensure!(root.used() == quota0);
    ensure!(kheap::live_blocks() == live0);
    Ok(())
}

fn alem_da_cota() -> Outcome {
    let root = root_quota().ok_or("sem cota raiz")?;
    let overhead = object_bytes::<MemoryQuota>();
    let child = obj_create(&root, ObjectType::MemoryQuota, overhead + 64)
        .map_err(|_| "obj_create falhou")?;
    let q = child.as_quota().map_err(|_| "tipo")?;
    ensure!(obj_create(q, ObjectType::MemoryQuota, 65).err() == Some(Error::QuotaExceeded));
    ensure!(q.used() == 0);
    let full = obj_create(q, ObjectType::MemoryQuota, 64).map_err(|_| "cabia")?;
    ensure!(q.available() == 0);
    ensure!(obj_create(q, ObjectType::MemoryQuota, 0).err() == Some(Error::QuotaExceeded));
    drop(full);
    ensure!(q.used() == 0);
    ensure!(root_quota().is_some_and(|r| r.used() >= overhead));
    Ok(())
}

fn handle_antigo() -> Outcome {
    let (space, q) = root_cap_space().map_err(|_| "root_cap_space")?;
    let mut space = space.lock();
    let a = space.mint(q, Rights::CREATE, None).map_err(|_| "mint")?;
    ensure!(space.delete(a).is_ok());
    let b = space.mint(q, Rights::ALL, None).map_err(|_| "mint")?;
    ensure!(a.index() == b.index() && a.generation() != b.generation());
    ensure!(space.info(a).err() == Some(Error::InvalidHandle));
    ensure!(space.delete(a).err() == Some(Error::InvalidHandle));
    ensure!(space.mint(a, Rights::ALL, None).err() == Some(Error::InvalidHandle));
    let info = space.info(b).map_err(|_| "info")?;
    ensure!(info.object_type == ObjectType::MemoryQuota);
    ensure!(info.rights == Rights::CREATE | Rights::SPLIT);
    Ok(())
}

fn capspace_cresce() -> Outcome {
    let root = root_quota().ok_or("sem cota raiz")?;
    let before = root.used();
    let (space, q) = root_cap_space().map_err(|_| "root_cap_space")?;
    let created = root.used();
    let handles = {
        let mut space = space.lock();
        let handles: Vec<_> = (0..10_000)
            .map(|_| space.mint(q, Rights::CREATE, None))
            .collect::<Result<_, _>>()
            .map_err(|_| "mint")?;
        // 10 001 capabilities (índice 0 reservado) ocupam 3 folhas.
        ensure!(root.used() == created + 2 * CapSpace::<4096>::LEAF_BYTES);
        for &h in &handles {
            ensure!(space.delete(h).is_ok());
        }
        ensure!(space.len() == 1);
        handles
    };
    ensure!(handles.len() == 10_000);
    drop(space);
    ensure!(root.used() == before);
    Ok(())
}
