//! Testes de kernel de objetos e capabilities.

use kabi::{Error, ObjectType};
use okernel::cap::object::object_bytes;
use okernel::cap::{MemoryQuota, obj_create};

use super::root_quota;
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
];

fn usa_o_heap() -> Outcome {
    let root = root_quota().ok_or("sem cota raiz")?;
    let (quota0, live0) = (root.used(), kheap::live_blocks());
    let objects: alloc::vec::Vec<_> = (0..100)
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
