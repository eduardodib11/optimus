//! Testes de kernel de objetos e capabilities.

use alloc::vec::Vec;

use kabi::{Error, ObjectType, Rights};
use okernel::cap::object::object_bytes;
use okernel::cap::{CapSpace, MemoryQuota, obj_create};

use okernel::cap::space::Revoke;

use super::{REVOKE_SLICE_BUDGET, root_cap_space, root_quota};
use crate::arch::x86_64::cpu;
use crate::kheap;
use crate::ktest::{Outcome, Test};
use crate::ktime::now_ns;

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
    Test {
        name: "cap.revogacao_de_100000_caps_fatiada",
        run: revogacao_fatiada,
    },
];

/// Capabilities derivadas no teste de revogação (aceite do T-204).
const REVOKE_CAPS: usize = 100_000;
/// Maior fatia aceita com KVM ou em hardware real (aceite do T-204).
const SLICE_LIMIT_NS: u64 = 50_000;
/// Tolerância no TCG do QEMU, que emula a CPU cerca de 8 vezes mais devagar
/// neste código: p99 das fatias até 10 vezes o limite (500 µs).
const TCG_P99_LIMIT_NS: u64 = 10 * SLICE_LIMIT_NS;
/// No TCG o TSC segue o relógio do host, e uma preempção do processo do
/// QEMU entra na medida de uma fatia: a maior fatia vai até 40 vezes o
/// limite (2 ms).
const TCG_MAX_LIMIT_NS: u64 = 40 * SLICE_LIMIT_NS;

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

fn revogacao_fatiada() -> Outcome {
    let (space, q) = root_cap_space().map_err(|_| "root_cap_space")?;
    let mut space = space.lock();
    let target = space.mint(q, Rights::ALL, None).map_err(|_| "mint")?;
    // Árvore aleatória (xorshift), limitada pela profundidade máxima.
    let mut handles = Vec::with_capacity(REVOKE_CAPS + 1);
    handles.push(target);
    let mut rng = 0x2545_f491_4f6c_dd1du64;
    while handles.len() <= REVOKE_CAPS {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let src = handles[usize::try_from(rng % handles.len() as u64).unwrap_or(0)];
        match space.mint(src, Rights::CREATE, None) {
            Ok(h) => handles.push(h),
            Err(Error::InvalidArgument) => {}
            Err(_) => return Err("mint falhou"),
        }
    }
    let total = handles.len() - 1;
    let mut slices: Vec<u32> = Vec::new();
    let start = now_ns();
    loop {
        let t0 = now_ns();
        let status = space.revoke(target, REVOKE_SLICE_BUDGET);
        slices.push(u32::try_from(now_ns() - t0).unwrap_or(u32::MAX));
        match status {
            Ok(Revoke::Continue) => {}
            Ok(Revoke::Done) => break,
            Err(_) => return Err("revoke falhou"),
        }
    }
    let elapsed = now_ns() - start;
    ensure!(space.len() == 2);
    ensure!(handles[1..].iter().all(|&h| space.get(h).is_err()));
    ensure!(space.check_invariants().is_ok());
    let count = slices.len();
    slices.sort_unstable();
    let (max, p99) = (slices[count - 1], slices[count * 99 / 100]);
    let tcg = cpu::hypervisor().is_some_and(|sig| &sig == b"TCGTCGTCGTCG");
    let (max_limit, p99_limit) = if tcg {
        (TCG_MAX_LIMIT_NS, TCG_P99_LIMIT_NS)
    } else {
        (SLICE_LIMIT_NS, SLICE_LIMIT_NS)
    };
    info!(
        "ktest: · revogação de {total} caps em {count} fatias de {REVOKE_SLICE_BUDGET} passos: \
         maior {max} ns, p99 {p99} ns, mediana {} ns, total {} µs \
         (limites {max_limit}/{p99_limit} ns, {})",
        slices[count / 2],
        elapsed / 1000,
        if tcg { "TCG" } else { "KVM/hardware" }
    );
    ensure!(count >= total / REVOKE_SLICE_BUDGET as usize);
    ensure!(u64::from(max) <= max_limit);
    ensure!(u64::from(p99) <= p99_limit);
    Ok(())
}
