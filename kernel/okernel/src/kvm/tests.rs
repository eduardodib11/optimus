//! Testes de kernel da memória virtual de usuário (T-205).

use kabi::vm::{EXEC, WRITE};
use kabi::{Error, Handle, ObjectType, Rights};
use okernel::cap::{Cap, SharedCapSpace};
use okernel::vm::{vm_map, vm_protect, vm_unmap};

use super::activate;
use crate::arch::x86_64::cpu;
use crate::arch::x86_64::probe::{self, PF_PRESENT};
use crate::kcap::{root_cap_space, root_quota};
use crate::kmem;
use crate::ktest::{Outcome, Test};

/// Testes de kernel da memória virtual de usuário.
pub const TESTS: &[Test] = &[
    Test {
        name: "vm.mapear_sem_direito_map_falha",
        run: sem_direito_map,
    },
    Test {
        name: "vm.espaco_novo_roda_o_kernel_e_smap_barra_o_usuario",
        run: espaco_novo,
    },
    Test {
        name: "vm.objetos_devolvem_frames_e_cota",
        run: devolvem_frames,
    },
];

const U: u64 = 0x40_0000;
const P: u64 = 4096;

fn cap(space: &SharedCapSpace, h: Handle) -> Result<Cap, &'static str> {
    space.lock().get(h).cloned().map_err(|_| "handle")
}

/// Cria um espaço e um objeto de `pages` páginas na tabela `space`.
fn create(space: &SharedCapSpace, quota: Handle, pages: u64) -> Result<(Handle, Handle), Error> {
    let mut s = space.lock();
    let a = s.obj_create(quota, ObjectType::AddressSpace, 0)?;
    let m = s.obj_create(quota, ObjectType::MemoryObject, pages * P)?;
    Ok((a, m))
}

fn sem_direito_map() -> Outcome {
    let (space, quota) = root_cap_space().map_err(|_| "cspace")?;
    let (a, m) = create(&space, quota, 2).map_err(|_| "obj_create")?;
    let (a_no_map, m_no_map) = {
        let mut s = space.lock();
        let a2 = s.mint(a, Rights::UNMAP, None).map_err(|_| "mint")?;
        let m2 = s
            .mint(m, Rights::READ | Rights::WRITE | Rights::EXEC, None)
            .map_err(|_| "mint")?;
        (a2, m2)
    };
    let (a, m, a_no_map, m_no_map) = (
        cap(&space, a)?,
        cap(&space, m)?,
        cap(&space, a_no_map)?,
        cap(&space, m_no_map)?,
    );
    ensure!(vm_map(&a_no_map, &m, U, 0, P, 0) == Err(Error::AccessDenied));
    ensure!(vm_map(&a, &m_no_map, U, 0, P, WRITE) == Err(Error::AccessDenied));
    ensure!(vm_map(&a, &m, U, 0, P, WRITE | EXEC) == Err(Error::InvalidArgument));
    let aspace = a.object.as_address_space().map_err(|_| "tipo")?;
    ensure!(aspace.lock().query(U).is_none());
    ensure!(vm_map(&a, &m, U, 0, 2 * P, WRITE) == Ok(()));
    ensure!(vm_protect(&a_no_map, U, P, 0) == Err(Error::AccessDenied));
    ensure!(vm_unmap(&a_no_map, U, 2 * P) == Ok(()));
    ensure!(aspace.lock().query(U).is_none());
    Ok(())
}

fn espaco_novo() -> Outcome {
    let (space, quota) = root_cap_space().map_err(|_| "cspace")?;
    let (a, m) = create(&space, quota, 1).map_err(|_| "obj_create")?;
    let (a, m) = (cap(&space, a)?, cap(&space, m)?);
    ensure!(vm_map(&a, &m, U, 0, P, WRITE) == Ok(()));
    let frame = m
        .object
        .as_memory_object()
        .map_err(|_| "tipo")?
        .frame(0)
        .ok_or("frame")?;
    // SAFETY: frame do objeto, vivo enquanto `m` existir, no mapa direto.
    unsafe { (kmem::direct(frame) as *mut u8).write_volatile(0x5a) };
    let aspace = a.object.as_address_space().map_err(|_| "tipo")?;
    let root = aspace.lock().root();
    let smap = cpu::read_cr4() & cpu::CR4_SMAP != 0;
    // SAFETY: `aspace` segue vivo até o CR3 voltar ao anterior.
    let old = unsafe { activate(root) };
    // Rodar até aqui com o CR3 novo já prova a metade alta compartilhada.
    let read = probe::read_byte(U);
    // SAFETY: o CR3 anterior era o do kernel, vivo para sempre.
    unsafe { cpu::write_cr3(old) };
    info!(
        "ktest: · leitura de página de usuário pelo kernel com SMAP {}: {read:?}",
        if smap { "ligado" } else { "desligado" }
    );
    match read {
        Ok(byte) => ensure!(!smap && byte == 0x5a),
        Err(f) => ensure!(smap && f.vector == 14 && f.error & PF_PRESENT != 0 && f.addr == U),
    }
    Ok(())
}

fn devolvem_frames() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let (space, q) = root_cap_space().map_err(|_| "cspace")?;
    let (frames0, used0) = (kmem::frame_stats().0, quota.used());
    {
        let (ha, hm) = create(&space, q, 8).map_err(|_| "obj_create")?;
        let (a, m) = (cap(&space, ha)?, cap(&space, hm)?);
        // Duas regiões em blocos de 2 MiB diferentes: mais tabelas.
        ensure!(vm_map(&a, &m, U, 0, 4 * P, 0) == Ok(()));
        ensure!(vm_map(&a, &m, U + (1 << 30), 4 * P, 4 * P, EXEC) == Ok(()));
        ensure!(kmem::frame_stats().0 < frames0 - 8);
        ensure!(quota.used() > used0 + 8 * P);
        let mut s = space.lock();
        ensure!(s.delete(ha).is_ok() && s.delete(hm).is_ok());
    }
    ensure!(kmem::frame_stats().0 == frames0);
    ensure!(quota.used() == used0);
    Ok(())
}
