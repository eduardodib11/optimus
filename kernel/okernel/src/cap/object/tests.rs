//! Testes no host de `MemoryQuota` e `obj_create`.

use super::*;
use crate::cap::Charge;

const OVERHEAD: u64 = object_bytes::<MemoryQuota>();

fn quota_of(obj: &Object) -> Arc<MemoryQuota> {
    Arc::clone(obj.as_quota().unwrap())
}

#[test]
fn cobra_tamanho_do_objeto_e_orcamento() {
    let root = MemoryQuota::root(10_000);
    let child = obj_create(&root, ObjectType::MemoryQuota, 1000).unwrap();
    assert_eq!(child.object_type(), ObjectType::MemoryQuota);
    assert_eq!(root.used(), OVERHEAD + 1000);
    let q = quota_of(&child);
    assert_eq!(
        (q.limit(), q.used(), q.parent_charge()),
        (1000, 0, OVERHEAD + 1000)
    );
    // O objeto é cobrado pelo tamanho real de um `Arc` dele.
    assert!(OVERHEAD >= size_of::<MemoryQuota>() as u64 + 16);
}

#[test]
fn alem_da_cota_retorna_quota_exceeded() {
    let root = MemoryQuota::root(OVERHEAD + 100);
    assert_eq!(
        obj_create(&root, ObjectType::MemoryQuota, 101).unwrap_err(),
        Error::QuotaExceeded
    );
    assert_eq!(root.used(), 0, "falha não cobra nada");
    let ok = obj_create(&root, ObjectType::MemoryQuota, 100).unwrap();
    assert_eq!(root.available(), 0);
    assert_eq!(
        obj_create(&root, ObjectType::MemoryQuota, 0).unwrap_err(),
        Error::QuotaExceeded
    );
    drop(ok);
    assert_eq!(root.used(), 0);
}

#[test]
fn liberar_devolve_a_cota_em_cadeia() {
    let root = MemoryQuota::root(1 << 20);
    let a = obj_create(&root, ObjectType::MemoryQuota, 4096).unwrap();
    let qa = quota_of(&a);
    let b = obj_create(&qa, ObjectType::MemoryQuota, 1024).unwrap();
    let qb = quota_of(&b);
    let c = obj_create(&qb, ObjectType::MemoryQuota, 0).unwrap();
    assert_eq!(qa.used(), OVERHEAD + 1024);
    assert_eq!(qb.used(), OVERHEAD);
    // Sem referências à mãe, a cobrança da filha a mantém viva.
    drop((a, qa, b));
    assert_eq!(root.used(), OVERHEAD + 4096);
    drop((qb, c));
    assert_eq!(root.used(), 0);
}

#[test]
fn neta_nao_passa_do_orcamento_da_filha() {
    let root = MemoryQuota::root(1 << 20);
    let filha = obj_create(&root, ObjectType::MemoryQuota, OVERHEAD + 10).unwrap();
    let qf = quota_of(&filha);
    assert_eq!(
        obj_create(&qf, ObjectType::MemoryQuota, 11).unwrap_err(),
        Error::QuotaExceeded
    );
    assert!(obj_create(&qf, ObjectType::MemoryQuota, 10).is_ok());
}

#[test]
fn argumentos_e_tipos_invalidos() {
    let root = MemoryQuota::root(u64::MAX);
    assert_eq!(
        obj_create(&root, ObjectType::MemoryQuota, u64::MAX).unwrap_err(),
        Error::InvalidArgument
    );
    assert_eq!(
        obj_create(&root, ObjectType::Thread, 0).unwrap_err(),
        Error::NotSupported
    );
    assert_eq!(root.used(), 0);
}

#[test]
fn charge_cresce_e_encolhe() {
    let root = MemoryQuota::root(100);
    let mut c: Charge = root.charge(40).unwrap();
    assert_eq!(c.grow(61), Err(Error::QuotaExceeded));
    assert_eq!(c.bytes(), 40);
    c.grow(60).unwrap();
    assert_eq!(root.available(), 0);
    c.shrink(30);
    assert_eq!((c.bytes(), root.used()), (70, 70));
    assert!(Arc::ptr_eq(c.quota(), &root));
    assert_eq!(root.charge(31).unwrap_err(), Error::QuotaExceeded);
    drop(c);
    assert_eq!(root.used(), 0);
}

#[test]
fn objetos_iguais_e_diferentes() {
    let root = MemoryQuota::root(1 << 20);
    let a = obj_create(&root, ObjectType::MemoryQuota, 0).unwrap();
    let b = obj_create(&root, ObjectType::MemoryQuota, 0).unwrap();
    assert!(a.same(&a.clone()));
    assert!(!a.same(&b));
}

#[test]
fn direitos_iniciais_da_tabela() {
    assert_eq!(
        default_rights(ObjectType::MemoryQuota),
        Rights::CREATE | Rights::SPLIT
    );
    assert_eq!(
        default_rights(ObjectType::Endpoint),
        Rights::SEND | Rights::RECV | Rights::GRANT | Rights::DESTROY
    );
    // Processos e threads: ligar o evento de morte e encerrar (T-348).
    assert_eq!(
        default_rights(ObjectType::CapSpace),
        Rights::MANAGE | Rights::BIND | Rights::DESTROY
    );
    assert!(default_rights(ObjectType::Thread).contains(Rights::BIND | Rights::DESTROY));
    for &ty in ObjectType::ALL {
        assert_ne!(default_rights(ty), Rights::NONE, "{ty:?}");
    }
}

#[test]
fn cobranca_concorrente_nunca_passa_do_limite() {
    let root = MemoryQuota::root(1000);
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let root = Arc::clone(&root);
            std::thread::spawn(move || {
                let mut held = Vec::new();
                for i in 0..10_000 {
                    if let Ok(c) = root.charge(7) {
                        held.push(c);
                    }
                    assert!(root.used() <= 1000);
                    if i % 3 == 0 {
                        held.pop();
                    }
                }
                held.len()
            })
        })
        .collect();
    let mut total = 0;
    for t in threads {
        total += t.join().unwrap();
    }
    // Todos os `Charge` já morreram com as threads.
    assert!(total * 7 <= 4 * 1000);
    assert_eq!(root.used(), 0);
}
