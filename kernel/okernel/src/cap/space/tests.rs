//! Testes no host do `CapSpace`.

use super::*;

/// Tabela pequena para exercitar folhas, capacidade e gerações.
type Small = CapSpace<4>;

fn quota_cap(root: &Arc<MemoryQuota>, budget: u64) -> Cap {
    Cap {
        object: obj_create(root, ObjectType::MemoryQuota, budget).unwrap(),
        rights: default_rights(ObjectType::MemoryQuota),
        badge: 0,
    }
}

fn setup<const N: usize>() -> (Arc<MemoryQuota>, CapSpace<N>, Handle) {
    let root = MemoryQuota::root(64 << 20);
    let mut space = CapSpace::<N>::new(&root).unwrap();
    let h = space.insert(quota_cap(&root, 16 << 20)).unwrap();
    (root, space, h)
}

#[test]
fn handle_antigo_retorna_invalid_handle() {
    let (_root, mut space, q) = setup::<CAPSPACE_SLOTS_PER_LEVEL>();
    let a = space.mint(q, Rights::ALL, None).unwrap();
    space.delete(a).unwrap();
    let b = space.mint(q, Rights::CREATE, None).unwrap();
    assert_eq!(a.index(), b.index(), "slot reutilizado");
    assert_eq!(b.generation(), a.generation() + 1);
    assert_eq!(space.info(a), Err(Error::InvalidHandle));
    assert_eq!(space.delete(a).unwrap_err(), Error::InvalidHandle);
    assert_eq!(space.mint(a, Rights::ALL, None), Err(Error::InvalidHandle));
    assert_eq!(space.info(b).unwrap().rights, Rights::CREATE);
}

#[test]
fn handles_invalidos() {
    let (_root, space, q) = setup::<4>();
    let bad = [
        Handle::from_raw(0),
        Handle::new(q.index(), q.generation() + 1).unwrap(),
        Handle::new(q.index() + 1, 0).unwrap(),
        Handle::new(Handle::MAX_INDEX, 0).unwrap(),
    ];
    for h in bad {
        assert_eq!(space.get(h).unwrap_err(), Error::InvalidHandle, "{h:?}");
    }
    assert_eq!(q.index(), 1, "o índice 0 nunca é entregue");
}

#[test]
fn geracao_esgotada_aposenta_o_slot() {
    let (_root, mut space, q) = setup::<4>();
    let mut seen = std::collections::HashSet::new();
    let mut last = None;
    for _ in 0..300 {
        let h = space.mint(q, Rights::ALL, None).unwrap();
        assert!(seen.insert(h), "par (índice, geração) repetido: {h:?}");
        space.delete(h).unwrap();
        last = Some(h);
    }
    // O slot 2 passou por 255 encarnações e foi aposentado; o 3 o substituiu.
    let last = last.unwrap();
    assert_eq!(last.index(), 3);
    assert_eq!(seen.iter().filter(|h| h.index() == 2).count(), 255);
    for h in &seen {
        assert_eq!(space.get(*h).unwrap_err(), Error::InvalidHandle);
    }
}

#[test]
fn mint_so_reduz_e_controla_badge() {
    let (_root, mut space, q) = setup::<4>();
    let only_create = space.mint(q, Rights::CREATE | Rights::SEND, None).unwrap();
    let info = space.info(only_create).unwrap();
    assert_eq!(info.rights, Rights::CREATE, "SEND não existia na origem");
    let back = space.mint(only_create, Rights::ALL, Some(7)).unwrap();
    assert_eq!(space.info(back).unwrap().rights, Rights::CREATE);
    assert_eq!(space.info(back).unwrap().badge, 7);
    assert_eq!(
        space.mint(back, Rights::ALL, Some(8)),
        Err(Error::AccessDenied)
    );
    let inherits = space.mint(back, Rights::ALL, None).unwrap();
    assert_eq!(space.info(inherits).unwrap().badge, 7);
    assert_eq!(
        space.info(inherits).unwrap().object_type,
        ObjectType::MemoryQuota
    );
}

#[test]
fn obj_create_confere_tipo_e_direitos() {
    let (root, mut space, q) = setup::<4>();
    let cs = space.obj_create(q, ObjectType::CapSpace, 0).unwrap();
    assert_eq!(
        space.info(cs).unwrap(),
        CapInfo {
            object_type: ObjectType::CapSpace,
            rights: Rights::MANAGE | Rights::BIND | Rights::DESTROY,
            badge: 0
        }
    );
    assert_eq!(
        space.obj_create(cs, ObjectType::CapSpace, 0),
        Err(Error::WrongType)
    );
    let no_split = space.mint(q, Rights::CREATE, None).unwrap();
    assert_eq!(
        space.obj_create(no_split, ObjectType::MemoryQuota, 0),
        Err(Error::AccessDenied)
    );
    // Sem SPLIT ainda se criam objetos que não são cotas.
    let cs2 = space.obj_create(no_split, ObjectType::CapSpace, 0).unwrap();
    assert!(
        !space
            .get(cs2)
            .unwrap()
            .object
            .same(&space.get(cs).unwrap().object)
    );
    let no_create = space.mint(q, Rights::SPLIT, None).unwrap();
    assert_eq!(
        space.obj_create(no_create, ObjectType::CapSpace, 0),
        Err(Error::AccessDenied)
    );
    // O argumento é o limite de threads vivas (ADR 0035, item 5).
    let limited = space.obj_create(q, ObjectType::CapSpace, 3).unwrap();
    let limit = space.get(limited).unwrap().object.clone();
    let crate::cap::Object::CapSpace(limit) = limit else {
        panic!("tipo")
    };
    assert_eq!(limit.lock().process().limit(), 3);
    drop(limit);
    assert_eq!(
        space.obj_create(q, ObjectType::CapSpace, 1 << 32),
        Err(Error::InvalidArgument)
    );
    drop(space);
    assert_eq!(root.used(), 0);
}

#[test]
fn capacidade_de_n_por_n_slots() {
    let (_root, mut space, q) = setup::<4>();
    for _ in 2..16 {
        space.mint(q, Rights::ALL, None).unwrap();
    }
    assert_eq!(space.len(), 15, "16 slots menos o índice 0");
    assert_eq!(space.mint(q, Rights::ALL, None), Err(Error::QuotaExceeded));
    assert_eq!(Small::CAPACITY, 16);
    assert_eq!(CapSpace::<CAPSPACE_SLOTS_PER_LEVEL>::CAPACITY, 1 << 24);
}

#[test]
fn folhas_cobradas_sob_demanda() {
    let root = MemoryQuota::root(1 << 20);
    let mut space = Small::new(&root).unwrap();
    let base = root.used();
    assert_eq!(space.charged(), base);
    let q = space.insert(quota_cap(&root, 0)).unwrap();
    let per_quota = root.used() - base - Small::LEAF_BYTES;
    assert_eq!(space.charged(), base + Small::LEAF_BYTES);
    let mut handles = vec![q];
    for _ in 0..3 {
        handles.push(space.mint(q, Rights::ALL, None).unwrap());
    }
    assert_eq!(
        space.charged(),
        base + 2 * Small::LEAF_BYTES,
        "índice 4 abriu a 2ª folha"
    );
    assert_eq!(root.used(), space.charged() + per_quota);
    for h in handles.drain(..) {
        drop(space.delete(h).unwrap());
    }
    assert_eq!(root.used(), space.charged());
    drop(space);
    assert_eq!(root.used(), 0);
}

#[test]
fn folha_alem_da_cota_falha_sem_efeito() {
    let root = MemoryQuota::root(1 << 20);
    let budget = object_bytes::<SpinLock<Small>>() + Small::LEAF_BYTES;
    let child = obj_create(&root, ObjectType::MemoryQuota, budget).unwrap();
    let cq = child.as_quota().unwrap();
    let mut space = Small::new(cq).unwrap();
    let cap = quota_cap(&root, 0);
    let first = space.insert(cap.clone()).unwrap();
    for _ in 2..4 {
        space.insert(cap.clone()).unwrap();
    }
    assert_eq!(cq.available(), 0);
    assert_eq!(space.insert(cap.clone()), Err(Error::QuotaExceeded));
    assert_eq!(space.len(), 3);
    // Slot liberado é reutilizado sem folha nova.
    space.delete(first).unwrap();
    assert!(space.insert(cap).is_ok());
}

#[test]
fn objeto_morre_com_a_ultima_capability() {
    let root = MemoryQuota::root(1 << 20);
    let mut space = Small::new(&root).unwrap();
    let before = root.used();
    let q = space.insert(quota_cap(&root, 1000)).unwrap();
    let copy = space.mint(q, Rights::CREATE, None).unwrap();
    let after_create = root.used();
    drop(space.delete(q).unwrap());
    assert_eq!(root.used(), after_create, "a cópia mantém o objeto");
    drop(space.delete(copy).unwrap());
    assert_eq!(root.used(), before + Small::LEAF_BYTES);
}
