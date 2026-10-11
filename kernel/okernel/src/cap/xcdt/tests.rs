//! Testes no host da árvore de derivação entre `CapSpace`s.

use alloc::sync::Arc;

use kabi::{Error, Handle, ObjectType, Rights};

use super::{delete, mint, revoke, transfer};
use crate::cap::space::Revoke;
use crate::cap::{Cap, CapSpace, MemoryQuota, Object, SharedCapSpace, obj_create};
use crate::sync::SpinLock;

fn quota() -> Arc<MemoryQuota> {
    MemoryQuota::root(64 << 20)
}

/// Tabela nova, já com a primeira folha (para a conta da cota fechar).
fn table(cota: &Arc<MemoryQuota>) -> Arc<SharedCapSpace> {
    let s = Arc::new(SpinLock::new(CapSpace::new(cota).unwrap()));
    let h = s.lock().insert(cap(cota)).unwrap();
    drop(s.lock().delete(h).unwrap());
    s
}

fn cap(cota: &Arc<MemoryQuota>) -> Cap {
    Cap {
        object: obj_create(cota, ObjectType::Notification, 0).unwrap(),
        rights: Rights::SIGNAL | Rights::WAIT,
        badge: 0,
    }
}

fn check(spaces: &[&Arc<SharedCapSpace>]) {
    for s in spaces {
        s.lock().check_invariants().unwrap();
    }
}

fn revoke_all(s: &Arc<SharedCapSpace>, h: Handle, budget: u32) -> u32 {
    let mut slices = 1;
    while revoke(s, h, budget).unwrap() == Revoke::Continue {
        slices += 1;
    }
    slices
}

fn alive(s: &Arc<SharedCapSpace>, h: Handle) -> bool {
    s.lock().get(h).is_ok()
}

#[test]
fn revogar_a_original_apaga_as_copias_em_outras_tabelas() {
    let cota = quota();
    let (a, b, c) = (table(&cota), table(&cota), table(&cota));
    let used0 = cota.used();
    let r = a.lock().insert(cap(&cota)).unwrap();
    let a1 = mint(&a, r, Rights::SIGNAL, Some(9)).unwrap();
    let b1 = transfer(&a, a1, &b).unwrap();
    let b2 = mint(&b, b1, Rights::SIGNAL, None).unwrap();
    let c1 = transfer(&b, b2, &c).unwrap();
    // A cópia tem os direitos e o badge da original.
    let info = b.lock().info(b1).unwrap();
    assert_eq!((info.rights, info.badge), (Rights::SIGNAL, 9));
    check(&[&a, &b, &c]);
    let slices = revoke_all(&a, r, 1);
    assert!(slices >= 4, "uma capability por fatia: {slices}");
    assert!(alive(&a, r));
    assert!(!alive(&a, a1) && !alive(&b, b1) && !alive(&b, b2) && !alive(&c, c1));
    assert_eq!((b.lock().len(), c.lock().len()), (0, 0));
    check(&[&a, &b, &c]);
    drop(a.lock().delete(r).unwrap());
    assert_eq!(cota.used(), used0, "slots e elos devolvidos à cota");
}

#[test]
fn delete_da_original_deixa_marcador_ate_a_copia_sumir() {
    let cota = quota();
    let (a, b) = (table(&cota), table(&cota));
    let charged = (a.lock().charged(), b.lock().charged());
    let c = cap(&cota);
    let weak = Arc::downgrade(c.object.as_notification().unwrap());
    let r = a.lock().insert(c).unwrap();
    let b1 = transfer(&a, r, &b).unwrap();
    delete(&a, r).unwrap();
    assert_eq!(a.lock().len(), 0);
    assert!(alive(&b, b1) && weak.strong_count() == 1);
    check(&[&a, &b]);
    // A cópia ainda é filha (do marcador): uma neta em C também.
    let c_space = table(&cota);
    let c1 = transfer(&b, b1, &c_space).unwrap();
    delete(&b, b1).unwrap();
    assert!(alive(&c_space, c1));
    check(&[&a, &b, &c_space]);
    delete(&c_space, c1).unwrap();
    assert_eq!(weak.strong_count(), 0, "o objeto morre com a última cópia");
    check(&[&a, &b, &c_space]);
    let after = (a.lock().charged(), b.lock().charged());
    assert_eq!(after, charged, "marcadores e elos liberados");
}

#[test]
fn delete_da_copia_sai_da_lista_do_pai() {
    let cota = quota();
    let (a, b) = (table(&cota), table(&cota));
    let used0 = cota.used();
    let r = a.lock().insert(cap(&cota)).unwrap();
    let b1 = transfer(&a, r, &b).unwrap();
    delete(&b, b1).unwrap();
    let index = a.lock().index(r).unwrap();
    assert!(!a.lock().has_xlinks(index));
    check(&[&a, &b]);
    delete(&a, r).unwrap();
    assert_eq!(cota.used(), used0);
}

#[test]
fn revogacao_em_andamento_barra_mint_e_transferencia_remotos() {
    let cota = quota();
    let (a, b, c) = (table(&cota), table(&cota), table(&cota));
    let r = a.lock().insert(cap(&cota)).unwrap();
    let a1 = mint(&a, r, Rights::ALL, None).unwrap();
    let b1 = transfer(&a, a1, &b).unwrap();
    let _a2 = mint(&a, r, Rights::ALL, None).unwrap();
    assert_eq!(revoke(&a, r, 1), Ok(Revoke::Continue));
    assert_eq!(mint(&b, b1, Rights::ALL, None), Err(Error::Busy));
    assert_eq!(transfer(&b, b1, &c), Err(Error::Busy));
    revoke_all(&a, r, 1);
    assert!(!alive(&b, b1));
    check(&[&a, &b, &c]);
}

#[test]
fn revogacao_de_fora_encerra_a_revogacao_da_copia() {
    let cota = quota();
    let (a, b) = (table(&cota), table(&cota));
    let r = a.lock().insert(cap(&cota)).unwrap();
    let b1 = transfer(&a, r, &b).unwrap();
    for _ in 0..3 {
        mint(&b, b1, Rights::ALL, None).unwrap();
    }
    assert_eq!(revoke(&b, b1, 1), Ok(Revoke::Continue));
    revoke_all(&a, r, 1);
    assert!(!alive(&b, b1));
    assert_eq!(b.lock().revoking(), None);
    assert_eq!(revoke(&b, b1, 1), Err(Error::InvalidHandle));
    check(&[&a, &b]);
}

#[test]
fn profundidade_conta_os_niveis_remotos() {
    let cota = quota();
    let (a, b) = (table(&cota), table(&cota));
    let mut h = a.lock().insert(cap(&cota)).unwrap();
    for _ in 0..63 {
        h = mint(&a, h, Rights::ALL, None).unwrap();
    }
    let deep = transfer(&a, h, &b).unwrap();
    assert_eq!(b.lock().depth(deep), Ok(0), "raiz local");
    assert_eq!(
        mint(&b, deep, Rights::ALL, None),
        Err(Error::InvalidArgument)
    );
    assert_eq!(transfer(&b, deep, &a), Err(Error::InvalidArgument));
    // Sem o elo remoto (só a tabela local), o mint passaria.
    assert!(b.lock().mint(deep, Rights::ALL, None).is_ok());
}

#[test]
fn tabela_morta_deixa_elos_vencidos_que_sao_descartados() {
    let cota = quota();
    let a = table(&cota);
    let used0 = cota.used();
    let r = a.lock().insert(cap(&cota)).unwrap();
    let b = table(&cota);
    transfer(&a, r, &b).unwrap();
    drop(b);
    assert_eq!(revoke(&a, r, 1), Ok(Revoke::Done));
    let index = a.lock().index(r).unwrap();
    assert!(!a.lock().has_xlinks(index));
    // Delete com filho vencido: o marcador é liberado na hora.
    let b = table(&cota);
    transfer(&a, r, &b).unwrap();
    drop(b);
    delete(&a, r).unwrap();
    check(&[&a]);
    assert_eq!(cota.used(), used0);
}

#[test]
fn na_mesma_tabela_a_transferencia_e_um_mint() {
    let cota = quota();
    let a = table(&cota);
    let r = a.lock().insert(cap(&cota)).unwrap();
    let copy = transfer(&a, r, &a).unwrap();
    assert_eq!(a.lock().parent(copy), Ok(Some(r)));
    let obj: Object = a.lock().get(copy).unwrap().object.clone();
    assert!(obj.same(&a.lock().get(r).unwrap().object));
    revoke_all(&a, r, 64);
    assert!(!alive(&a, copy));
}

/// Modelo de referência: cada capability com o pai lógico (o marcador é
/// transparente: o filho de uma capability apagada passa ao avô).
struct Model {
    /// Tabela, handle e pai (índice no vetor).
    nodes: Vec<(usize, Handle, Option<usize>)>,
    alive: Vec<bool>,
}

impl Model {
    fn descendants(&self, i: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = vec![i];
        while let Some(n) = stack.pop() {
            for (j, &(_, _, p)) in self.nodes.iter().enumerate() {
                if p == Some(n) && self.alive[j] {
                    out.push(j);
                    stack.push(j);
                }
            }
        }
        out
    }

    fn live(&self) -> Vec<usize> {
        (0..self.nodes.len()).filter(|&i| self.alive[i]).collect()
    }

    fn push(&mut self, space: usize, h: Handle, parent: Option<usize>) {
        self.nodes.push((space, h, parent));
        self.alive.push(true);
    }
}

#[test]
fn operacoes_aleatorias_entre_tres_tabelas_seguem_o_modelo() {
    let cota = quota();
    let spaces = [table(&cota), table(&cota), table(&cota)];
    let mut model = Model {
        nodes: Vec::new(),
        alive: Vec::new(),
    };
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        usize::try_from(seed % n as u64).unwrap()
    };
    for step in 0..3000 {
        let live = model.live();
        let op = if live.is_empty() { 0 } else { next(10) };
        let i = if live.is_empty() {
            0
        } else {
            live[next(live.len())]
        };
        match op {
            0 => {
                let s = next(3);
                let h = spaces[s].lock().insert(cap(&cota)).unwrap();
                model.push(s, h, None);
            }
            1..=3 => {
                let (s, h, _) = model.nodes[i];
                if let Ok(c) = mint(&spaces[s], h, Rights::ALL, None) {
                    model.push(s, c, Some(i));
                }
            }
            4..=6 => {
                let (s, h, _) = model.nodes[i];
                let to = next(3);
                if let Ok(c) = transfer(&spaces[s], h, &spaces[to]) {
                    model.push(to, c, Some(i));
                }
            }
            7 | 8 => {
                let (s, h, parent) = model.nodes[i];
                delete(&spaces[s], h).unwrap();
                model.alive[i] = false;
                for node in &mut model.nodes {
                    if node.2 == Some(i) {
                        node.2 = parent;
                    }
                }
            }
            _ => {
                let (s, h, _) = model.nodes[i];
                revoke_all(&spaces[s], h, 3);
                for d in model.descendants(i) {
                    model.alive[d] = false;
                }
            }
        }
        for (n, &(s, h, _)) in model.nodes.iter().enumerate() {
            assert_eq!(alive(&spaces[s], h), model.alive[n], "passo {step}, nó {n}");
        }
        for (s, space) in spaces.iter().enumerate() {
            let live = model.live();
            let count = live.iter().filter(|&&n| model.nodes[n].0 == s).count();
            assert_eq!(space.lock().len() as usize, count, "passo {step}");
            space.lock().check_invariants().unwrap();
        }
    }
}
