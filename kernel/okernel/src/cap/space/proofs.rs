//! Provas Kani de que direitos nunca aumentam (T-204).
//!
//! Rodam com `cargo xtask kani` (Kani instalado no host: `cargo install
//! --locked kani-verifier && cargo kani setup`). Os valores simbólicos
//! cobrem todos os padrões de bits de direitos, máscara e badge e todos os
//! handles de 32 bits; as sequências de operações usam um `CapSpace<2>` (3
//! slots utilizáveis), o mesmo tamanho do modelo do TLC.
//!
//! As provas usam um objeto de brinquedo ([`Token`]) no lugar de `Object`: a
//! destruição em cadeia de `Arc`s (cota que segura a cota mãe, tabela que
//! segura capabilities) vira recursão que o CBMC teria de desenrolar em todo
//! caminho de erro, e a lógica de slots e da árvore não depende do objeto.
//! Pelo mesmo motivo a tabela não é destruída no fim (`mem::forget`): o
//! `Charge` dela segura a cota.
//!
//! Estado: `derive_nunca_aumenta` e `mint_nunca_aumenta` são verificadas
//! (Kani 0.68, CBMC 6.11; cerca de 40 s). As provas de delete e revoke
//! partem de uma cadeia de dois mints, e já montar essa cadeia esgota os
//! 15 GiB de memória do CBMC na fase de pós-processamento; ficam escritas e
//! só rodam com `KANI_ALL=1 cargo xtask kani`. A mesma propriedade (e os
//! demais invariantes da spec) é coberta pelos testes exaustivo e
//! aleatório de `tests_cdt`.

use super::*;

/// Direitos simbólicos: qualquer combinação dos bits definidos.
fn any_rights() -> Rights {
    Rights::from_bits(kani::any::<u32>() & Rights::ALL.bits()).unwrap()
}

/// Objeto sem destruição em cadeia; a identidade é o número.
#[derive(Clone, Debug)]
struct Token(u8);

impl CapObject for Token {
    fn object_type(&self) -> ObjectType {
        ObjectType::Endpoint
    }

    fn same(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

type Space = CapSpace<2, Token>;

/// Tabela com uma capability raiz de objeto, direitos e badge quaisquer.
fn space_with_root() -> (Space, Handle) {
    let quota = MemoryQuota::root(u64::MAX);
    let mut space = Space::new(&quota).unwrap();
    core::mem::forget(quota);
    let cap = Cap {
        object: Token(kani::any()),
        rights: any_rights(),
        badge: kani::any(),
    };
    let h = space.insert(cap).unwrap();
    (space, h)
}

/// `Rights::derive` nunca devolve bit que a origem não tinha.
#[kani::proof]
fn derive_nunca_aumenta() {
    let (parent, mask) = (any_rights(), any_rights());
    let child = parent.derive(mask);
    assert!(parent.contains(child));
    assert!(mask.contains(child));
}

/// Um `cap_mint` com origem, máscara e badge simbólicos só reduz direitos,
/// e a cópia é filha da origem, do mesmo objeto.
#[kani::proof]
#[kani::unwind(6)]
fn mint_nunca_aumenta() {
    let (mut space, root) = space_with_root();
    let parent = space.get(root).unwrap().rights;
    let badge: Option<u64> = kani::any();
    if let Ok(h) = space.mint(root, any_rights(), badge) {
        assert!(parent.contains(space.get(h).unwrap().rights));
        assert!(space.parent(h) == Ok(Some(root)));
    }
    core::mem::forget(space);
}

/// `MintMonotonic` da spec: todo filho tem direitos contidos nos do pai e
/// aponta para o mesmo objeto. Versão enxuta de `check_invariants`, que
/// esgota a memória do CBMC dentro de uma sequência.
fn mint_monotonic(space: &Space) -> bool {
    (1..space.fresh).all(|index| {
        let slot = space.slot(index);
        match (&slot.cap, slot.parent) {
            (None, parent) => parent == NIL,
            (Some(_), NIL) => true,
            (Some(cap), parent) => space
                .slot(parent)
                .cap
                .as_ref()
                .is_some_and(|p| p.rights.contains(cap.rights) && p.object.same(&cap.object)),
        }
    })
}

/// Cadeia raiz → a → b com direitos e máscaras simbólicos (os 3 slots de
/// um `CapSpace<2>`); devolve o handle de posição `which` na cadeia. Cada
/// posição tem a própria prova: com o alvo concreto, o CBMC não precisa
/// raciocinar sobre escritas em slot simbólico (que esgotam a memória).
fn chain(which: usize) -> (Space, Handle) {
    let (mut space, root) = space_with_root();
    let a = space.mint(root, any_rights(), None).unwrap();
    let b = space.mint(a, any_rights(), None).unwrap();
    (space, [root, a, b][which])
}

/// `cap_delete` preserva `MintMonotonic`, inclusive quando sobe o filho para
/// o avô ou o torna raiz.
fn check_delete(which: usize) {
    let (mut space, h) = chain(which);
    assert!(space.delete(h).is_ok());
    assert!(mint_monotonic(&space));
    core::mem::forget(space);
}

/// Uma fatia de `cap_revoke` de orçamento qualquer preserva
/// `MintMonotonic` e nunca apaga o alvo.
fn check_revoke(which: usize) {
    let (mut space, h) = chain(which);
    assert!(space.revoke(h, kani::any()).is_ok());
    assert!(space.get(h).is_ok());
    assert!(mint_monotonic(&space));
    core::mem::forget(space);
}

/// Delete da raiz: o filho vira raiz.
#[kani::proof]
#[kani::unwind(6)]
fn delete_da_raiz_nunca_aumenta_direitos() {
    check_delete(0);
}

/// Delete do meio: o neto sobe para a raiz.
#[kani::proof]
#[kani::unwind(6)]
fn delete_do_meio_nunca_aumenta_direitos() {
    check_delete(1);
}

/// Delete da folha.
#[kani::proof]
#[kani::unwind(6)]
fn delete_da_folha_nunca_aumenta_direitos() {
    check_delete(2);
}

/// Revoke da raiz, em uma ou mais fatias conforme o orçamento.
#[kani::proof]
#[kani::unwind(6)]
fn revoke_da_raiz_nunca_aumenta_direitos() {
    check_revoke(0);
}

/// Revoke do meio.
#[kani::proof]
#[kani::unwind(6)]
fn revoke_do_meio_nunca_aumenta_direitos() {
    check_revoke(1);
}
