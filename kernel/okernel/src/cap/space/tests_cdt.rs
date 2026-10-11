//! Testes no host da árvore de derivação e de `cap_revoke` (T-204).
//!
//! Além dos casos dirigidos, dois testes cobrem a propriedade "direitos
//! nunca aumentam" e os demais invariantes da spec `CapRevoke.tla`: um
//! exaustivo (todas as sequências curtas de operações num `CapSpace`
//! pequeno, como o TLC faria) e um aleatório longo com PRNG próprio.

use super::*;

fn setup<const N: usize>() -> (Arc<MemoryQuota>, CapSpace<N>, Handle) {
    let root = MemoryQuota::root(1 << 30);
    let mut space = CapSpace::<N>::new(&root).unwrap();
    let cap = Cap {
        object: obj_create(&root, ObjectType::MemoryQuota, 0).unwrap(),
        rights: Rights::ALL,
        badge: 0,
    };
    let h = space.insert(cap).unwrap();
    (root, space, h)
}

/// Índices dos descendentes de `index`, por busca na árvore.
fn descendants<const N: usize>(space: &CapSpace<N>, index: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut stack = vec![space.slot(index).first_child];
    while let Some(mut child) = stack.pop() {
        while child != NIL {
            out.push(child);
            stack.push(space.slot(child).first_child);
            child = space.slot(child).next;
        }
    }
    out
}

fn revoke_all<const N: usize>(space: &mut CapSpace<N>, h: Handle, budget: u32) -> u32 {
    let mut slices = 1;
    while space.revoke(h, budget).unwrap() == Revoke::Continue {
        slices += 1;
    }
    slices
}

#[test]
fn delete_sobe_filhos_para_o_avo() {
    let (_q, mut s, r) = setup::<16>();
    let a = s.mint(r, Rights::ALL, None).unwrap();
    let b1 = s.mint(a, Rights::CREATE, None).unwrap();
    let b2 = s.mint(a, Rights::SPLIT, None).unwrap();
    let c = s.mint(b1, Rights::NONE, None).unwrap();
    assert_eq!((s.depth(c), s.parent(c)), (Ok(3), Ok(Some(b1))));
    s.delete(a).unwrap();
    assert_eq!(s.parent(b1), Ok(Some(r)));
    assert_eq!(s.parent(b2), Ok(Some(r)));
    assert_eq!(s.depth(c), Ok(2));
    s.check_invariants().unwrap();
    // Apagar uma raiz com filhos os torna raízes.
    s.delete(r).unwrap();
    assert_eq!((s.parent(b1), s.parent(b2)), (Ok(None), Ok(None)));
    assert_eq!(s.parent(c), Ok(Some(b1)));
    s.check_invariants().unwrap();
}

#[test]
fn revoke_apaga_descendentes_e_poupa_o_resto() {
    let (_q, mut s, r) = setup::<16>();
    let a = s.mint(r, Rights::ALL, None).unwrap();
    let sibling = s.mint(r, Rights::ALL, None).unwrap();
    let mut under_a = vec![];
    for i in 0..20 {
        let src = if i % 3 == 0 { a } else { under_a[i / 2] };
        under_a.push(s.mint(src, Rights::ALL, None).unwrap());
        if i == 0 {
            under_a.push(s.mint(a, Rights::ALL, None).unwrap());
        }
    }
    assert_eq!(s.revoke(a, 1000).unwrap(), Revoke::Done);
    for h in &under_a {
        assert_eq!(s.get(*h).unwrap_err(), Error::InvalidHandle);
    }
    assert!(s.get(a).is_ok() && s.get(sibling).is_ok() && s.get(r).is_ok());
    assert_eq!(s.len(), 3);
    assert_eq!(s.revoking(), None);
    // Revogar sem descendentes termina na hora.
    assert_eq!(s.revoke(a, 0), Ok(Revoke::Done));
    s.check_invariants().unwrap();
}

#[test]
fn revogacao_em_andamento_marca_busy() {
    let (_q, mut s, r) = setup::<64>();
    let a = s.mint(r, Rights::ALL, None).unwrap();
    let outside = s.mint(r, Rights::ALL, None).unwrap();
    let mut inside = vec![a];
    for i in 0..300 {
        inside.push(s.mint(inside[i / 2], Rights::ALL, None).unwrap());
    }
    assert_eq!(s.revoke(a, 0), Ok(Revoke::Continue));
    assert_eq!(s.revoking(), Some(a));
    let alive = inside.iter().copied().filter(|h| s.get(*h).is_ok());
    let alive: Vec<_> = alive.collect();
    assert!(alive.len() > 2, "a fatia não apagou tudo");
    // Mint na subárvore (alvo incluído): Busy. Fora dela: ok.
    for &h in &alive {
        assert_eq!(s.mint(h, Rights::ALL, None), Err(Error::Busy));
    }
    assert!(s.mint(outside, Rights::ALL, None).is_ok());
    assert!(
        s.mint(r, Rights::ALL, None).is_ok(),
        "ancestral não está na subárvore"
    );
    // Delete do alvo: Busy; de outro descendente: ok.
    assert_eq!(s.delete(a).unwrap_err(), Error::Busy);
    s.delete(*alive.last().unwrap()).unwrap();
    // Outra revogação: Busy; a mesma retoma.
    assert_eq!(s.revoke(r, 0), Err(Error::Busy));
    assert_eq!(s.revoke(outside, 0), Err(Error::Busy));
    s.check_invariants().unwrap();
    revoke_all(&mut s, a, 0);
    assert_eq!(s.revoking(), None);
    assert!(s.mint(a, Rights::ALL, None).is_ok());
    assert_eq!(s.revoke(r, 1000), Ok(Revoke::Done));
    assert_eq!(s.len(), 1);
}

#[test]
fn fatias_respeitam_o_orcamento() {
    let (_q, mut s, r) = setup::<128>();
    let mut handles = vec![r];
    for i in 0..10_000usize {
        let src = handles[(i * 7919) % handles.len()];
        match s.mint(src, Rights::ALL, None) {
            Ok(h) => handles.push(h),
            Err(e) => assert_eq!(e, Error::InvalidArgument, "só o limite de profundidade"),
        }
    }
    let total = s.len() - 1;
    let budget = 200;
    let mut slices = 0;
    loop {
        let before = s.len();
        let status = s.revoke(r, budget).unwrap();
        // Cada passo apaga no máximo uma capability; toda fatia progride.
        let freed = before - s.len();
        assert!(freed <= budget && (freed > 0 || status == Revoke::Done));
        assert!(status == Revoke::Done || freed > 0);
        slices += 1;
        if status == Revoke::Done {
            break;
        }
    }
    assert!(slices >= total.div_ceil(budget), "{slices} fatias");
    assert_eq!(s.len(), 1);
    s.check_invariants().unwrap();
}

#[test]
fn profundidade_limitada() {
    let (_q, mut s, r) = setup::<16>();
    let mut h = r;
    for _ in 0..MAX_DERIVATION_DEPTH {
        h = s.mint(h, Rights::ALL, None).unwrap();
    }
    assert_eq!(s.depth(h), Ok(MAX_DERIVATION_DEPTH));
    assert_eq!(s.mint(h, Rights::ALL, None), Err(Error::InvalidArgument));
    // A cadeia mais funda ainda é revogada com o orçamento mínimo.
    // Mesmo com orçamento 1, a fatia desce 64 níveis e apaga a folha.
    assert_eq!(s.revoke(r, 1), Ok(Revoke::Continue));
    assert_eq!(s.len(), MAX_DERIVATION_DEPTH);
    assert_eq!(revoke_all(&mut s, r, 1), 63);
    assert_eq!(s.len(), 1);
}

/// PRNG xorshift64: determinístico e sem dependências.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

/// Operação sobre o `CapSpace`, com handles por posição na lista dos já
/// entregues (posição além do fim: handle forjado).
#[derive(Clone, Copy, Debug)]
enum Op {
    Create,
    Mint(usize, u32, Option<u64>),
    Delete(usize),
    Revoke(usize, u32),
}

/// Aplica `op` e confere a spec: direitos só diminuem, invariantes da
/// árvore, handle antigo nunca volta a resolver e revogação completa.
struct Checker<const N: usize> {
    quota: Arc<MemoryQuota>,
    space: CapSpace<N>,
    /// Handles entregues e se ainda podem resolver.
    issued: Vec<(Handle, bool)>,
    /// Descendentes do alvo quando a revogação em andamento começou.
    revoked: Vec<Handle>,
}

impl<const N: usize> Checker<N> {
    fn new() -> Self {
        let quota = MemoryQuota::root(1 << 30);
        let space = CapSpace::new(&quota).unwrap();
        Self {
            quota,
            space,
            issued: Vec::new(),
            revoked: Vec::new(),
        }
    }

    fn handle(&self, i: usize) -> Handle {
        self.issued.get(i).map_or(
            Handle::new(u32::try_from(i).unwrap() + 1, 0).unwrap(),
            |e| e.0,
        )
    }

    /// `InRevoke` da spec: `h` é o alvo da revogação ou descende dele.
    fn in_revoke(&self, h: Handle) -> bool {
        self.space
            .revoking()
            .is_some_and(|r| r == h || descendants(&self.space, r.index()).contains(&h.index()))
    }

    fn apply(&mut self, op: Op) {
        match op {
            Op::Create => {
                let object = obj_create(&self.quota, ObjectType::MemoryQuota, 0).unwrap();
                let cap = Cap {
                    object,
                    rights: Rights::ALL,
                    badge: 0,
                };
                if let Ok(h) = self.space.insert(cap) {
                    self.issued.push((h, true));
                }
            }
            Op::Mint(i, mask, badge) => {
                let src = self.handle(i);
                let mask = Rights::from_bits(mask & Rights::ALL.bits()).unwrap();
                let before = self.space.get(src).map(|c| c.rights);
                let result = self.space.mint(src, mask, badge);
                if before.is_ok() && self.in_revoke(src) {
                    assert_eq!(result, Err(Error::Busy), "mint na subárvore em revogação");
                }
                if let Ok(h) = result {
                    let parent = before.expect("mint de handle inválido");
                    let child = self.space.get(h).unwrap().rights;
                    assert!(parent.contains(child), "direitos aumentaram");
                    assert_eq!(child, parent.derive(mask));
                    assert_eq!(self.space.parent(h), Ok(Some(src)));
                    self.issued.push((h, true));
                }
            }
            Op::Delete(i) => {
                let h = self.handle(i);
                let target = self.space.revoking() == Some(h);
                match self.space.delete(h) {
                    Ok(_) => assert!(!target && self.space.get(h).is_err()),
                    Err(e) => assert!(!target || e == Error::Busy),
                }
            }
            Op::Revoke(i, budget) => {
                let h = self.handle(i);
                let starting = self.space.revoking().is_none();
                let index = self.space.index_of(h);
                if let (true, Ok(index)) = (starting, index) {
                    self.revoked = descendants(&self.space, index)
                        .into_iter()
                        .map(|d| self.space.handle(d))
                        .collect();
                }
                if self.space.revoke(h, budget) == Ok(Revoke::Done) {
                    // RevokeComplete: nenhum descendente sobrou.
                    assert!(descendants(&self.space, h.index()).is_empty());
                    for d in self.revoked.drain(..) {
                        assert!(self.space.get(d).is_err(), "descendente sobreviveu");
                    }
                }
            }
        }
        self.space.check_invariants().unwrap();
        for (h, alive) in &mut self.issued {
            let resolves = self.space.get(*h).is_ok();
            assert!(*alive || !resolves, "NoStaleHandle: {h:?} voltou a valer");
            *alive = resolves;
        }
    }
}

const MASKS: [u32; 3] = [u32::MAX, 0b01, 0b10];

/// Todas as sequências de até `depth` operações num alfabeto pequeno.
fn explore(prefix: &mut Vec<Op>, depth: usize, count: &mut u64) {
    let mut checker = Checker::<2>::new();
    for &op in prefix.iter() {
        checker.apply(op);
    }
    *count += 1;
    if depth == 0 {
        return;
    }
    let handles = checker.issued.len() + 1;
    let mut ops = vec![Op::Create];
    for i in 0..handles {
        for &m in &MASKS {
            ops.push(Op::Mint(i, m, None));
        }
        ops.push(Op::Mint(i, u32::MAX, Some(9)));
        ops.push(Op::Delete(i));
        ops.push(Op::Revoke(i, 1));
    }
    for op in ops {
        prefix.push(op);
        explore(prefix, depth - 1, count);
        prefix.pop();
    }
}

#[test]
fn exaustivo_em_capspace_pequeno() {
    // CapSpace<2>: 3 slots utilizáveis, como o modelo do TLC.
    let mut count = 0;
    explore(&mut Vec::new(), 5, &mut count);
    println!("{count} sequências exploradas");
    assert!(count > 100_000, "{count} sequências");
}

#[test]
fn aleatorio_longo_com_prng() {
    for seed in 1..=8u64 {
        let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut checker = Checker::<8>::new();
        for _ in 0..4000 {
            let alive: Vec<usize> = (0..checker.issued.len())
                .filter(|&i| checker.issued[i].1)
                .collect();
            let pick = |rng: &mut XorShift| {
                if alive.is_empty() || rng.below(10) == 0 {
                    rng.below(checker.issued.len() + 2)
                } else {
                    alive[rng.below(alive.len())]
                }
            };
            let op = match rng.below(10) {
                0 => Op::Create,
                1..=5 => {
                    let i = pick(&mut rng);
                    let mask = u32::try_from(rng.next() >> 32).unwrap();
                    let badge = (rng.below(4) == 0).then(|| rng.next());
                    Op::Mint(i, mask, badge)
                }
                6 | 7 => Op::Delete(pick(&mut rng)),
                _ => Op::Revoke(pick(&mut rng), u32::try_from(rng.below(8)).unwrap()),
            };
            checker.apply(op);
        }
    }
}
