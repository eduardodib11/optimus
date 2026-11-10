//! Testes no host do backend de VT-d, com registradores e memória falsos.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::*;
use crate::acpi::dmar;
use crate::mm::paging::{ENTRIES, Table};

/// Estado visível de fora da unidade falsa.
#[derive(Default)]
struct Seen {
    regs: Vec<HashMap<usize, u64>>,
    /// Invalidações de IOTLB pedidas: unidade e valor escrito.
    iotlb: Vec<(usize, u64)>,
    tables: HashMap<u64, Box<Table>>,
    next: u64,
    /// Descritores executados da fila: unidade, `u64` baixo e alto.
    queued: Vec<(usize, u64, u64)>,
}

#[derive(Clone)]
struct Fake(Arc<Mutex<Seen>>);

const IOTLB_REG: usize = 0xf8;
const IQH: usize = 0x80;
const FAULTS: usize = 0x220;
/// ND = 2 (256 domínios), SAGAW de 3 níveis, faltas em 0x220, 4 delas.
const CAP_3: u64 = 2 | 2 << 8 | 0x22 << 24 | 3 << 40;
/// Coerente, IOTLB em 0xf0.
const ECAP_C: u64 = 1 | 0x0f << 8;

impl Fake {
    fn new(caps: &[u64]) -> Self {
        Self::with_ecap(caps, ECAP_C)
    }

    fn with_ecap(caps: &[u64], ecap: u64) -> Self {
        let mut seen = Seen {
            next: 0x10_0000,
            ..Seen::default()
        };
        for &cap in caps {
            seen.regs.push(HashMap::from([(CAP, cap), (ECAP, ecap)]));
        }
        Self(Arc::new(Mutex::new(seen)))
    }

    /// Executa a fila da unidade `u` até `tail`: o descritor de espera
    /// escreve o dado no endereço de estado.
    fn run_queue(seen: &mut Seen, u: usize, tail: u64) {
        let base = seen.regs[u][&ir::IQA] & ADDR;
        let mut head = seen.regs[u].get(&IQH).copied().unwrap_or(0);
        while head != tail {
            let i = (head / 8) as usize;
            let (lo, hi) = (seen.tables[&base][i], seen.tables[&base][i + 1]);
            if lo & 0xf == 5 {
                seen.tables.get_mut(&(hi & ADDR)).unwrap()[0] = lo >> 32;
            } else {
                seen.queued.push((u, lo, hi));
            }
            head = (head + 16) % 4096;
        }
        seen.regs[u].insert(IQH, head);
    }

    fn reg(&self, unit: usize, off: usize) -> u64 {
        self.0.lock().unwrap().regs[unit]
            .get(&off)
            .copied()
            .unwrap_or(0)
    }

    fn entry(&self, table: u64, e: usize) -> u64 {
        self.0.lock().unwrap().tables[&table][e]
    }

    fn live(&self) -> usize {
        self.0.lock().unwrap().tables.len()
    }
}

impl TableMemory for Fake {
    fn table(&mut self, phys: PhysAddr) -> &mut Table {
        let mut seen = self.0.lock().unwrap();
        let t: *mut Table = &raw mut **seen.tables.get_mut(&phys.0).expect("tabela desconhecida");
        // SAFETY: a caixa vive no mapa até `free_table`, e o backend só a
        // toca com a trava dele na mão, uma de cada vez.
        unsafe { &mut *t }
    }

    fn alloc_table(&mut self) -> Option<PhysAddr> {
        let mut seen = self.0.lock().unwrap();
        let phys = seen.next;
        seen.next += 4096;
        seen.tables.insert(phys, Box::new([0; ENTRIES]));
        Some(PhysAddr(phys))
    }

    fn free_table(&mut self, phys: PhysAddr) {
        assert!(self.0.lock().unwrap().tables.remove(&phys.0).is_some());
    }
}

impl Hw for Fake {
    fn read32(&mut self, unit: usize, off: usize) -> u32 {
        self.reg(unit, off) as u32
    }

    fn read64(&mut self, unit: usize, off: usize) -> u64 {
        self.reg(unit, off)
    }

    fn write32(&mut self, unit: usize, off: usize, value: u32) {
        let mut seen = self.0.lock().unwrap();
        let regs = &mut seen.regs[unit];
        if off == GCMD {
            // TE, QIE e IRE espelham; SRTP e SIRTP acendem o status; WBF
            // termina na hora.
            let mirrored = TE | SRTP | ir::QIE | ir::IRE | ir::SIRTP;
            regs.insert(GSTS, u64::from(value & mirrored));
        } else {
            regs.insert(off, value.into());
        }
    }

    fn write64(&mut self, unit: usize, off: usize, value: u64) {
        let mut seen = self.0.lock().unwrap();
        if off == IOTLB_REG {
            seen.iotlb.push((unit, value));
        }
        let queue_on = seen.regs[unit]
            .get(&GSTS)
            .is_some_and(|s| *s as u32 & ir::QIE != 0);
        if off == ir::IQT && queue_on {
            seen.regs[unit].insert(off, value);
            Self::run_queue(&mut seen, unit, value);
            return;
        }
        // Invalidações terminam na hora; o F das faltas é RW1C.
        let stored = match off {
            CCMD | IOTLB_REG => value & !(1 << 63),
            o if o >= FAULTS && (o - FAULTS) % 16 == 8 => 0,
            _ => value,
        };
        seen.regs[unit].insert(off, stored);
    }

    fn flush(&mut self, _: PhysAddr, _: usize) {}
}

fn dmar_with(units: &[(u8, Vec<u8>)]) -> Dmar {
    let mut t = vec![0u8; 36];
    t.extend([38, 0]);
    t.extend([0; 10]);
    for (i, (flags, scope)) in units.iter().enumerate() {
        let len = u16::try_from(16 + scope.len()).unwrap();
        t.extend([0, 0]);
        t.extend(len.to_le_bytes());
        t.extend([*flags, 0, 0, 0]);
        t.extend((0xfed9_0000u64 + i as u64 * 0x1000).to_le_bytes());
        t.extend(scope);
    }
    dmar::parse(&t).unwrap()
}

fn one_unit(cap: u64) -> (Fake, VtD) {
    let fake = Fake::new(&[cap]);
    let vtd = VtD::new(Box::new(fake.clone()), dmar_with(&[(1, vec![])])).unwrap();
    (fake, vtd)
}

fn no_quota() -> impl FnMut() -> Result<(), Error> {
    || Ok(())
}

#[test]
fn liga_a_traducao_com_tudo_bloqueado() {
    let (fake, vtd) = one_unit(CAP_3);
    assert_eq!(vtd.shape(), (1, 3));
    assert_eq!(fake.reg(0, GSTS) as u32 & TE, TE);
    let root = fake.reg(0, RTADDR);
    assert!((0..512).all(|e| fake.entry(root, e) == 0));
    let seen = fake.0.lock().unwrap();
    assert_eq!(seen.iotlb, [(0, IVT | DRAIN | GLOBAL_IOTLB)]);
}

#[test]
fn attach_e_map_montam_as_tabelas() {
    let (fake, vtd) = one_unit(CAP_3);
    let tables_before = fake.live();
    let id = vtd.create(&mut no_quota()).unwrap();
    assert_eq!(id, 1);
    vtd.map(id, 0x40_2000, PhysAddr(0x1234_5000), true, &mut no_quota())
        .unwrap();
    vtd.map(id, 0x40_3000, PhysAddr(0x1234_6000), false, &mut no_quota())
        .unwrap();
    vtd.attach(id, 0x0018).unwrap();
    assert_eq!(vtd.attach(id, 0x0018), Err(Error::Busy));
    // Raiz → contexto do barramento 0 → entrada do 00:03.0.
    let root = fake.reg(0, RTADDR);
    let ctx = fake.entry(root, 0) & ADDR;
    let (lo, hi) = (fake.entry(ctx, 0x18 * 2), fake.entry(ctx, 0x18 * 2 + 1));
    assert_eq!((lo & PRESENT, hi), (PRESENT, 1 | 1 << 8));
    // Três níveis: 0x40_2000 = índices 0, 2 e 2.
    let l3 = lo & ADDR;
    let l2 = fake.entry(l3, 0) & ADDR;
    let l1 = fake.entry(l2, 2) & ADDR;
    assert_eq!(fake.entry(l1, 2), 0x1234_5000 | READ | WRITE);
    assert_eq!(fake.entry(l1, 3), 0x1234_6000 | READ);
    // Desmapear zera a folha e invalida o IOTLB do domínio antes de voltar.
    vtd.unmap(id, 0x40_2000, 1);
    assert_eq!(fake.entry(l1, 2), 0);
    let last = *fake.0.lock().unwrap().iotlb.last().unwrap();
    assert_eq!(last, (0, IVT | DRAIN | DOMAIN_IOTLB | 1 << 32));
    // Destruir desliga o dispositivo e devolve raiz e intermediárias.
    assert_eq!(vtd.destroy(id), 3);
    assert_eq!(fake.entry(ctx, 0x18 * 2), 0);
    assert_eq!(fake.live(), tables_before + 1, "fica só a de contexto");
}

#[test]
fn detach_so_do_proprio_dominio() {
    let (fake, vtd) = one_unit(CAP_3);
    let a = vtd.create(&mut no_quota()).unwrap();
    let b = vtd.create(&mut no_quota()).unwrap();
    vtd.attach(a, 0x0100).unwrap();
    vtd.detach(b, 0x0100);
    let ctx = fake.entry(fake.reg(0, RTADDR), 2) & ADDR;
    assert_eq!(fake.entry(ctx, 0) & PRESENT, PRESENT);
    vtd.detach(a, 0x0100);
    assert_eq!(fake.entry(ctx, 0), 0);
}

#[test]
fn faltas_lidas_e_limpas() {
    let (fake, vtd) = one_unit(CAP_3);
    {
        let mut seen = fake.0.lock().unwrap();
        seen.regs[0].insert(FAULTS + 16, 0x40_2abc);
        seen.regs[0].insert(FAULTS + 24, 1 << 63 | 1 << 62 | 6 << 32 | 0x0018);
    }
    let mut got = Vec::new();
    vtd.faults(&mut |f| got.push(f));
    let fault = Fault {
        bdf: 0x0018,
        iova: 0x40_2000,
        reason: 6,
        write: false,
    };
    assert_eq!(got, [fault]);
    got.clear();
    vtd.faults(&mut |f| got.push(f));
    assert!(got.is_empty());
}

#[test]
fn caching_mode_invalida_no_map() {
    let (fake, vtd) = one_unit(CAP_3 | 1 << 7);
    let id = vtd.create(&mut no_quota()).unwrap();
    let before = fake.0.lock().unwrap().iotlb.len();
    vtd.map(id, 0, PhysAddr(0x5000), false, &mut no_quota())
        .unwrap();
    assert_eq!(fake.0.lock().unwrap().iotlb.len(), before + 1);
}

#[test]
fn recusas() {
    // Sem níveis em comum: uma unidade só de 3 níveis, outra só de 4.
    let fake = Fake::new(&[CAP_3, CAP_3 & !(0x1f << 8) | 4 << 8]);
    let two = dmar_with(&[(1, vec![]), (0, vec![])]);
    assert!(VtD::new(Box::new(fake), two).is_none());
    assert!(VtD::new(Box::new(Fake::new(&[])), dmar_with(&[])).is_none());
    // 4 níveis em comum.
    let cap4 = CAP_3 | 4 << 8;
    let fake = Fake::new(&[cap4, cap4 & !(2 << 8)]);
    let vtd = VtD::new(Box::new(fake), dmar_with(&[(1, vec![]), (0, vec![])])).unwrap();
    assert_eq!(vtd.shape(), (2, 4));
    // Unidade sem `INCLUDE_PCI_ALL` e sem escopo: dispositivo sem unidade.
    let fake = Fake::new(&[CAP_3]);
    let vtd = VtD::new(Box::new(fake), dmar_with(&[(0, vec![])])).unwrap();
    let id = vtd.create(&mut no_quota()).unwrap();
    assert_eq!(vtd.attach(id, 0x0018), Err(Error::InvalidArgument));
    // Sem cota para a tabela: nada fica alocado.
    let (fake, vtd) = one_unit(CAP_3);
    let live = fake.live();
    let mut deny = || Err(Error::QuotaExceeded);
    assert_eq!(vtd.create(&mut deny), Err(Error::QuotaExceeded));
    assert_eq!(fake.live(), live);
}

#[test]
fn remapeamento_de_interrupcoes_pela_fila() {
    let fake = Fake::with_ecap(&[CAP_3], ECAP_C | ir::ECAP_QI | ir::ECAP_IR);
    let vtd = VtD::new(Box::new(fake.clone()), dmar_with(&[(1, vec![])])).unwrap();
    assert!(vtd.remapping());
    let sts = fake.reg(0, GSTS) as u32;
    assert_eq!(sts & (TE | ir::QIE | ir::IRE), TE | ir::QIE | ir::IRE);
    let irt = fake.reg(0, ir::IRTA) & ADDR;
    assert_eq!(fake.reg(0, ir::IRTA) & 0xf, 7, "256 entradas");
    {
        let seen = fake.0.lock().unwrap();
        // Com a fila ligada, nada passa pelos registradores de IOTLB.
        assert!(seen.iotlb.is_empty());
        let kinds: Vec<u64> = seen.queued.iter().map(|q| q.1).collect();
        assert_eq!(kinds, [1 | 1 << 4, 2 | 1 << 4 | 3 << 6, 4]);
    }
    // MSI do vetor 0x41 ao APIC 2, só do 00:03.0.
    let address = vtd.remap(0x41, 2, Some(0x18)).unwrap();
    assert_eq!(address, 0xfee0_0000 | 0x41 << 5 | 1 << 4);
    let (lo, hi) = (fake.entry(irt, 0x82), fake.entry(irt, 0x83));
    assert_eq!(lo, 1 | 0x41 << 16 | 2 << 40);
    assert_eq!(hi, 0x18 | 1 << 18);
    let last = *fake.0.lock().unwrap().queued.last().unwrap();
    assert_eq!(last, (0, 4 | 1 << 4 | 0x41 << 32, 0));
    // O IOTLB de um domínio também vai pela fila.
    let id = vtd.create(&mut no_quota()).unwrap();
    vtd.map(id, 0x1000, PhysAddr(0x5000), true, &mut no_quota())
        .unwrap();
    vtd.unmap(id, 0x1000, 1);
    let last = *fake.0.lock().unwrap().queued.last().unwrap();
    assert_eq!(last, (0, 2 | 2 << 4 | 3 << 6 | u64::from(id) << 16, 0));
    // Sem fila ou sem IR, nada de remapeamento.
    let (_, plain) = one_unit(CAP_3);
    assert!(!plain.remapping());
    assert_eq!(plain.remap(0x41, 2, None), None);
}
