//! Testes no host do backend de AMD-Vi, com uma unidade falsa que executa
//! os comandos do buffer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::*;
use crate::acpi::ivrs;
use crate::mm::paging::{ENTRIES, Table, TableMemory};

#[derive(Default)]
struct Seen {
    regs: Vec<HashMap<usize, u64>>,
    tables: HashMap<u64, Box<Table>>,
    next: u64,
    /// Comandos executados (sem os `COMPLETION_WAIT`): unidade e opcode.
    done: Vec<(usize, u32, u64)>,
}

#[derive(Clone)]
struct Fake(Arc<Mutex<Seen>>);

impl Fake {
    fn new(units: usize) -> Self {
        let seen = Seen {
            regs: vec![HashMap::new(); units],
            next: 0x10_0000,
            ..Seen::default()
        };
        Self(Arc::new(Mutex::new(seen)))
    }

    fn reg(&self, u: usize, off: usize) -> u64 {
        self.0.lock().unwrap().regs[u]
            .get(&off)
            .copied()
            .unwrap_or(0)
    }

    fn word(&self, phys: u64) -> u64 {
        self.0.lock().unwrap().tables[&(phys & !0xfff)][((phys & 0xfff) / 8) as usize]
    }

    fn live(&self) -> usize {
        self.0.lock().unwrap().tables.len()
    }

    /// Executa os comandos de `head` a `tail` da unidade `u`.
    fn run(seen: &mut Seen, u: usize, tail: u64) {
        let base = seen.regs[u][&CMD_BUF] & ADDR;
        let mut head = seen.regs[u].get(&CMD_HEAD).copied().unwrap_or(0);
        while head != tail {
            let t = &seen.tables[&base];
            let (lo, hi) = (t[(head / 8) as usize], t[(head / 8) as usize + 1]);
            let op = (lo >> 60) as u32;
            if op == 1 {
                let addr = (lo & 0xffff_fff8) | (lo >> 32 & 0xf_ffff) << 32;
                seen.tables.get_mut(&(addr & !0xfff)).unwrap()[0] = hi;
            } else {
                seen.done.push((u, op, lo));
            }
            head = (head + 16) % 4096;
        }
        seen.regs[u].insert(CMD_HEAD, head);
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
        self.alloc_contiguous(0)
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
        self.write64(unit, off, value.into());
    }

    fn write64(&mut self, unit: usize, off: usize, value: u64) {
        let mut seen = self.0.lock().unwrap();
        seen.regs[unit].insert(off, value);
        let on = seen.regs[unit]
            .get(&CONTROL)
            .is_some_and(|c| c & CMD_BUF_EN != 0);
        if off == CMD_TAIL && on {
            Self::run(&mut seen, unit, value);
        }
    }

    fn flush(&mut self, _: PhysAddr, _: usize) {}

    fn alloc_contiguous(&mut self, order: u32) -> Option<PhysAddr> {
        let mut seen = self.0.lock().unwrap();
        let first = seen.next;
        for p in 0..1u64 << order {
            seen.tables.insert(first + p * 4096, Box::new([0; ENTRIES]));
        }
        seen.next += 4096 << order;
        Some(PhysAddr(first))
    }
}

fn ivrs_all(units: usize) -> Ivrs {
    let mut t = vec![0u8; 48];
    for u in 0..units {
        let mut b = vec![0u8; 24];
        b[0] = 0x10;
        b[8..16].copy_from_slice(&(0xfed8_0000u64 + u as u64 * 0x10_0000).to_le_bytes());
        b.extend([1, 0, 0, 0]);
        b[2..4].copy_from_slice(&28u16.to_le_bytes());
        t.extend(b);
    }
    ivrs::parse(&t).unwrap()
}

fn one_unit() -> (Fake, AmdVi) {
    let fake = Fake::new(1);
    let amd = AmdVi::new(Box::new(fake.clone()), ivrs_all(1)).unwrap();
    (fake, amd)
}

fn no_quota() -> impl FnMut() -> Result<(), Error> {
    || Ok(())
}

/// Entrada bloqueada: a tabela vazia da unidade 0, domínio 0.
fn blocked_entry(fake: &Fake) -> (u64, u64) {
    let (lo, hi) = entry(fake, 0);
    assert_eq!(lo & !ADDR, VALID | TRANSLATE | 3 << 9 | IR | IW);
    let empty = lo & ADDR;
    assert!((0..512).all(|e| fake.word(empty + e * 8) == 0));
    (lo, hi)
}

fn entry(fake: &Fake, bdf: u16) -> (u64, u64) {
    let base = fake.reg(0, DEV_TAB) & ADDR;
    let at = base + u64::from(bdf) * 32;
    (fake.word(at), fake.word(at + 8))
}

#[test]
fn liga_com_todo_dispositivo_bloqueado() {
    let (fake, amd) = one_unit();
    assert_eq!(amd.units(), 1);
    assert_eq!(fake.reg(0, DEV_TAB) & 0x1ff, 0x1ff);
    assert_eq!(
        fake.reg(0, CONTROL) & (IOMMU_EN | CMD_BUF_EN),
        IOMMU_EN | CMD_BUF_EN
    );
    let blocked = blocked_entry(&fake);
    for bdf in [0x18, 0xffff] {
        assert_eq!(entry(&fake, bdf), blocked);
    }
}

#[test]
fn attach_e_map_montam_as_tabelas() {
    let (fake, amd) = one_unit();
    let before = fake.live();
    let id = amd.create(&mut no_quota()).unwrap();
    amd.map(id, 0x40_2000, PhysAddr(0x1234_5000), true, &mut no_quota())
        .unwrap();
    amd.map(id, 0x40_3000, PhysAddr(0x1234_6000), false, &mut no_quota())
        .unwrap();
    amd.attach(id, 0x0018).unwrap();
    assert_eq!(amd.attach(id, 0x0018), Err(Error::Busy));
    let (lo, hi) = entry(&fake, 0x0018);
    assert_eq!(
        (lo & !ADDR, hi),
        (VALID | TRANSLATE | 3 << 9 | IR | IW, u64::from(id))
    );
    assert!(
        fake.0
            .lock()
            .unwrap()
            .done
            .contains(&(0, 2, 0x2000_0000_0000_0018))
    );
    // 0x40_2000: índices 0, 2 e 2; diretórios com o nível de baixo.
    let l3 = lo & ADDR;
    let l2 = fake.word(l3);
    let l1 = fake.word((l2 & ADDR) + 2 * 8);
    assert_eq!((l2 & 0xe00, l1 & 0xe00), (2 << 9, 1 << 9));
    let leaf = |i: u64| fake.word((l1 & ADDR) + i * 8);
    assert_eq!(leaf(2), 0x1234_5000 | IR | IW | PRESENT);
    assert_eq!(leaf(3), 0x1234_6000 | IR | PRESENT);
    // Desmapear zera a folha e invalida as páginas do domínio.
    let flushes = |f: &Fake| f.0.lock().unwrap().done.iter().filter(|d| d.1 == 3).count();
    amd.unmap(id, 0x40_2000, 1);
    assert_eq!(leaf(2), 0);
    assert_eq!(flushes(&fake), 1);
    // Destruir bloqueia de novo e devolve as três tabelas.
    assert_eq!(amd.destroy(id), 3);
    assert_eq!(entry(&fake, 0x0018), blocked_entry(&fake));
    assert_eq!(fake.live(), before);
}

#[test]
fn detach_so_do_proprio_dominio() {
    let (fake, amd) = one_unit();
    let a = amd.create(&mut no_quota()).unwrap();
    let b = amd.create(&mut no_quota()).unwrap();
    amd.attach(a, 0x0100).unwrap();
    amd.detach(b, 0x0100);
    assert_eq!(entry(&fake, 0x0100).1, u64::from(a));
    amd.detach(a, 0x0100);
    assert_eq!(entry(&fake, 0x0100), blocked_entry(&fake));
}

#[test]
fn faltas_do_log_de_eventos() {
    let (fake, amd) = one_unit();
    {
        let mut seen = fake.0.lock().unwrap();
        let log = seen.regs[0][&EVT_LOG] & ADDR;
        let t = seen.tables.get_mut(&log).unwrap();
        // Falta de página de escrita do 00:03.0 e um evento de outro tipo.
        t[0] = 0x0018 | (2u64 << 28 | 1 << 21) << 32;
        t[1] = 0x40_2abc;
        t[2] = 1 << 60;
        seen.regs[0].insert(EVT_TAIL, 32);
    }
    let mut got = Vec::new();
    amd.faults(&mut |f| got.push(f));
    let fault = Fault {
        bdf: 0x0018,
        iova: 0x40_2000,
        reason: 2,
        write: true,
    };
    assert_eq!(got, [fault]);
    assert_eq!(fake.reg(0, EVT_HEAD), 32);
}

#[test]
fn recusas() {
    assert!(AmdVi::new(Box::new(Fake::new(0)), ivrs_all(0)).is_none());
    let (fake, amd) = one_unit();
    let live = fake.live();
    let mut deny = || Err(Error::QuotaExceeded);
    assert_eq!(amd.create(&mut deny), Err(Error::QuotaExceeded));
    assert_eq!(fake.live(), live);
    // Duas unidades: cada dispositivo na de `ALL` (a primeira).
    let fake = Fake::new(2);
    let amd = AmdVi::new(Box::new(fake.clone()), ivrs_all(2)).unwrap();
    let id = amd.create(&mut no_quota()).unwrap();
    amd.attach(id, 0x0018).unwrap();
    assert!(fake.0.lock().unwrap().done.iter().all(|d| d.0 == 0));
}
