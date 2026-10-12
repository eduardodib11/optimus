//! Testes no host de `MemoryObject` e `Perms`, e a plataforma falsa dos
//! testes de memória virtual.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use super::*;
use crate::mm::FRAME_SIZE;
use crate::mm::paging::{ENTRIES, Table, TableMemory};
use crate::platform::KernelStack;
use crate::thread::Thread;

/// PML4 do kernel na plataforma falsa.
pub(crate) const KERNEL_ROOT: PhysAddr = PhysAddr(0x7f00_0000);
/// Entrada da metade alta do PML4 do kernel falso.
pub(crate) const KERNEL_ENTRY: u64 = 0x7e00_0000 | 3;

/// Plataforma falsa: frames com endereços crescentes, contados.
pub(crate) struct Fake {
    pub(crate) next: AtomicU64,
    pub(crate) frames_live: AtomicI64,
    pub(crate) tables_live: AtomicI64,
    pub(crate) stacks_live: AtomicI64,
    /// Threads acordadas por objeto de IPC destruído.
    pub(crate) woken: AtomicU64,
    pub(crate) frame_limit: i64,
    /// Shootdowns pedidos: início, páginas e frames vivos na hora.
    pub(crate) flushes: Mutex<Vec<(u64, u64, i64)>>,
}

/// Tabelas falsas de um espaço, num mapa por endereço.
struct FakeTables {
    platform: &'static Fake,
    tables: HashMap<u64, Box<Table>>,
}

impl TableMemory for FakeTables {
    fn table(&mut self, phys: PhysAddr) -> &mut Table {
        self.tables.entry(phys.0).or_insert_with(|| {
            assert_eq!(phys, KERNEL_ROOT, "tabela desconhecida");
            let mut k = Box::new([0; ENTRIES]);
            k[ENTRIES / 2..].fill(KERNEL_ENTRY);
            k
        })
    }

    fn alloc_table(&mut self) -> Option<PhysAddr> {
        let phys = self.platform.alloc_frame()?;
        self.platform.tables_live.fetch_add(1, Ordering::Relaxed);
        self.tables.insert(phys.0, Box::new([0; ENTRIES]));
        Some(phys)
    }

    fn free_table(&mut self, phys: PhysAddr) {
        assert!(self.tables.remove(&phys.0).is_some());
        self.platform.tables_live.fetch_sub(1, Ordering::Relaxed);
        self.platform.free_frame(phys);
    }
}

impl Fake {
    fn new(frame_limit: i64) -> &'static Self {
        Box::leak(Box::new(Self {
            next: AtomicU64::new(0x10_0000),
            frames_live: AtomicI64::new(0),
            tables_live: AtomicI64::new(0),
            stacks_live: AtomicI64::new(0),
            woken: AtomicU64::new(0),
            frame_limit,
            flushes: Mutex::new(Vec::new()),
        }))
    }

    fn alloc_frame(&self) -> Option<PhysAddr> {
        if self.frames_live.fetch_add(1, Ordering::Relaxed) >= self.frame_limit {
            self.frames_live.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(PhysAddr(self.next.fetch_add(FRAME_SIZE, Ordering::Relaxed)))
    }

    fn free_frame(&self, _: PhysAddr) {
        self.frames_live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A plataforma: as tabelas precisam do `Fake` vazado (`'static`).
pub(crate) struct Leaked(&'static Fake);

impl Platform for Leaked {
    fn tables(&self) -> Box<dyn TableMemory + Send> {
        Box::new(FakeTables {
            platform: self.0,
            tables: HashMap::new(),
        })
    }
    fn kernel_root(&self) -> PhysAddr {
        KERNEL_ROOT
    }
    fn alloc_frame(&self) -> Option<PhysAddr> {
        self.0.alloc_frame()
    }
    fn free_frame(&self, frame: PhysAddr) {
        self.0.free_frame(frame);
    }
    fn flush(&self, _: PhysAddr, start: u64, pages: u64) {
        let live = self.0.frames_live.load(Ordering::Relaxed);
        self.0.flushes.lock().unwrap().push((start, pages, live));
    }
    fn alloc_kernel_stack(&self) -> Option<KernelStack> {
        let slot = self.0.stacks_live.fetch_add(1, Ordering::Relaxed);
        Some(KernelStack {
            top: 0xffff_e000_0000_4000,
            slot: u32::try_from(slot).ok()?,
        })
    }
    fn free_kernel_stack(&self, _: KernelStack) {
        self.0.stacks_live.fetch_sub(1, Ordering::Relaxed);
    }
    fn fpu_area_bytes(&self) -> usize {
        832
    }
    fn wake(&self, _: Arc<Thread>) {
        self.0.woken.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn platform(frame_limit: i64) -> (&'static Fake, &'static Leaked) {
    let fake = Fake::new(frame_limit);
    (fake, Box::leak(Box::new(Leaked(fake))))
}

/// Página.
pub(crate) const P: u64 = PAGE_SIZE;

#[test]
fn objeto_cobra_paginas_e_devolve_frames() {
    let (fake, p) = platform(10);
    let quota = MemoryQuota::root(1 << 20);
    let mo = MemoryObject::new(&quota, 3 * P, p).unwrap();
    assert_eq!(mo.pages(), 3);
    assert_eq!(quota.used(), mo.charged());
    assert!(mo.charged() >= 3 * P + 24);
    assert_eq!(fake.frames_live.load(Ordering::Relaxed), 3);
    drop(mo);
    assert_eq!(
        (quota.used(), fake.frames_live.load(Ordering::Relaxed)),
        (0, 0)
    );
    for bad in [0, 100, P + 1] {
        assert_eq!(
            MemoryObject::new(&quota, bad, p).unwrap_err(),
            Error::InvalidArgument
        );
    }
    // Sem frames: nada fica cobrado nem alocado.
    assert_eq!(
        MemoryObject::new(&quota, 11 * P, p).unwrap_err(),
        Error::QuotaExceeded
    );
    assert_eq!(
        (quota.used(), fake.frames_live.load(Ordering::Relaxed)),
        (0, 0)
    );
    let small = MemoryQuota::root(2 * P);
    assert_eq!(
        MemoryObject::new(&small, 2 * P, p).unwrap_err(),
        Error::QuotaExceeded
    );
}

#[test]
fn flags_recusam_w_e_x_juntos() {
    assert_eq!(Perms::from_flags(WRITE | EXEC), Err(Error::InvalidArgument));
    assert_eq!(Perms::from_flags(1 << 5), Err(Error::InvalidArgument));
    assert_eq!(
        Perms::from_flags(EXEC),
        Ok(Perms {
            write: false,
            exec: true
        })
    );
}
