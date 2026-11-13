//! Testes no host de `DmaDomain` (T-403), com e sem IOMMU.

use std::sync::Mutex;

use super::*;
use crate::vm::tests::platform;

/// Entrada da IOMMU falsa: domínio, iova, físico e escrita.
type Entry = (u32, u64, PhysAddr, bool);

/// IOMMU falsa: guarda as entradas e conta as invalidações.
#[derive(Default)]
struct FakeIommu {
    entries: Mutex<Vec<Entry>>,
    attached: Mutex<Vec<(u32, u16)>>,
    flushes: Mutex<u64>,
}

impl Iommu for FakeIommu {
    fn create(&self, table: &mut dyn FnMut() -> Result<(), Error>) -> Result<u32, Error> {
        table()?;
        Ok(7)
    }

    fn destroy(&self, id: u32) -> u64 {
        self.attached.lock().unwrap().retain(|&(d, _)| d != id);
        self.entries.lock().unwrap().retain(|e| e.0 != id);
        1
    }

    fn map(
        &self,
        id: u32,
        iova: u64,
        phys: PhysAddr,
        write: bool,
        _: &mut dyn FnMut() -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.entries.lock().unwrap().push((id, iova, phys, write));
        Ok(())
    }

    fn unmap(&self, id: u32, iova: u64, pages: u64) {
        let end = iova + pages * PAGE_SIZE;
        self.entries
            .lock()
            .unwrap()
            .retain(|e| e.0 != id || e.1 < iova || e.1 >= end);
        *self.flushes.lock().unwrap() += 1;
    }

    fn attach(&self, id: u32, bdf: u16) -> Result<(), Error> {
        self.attached.lock().unwrap().push((id, bdf));
        Ok(())
    }

    fn detach(&self, id: u32, bdf: u16) {
        self.attached.lock().unwrap().retain(|&e| e != (id, bdf));
    }
}

fn object(quota: &Arc<MemoryQuota>, pages: u64) -> Arc<MemoryObject> {
    let (_, p) = platform(64);
    Arc::new(MemoryObject::new(quota, pages * PAGE_SIZE, p).unwrap())
}

#[test]
fn sem_iommu_devolve_o_fisico_contiguo() {
    let quota = MemoryQuota::root(1 << 20);
    let d = DmaDomain::with_unit(&quota, None).unwrap();
    let o = object(&quota, 4);
    let phys = d.map(&o, 0x1000, PAGE_SIZE, 2 * PAGE_SIZE, true).unwrap();
    assert_eq!(phys, o.frame(1).unwrap().0);
    assert_eq!(d.counts(), (1, 0));
    // Sobreposição, desalinhamento, faixa vazia, fora do objeto e da IOVA.
    let bad = [
        (0x2000, 0, PAGE_SIZE),
        (0x8000, 1, PAGE_SIZE),
        (0x8000, 0, 0),
        (0x8000, 0, 5 * PAGE_SIZE),
        (IOVA_END - PAGE_SIZE, 0, 2 * PAGE_SIZE),
    ];
    for (iova, offset, len) in bad {
        assert_eq!(
            d.map(&o, iova, offset, len, false),
            Err(Error::InvalidArgument)
        );
    }
    // `unmap` só do mapeamento exato.
    assert_eq!(d.unmap(0x1000, PAGE_SIZE), Err(Error::InvalidArgument));
    d.unmap(0x1000, 2 * PAGE_SIZE).unwrap();
    assert_eq!(d.counts(), (0, 0));
}

#[test]
fn objeto_lazy_e_mmio_recusados() {
    let quota = MemoryQuota::root(1 << 20);
    let d = DmaDomain::with_unit(&quota, None).unwrap();
    let (_, p) = platform(64);
    let lazy = Arc::new(MemoryObject::new_lazy(&quota, PAGE_SIZE, p).unwrap());
    assert_eq!(
        d.map(&lazy, 0, 0, PAGE_SIZE, false),
        Err(Error::NotSupported)
    );
    let device = MemoryQuota::device(&quota, 4096).unwrap();
    let mmio = MemoryObject::new_device(&device, 0xC000_0000, PAGE_SIZE, p).unwrap();
    let mmio = Arc::new(mmio);
    assert_eq!(
        d.map(&mmio, 0, 0, PAGE_SIZE, false),
        Err(Error::InvalidArgument)
    );
}

#[test]
fn com_iommu_mapeia_por_pagina_e_segura_o_objeto() {
    let unit: &'static FakeIommu = Box::leak(Box::default());
    let quota = MemoryQuota::root(1 << 20);
    let o = object(&quota, 2);
    let before = quota.used();
    let d = DmaDomain::with_unit(&quota, Some(unit)).unwrap();
    assert_eq!(d.map(&o, 0x10_0000, 0, 2 * PAGE_SIZE, false), Ok(0x10_0000));
    {
        let entries = unit.entries.lock().unwrap();
        let got: Vec<_> = entries.iter().map(|e| (e.1, e.2, e.3)).collect();
        let f = |i| o.frame(i).unwrap();
        assert_eq!(got, [(0x10_0000, f(0), false), (0x10_1000, f(1), false)]);
    }
    // O domínio segura o objeto: o `Arc` local não é o último.
    assert_eq!(Arc::strong_count(&o), 2);
    d.unmap(0x10_0000, 2 * PAGE_SIZE).unwrap();
    assert!(unit.entries.lock().unwrap().is_empty());
    assert_eq!(*unit.flushes.lock().unwrap(), 1);
    assert_eq!(Arc::strong_count(&o), 1);
    // Mapeamento vivo na morte do domínio: a tabela sai antes do objeto.
    d.map(&o, 0, 0, PAGE_SIZE, true).unwrap();
    drop(d);
    assert!(unit.entries.lock().unwrap().is_empty());
    assert_eq!(Arc::strong_count(&o), 1);
    assert_eq!(quota.used(), before);
}

#[test]
fn dispositivo_so_num_dominio() {
    let quota = MemoryQuota::root(1 << 20);
    let a = Arc::new(DmaDomain::with_unit(&quota, None).unwrap());
    let b = Arc::new(DmaDomain::with_unit(&quota, None).unwrap());
    // Números de `bdf` só deste teste: `ATTACHED` é global.
    a.attach(0xA108).unwrap();
    assert_eq!(b.attach(0xA108), Err(Error::Busy));
    assert_eq!(b.detach(0xA108), Err(Error::InvalidArgument));
    a.detach(0xA108).unwrap();
    b.attach(0xA108).unwrap();
    assert_eq!(b.counts(), (0, 1));
    // Domínio morto solta o dispositivo.
    drop(b);
    a.attach(0xA108).unwrap();
}

#[test]
fn cota_volta_inteira() {
    let quota = MemoryQuota::root(1 << 20);
    let o = object(&quota, 1);
    let before = quota.used();
    let d = Arc::new(DmaDomain::with_unit(&quota, None).unwrap());
    d.map(&o, 0, 0, PAGE_SIZE, false).unwrap();
    d.attach(0xA210).unwrap();
    assert!(quota.used() > before);
    drop(d);
    assert_eq!(quota.used(), before);
    // Sem cota, nada fica pela metade.
    let tight = MemoryQuota::root(object_bytes::<DmaDomain>());
    let d = DmaDomain::with_unit(&tight, None).unwrap();
    assert_eq!(d.map(&o, 0, 0, PAGE_SIZE, false), Err(Error::QuotaExceeded));
    assert_eq!(d.counts(), (0, 0));
}

#[test]
fn falta_sinaliza_a_ligacao_do_dominio_do_dispositivo() {
    let quota = MemoryQuota::root(1 << 20);
    let d = Arc::new(DmaDomain::with_unit(&quota, None).unwrap());
    let ntfy = Arc::new(Notification::new(&quota).unwrap());
    // `bdf` só deste teste: `ATTACHED` é global.
    d.attach(0xA320).unwrap();
    // Sem ligação, nada a sinalizar; de outro dispositivo, também não.
    assert!(fault_binding(0xA320).is_none());
    assert!(d.bind_fault(Some((Arc::clone(&ntfy), 0b100))).is_none());
    let (got, mask) = fault_binding(0xA320).unwrap();
    assert!(Arc::ptr_eq(&got, &ntfy));
    assert_eq!(mask, 0b100);
    assert!(fault_binding(0xA328).is_none());
    // Religar devolve a anterior; `None` desliga.
    assert!(d.bind_fault(Some((Arc::clone(&ntfy), 1))).is_some());
    assert!(d.bind_fault(None).is_some());
    assert!(fault_binding(0xA320).is_none());
    // Domínio morto: nenhum dispositivo atribuído.
    d.bind_fault(Some((ntfy, 1)));
    drop(d);
    assert!(fault_binding(0xA320).is_none());
}
