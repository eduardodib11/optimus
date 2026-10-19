//! Testes no host das tabelas de página.

use super::*;

/// Memória falsa: a tabela `i` mora no endereço físico `(i + 1) * 4 KiB`.
struct Fake {
    tables: Vec<Box<Table>>,
    limit: usize,
    freed: Vec<PhysAddr>,
}

impl Fake {
    fn new(limit: usize) -> PageTables<Self> {
        let mut mem = Self {
            tables: Vec::new(),
            limit,
            freed: Vec::new(),
        };
        let root = mem.alloc_table().unwrap();
        PageTables::new(root, mem)
    }
}

impl TableMemory for Fake {
    fn table(&mut self, phys: PhysAddr) -> &mut Table {
        let i = usize::try_from(phys.0 / FRAME_SIZE).unwrap() - 1;
        &mut self.tables[i]
    }

    fn alloc_table(&mut self) -> Option<PhysAddr> {
        if self.tables.len() >= self.limit {
            return None;
        }
        self.tables.push(Box::new([0; ENTRIES]));
        Some(PhysAddr(self.tables.len() as u64 * FRAME_SIZE))
    }

    fn free_table(&mut self, phys: PhysAddr) {
        self.freed.push(phys);
    }
}

const K: u64 = 0xffff_c000_0000_0000;
const MIB2: u64 = 2 << 20;

#[test]
fn mapeia_traduz_protege_e_desmapeia_4k() {
    let mut pt = Fake::new(16);
    pt.map(K + 0x5000, PhysAddr(0x12_3000), PageSize::Size4K, Flags::RW)
        .unwrap();
    // PML4 + PDPT + PD + PT.
    assert_eq!(pt.memory().tables.len(), 4);
    let m = pt.translate(K + 0x5abc).unwrap();
    assert_eq!(m.phys, PhysAddr(0x12_3abc));
    assert_eq!((m.size, m.flags), (PageSize::Size4K, Flags::RW));
    assert_eq!(pt.translate(K + 0x6000), None);

    pt.protect(K + 0x5000, PageSize::Size4K, Flags::READ)
        .unwrap();
    assert_eq!(pt.translate(K + 0x5000).unwrap().flags, Flags::READ);
    assert_eq!(
        pt.unmap(K + 0x5000, PageSize::Size4K),
        Ok(PhysAddr(0x12_3000))
    );
    assert_eq!(pt.translate(K + 0x5000), None);
    assert_eq!(
        pt.unmap(K + 0x5000, PageSize::Size4K),
        Err(MapError::NotMapped)
    );
    assert_eq!(
        pt.protect(K + 0x5000, PageSize::Size4K, Flags::RW),
        Err(MapError::NotMapped)
    );
}

#[test]
fn bits_da_folha() {
    let mut pt = Fake::new(16);
    pt.map(K, PhysAddr(0x1000), PageSize::Size4K, Flags::READ)
        .unwrap();
    pt.map(K + 0x1000, PhysAddr(0x2000), PageSize::Size4K, Flags::RX)
        .unwrap();
    let pt_phys = PhysAddr(4 * FRAME_SIZE);
    let leaves = pt.memory().table(pt_phys);
    assert_eq!(leaves[0], 0x1000 | PRESENT | NO_EXECUTE);
    assert_eq!(leaves[1], 0x2000 | PRESENT);
    let uncached = Flags {
        uncached: true,
        global: true,
        ..Flags::RW
    };
    assert_eq!(
        uncached.bits(PageSize::Size2M),
        PRESENT | WRITABLE | NO_EXECUTE | GLOBAL | NO_CACHE | WRITE_THROUGH | HUGE
    );
    assert_eq!(Flags::from_bits(uncached.bits(PageSize::Size4K)), uncached);
}

#[test]
fn recusa_w_x_desalinhado_nao_canonico_e_ocupado() {
    let mut pt = Fake::new(16);
    let wx = Flags {
        exec: true,
        ..Flags::RW
    };
    assert_eq!(
        pt.map(K, PhysAddr(0), PageSize::Size4K, wx),
        Err(MapError::WriteExec)
    );
    assert_eq!(
        pt.map(K + 1, PhysAddr(0), PageSize::Size4K, Flags::RW),
        Err(MapError::Unaligned)
    );
    assert_eq!(
        pt.map(K, PhysAddr(0x1000), PageSize::Size2M, Flags::RW),
        Err(MapError::Unaligned)
    );
    assert_eq!(
        pt.map(
            0x0000_8000_0000_0000,
            PhysAddr(0),
            PageSize::Size4K,
            Flags::RW
        ),
        Err(MapError::NonCanonical)
    );
    pt.map(K, PhysAddr(0), PageSize::Size4K, Flags::RW).unwrap();
    assert_eq!(
        pt.map(K, PhysAddr(0x1000), PageSize::Size4K, Flags::READ),
        Err(MapError::AlreadyMapped)
    );
    // Já há uma tabela de 4 KiB nesses 2 MiB.
    assert_eq!(
        pt.map(K, PhysAddr(0), PageSize::Size2M, Flags::RW),
        Err(MapError::AlreadyMapped)
    );
    assert_eq!(pt.unmap(K, PageSize::Size2M), Err(MapError::SizeMismatch));
    pt.map(K, PhysAddr(0), PageSize::Size4K, Flags::RW)
        .unwrap_err();
    assert_eq!(
        pt.protect(K, PageSize::Size4K, wx),
        Err(MapError::WriteExec)
    );
    assert_eq!(pt.translate(0x0000_8000_0000_0000), None);
}

#[test]
fn pagina_de_2m_e_divisao() {
    let mut pt = Fake::new(16);
    pt.map(K, PhysAddr(4 * MIB2), PageSize::Size2M, Flags::RW)
        .unwrap();
    assert_eq!(pt.memory().tables.len(), 3);
    let m = pt.translate(K + 0x1_2345).unwrap();
    assert_eq!(m.phys, PhysAddr(4 * MIB2 + 0x1_2345));
    assert_eq!(m.size, PageSize::Size2M);
    assert_eq!(
        pt.map(K + 0x3000, PhysAddr(0), PageSize::Size4K, Flags::RW),
        Err(MapError::AlreadyMapped)
    );

    // Proteger 4 KiB divide a página grande; as vizinhas ficam como estavam.
    pt.protect(K + 0x3000, PageSize::Size4K, Flags::READ)
        .unwrap();
    assert_eq!(pt.memory().tables.len(), 4);
    let small = pt.translate(K + 0x3000).unwrap();
    assert_eq!(
        (small.phys, small.size, small.flags),
        (PhysAddr(4 * MIB2 + 0x3000), PageSize::Size4K, Flags::READ)
    );
    for virt in [K, K + 0x2000, K + 0x4000, K + MIB2 - 0x1000] {
        let m = pt.translate(virt).unwrap();
        assert_eq!(m.phys, PhysAddr(4 * MIB2 + (virt - K)));
        assert_eq!((m.size, m.flags), (PageSize::Size4K, Flags::RW));
    }
    assert_eq!(
        pt.protect(K, PageSize::Size2M, Flags::READ),
        Err(MapError::SizeMismatch)
    );
    // Desmapear 4 KiB numa página grande também divide.
    pt.map(K + MIB2, PhysAddr(0), PageSize::Size2M, Flags::READ)
        .unwrap();
    assert_eq!(
        pt.unmap(K + MIB2 + 0x1000, PageSize::Size4K),
        Ok(PhysAddr(0x1000))
    );
    assert_eq!(pt.translate(K + MIB2 + 0x1000), None);
    assert_eq!(pt.translate(K + MIB2).unwrap().phys, PhysAddr(0));
    assert_eq!(pt.unmap(K + MIB2, PageSize::Size4K), Ok(PhysAddr(0)));
}

#[test]
fn percorre_todas_as_folhas_em_ordem() {
    let mut pt = Fake::new(16);
    pt.map(0x40_0000, PhysAddr(0), PageSize::Size2M, Flags::READ)
        .unwrap();
    pt.map(K + 0x3000, PhysAddr(0x9000), PageSize::Size4K, Flags::RX)
        .unwrap();
    pt.map(K, PhysAddr(0x8000), PageSize::Size4K, Flags::RW)
        .unwrap();
    let mut seen = Vec::new();
    pt.for_each_leaf(&mut |virt, m| seen.push((virt, m.phys, m.size, m.flags)));
    assert_eq!(
        seen,
        [
            (0x40_0000, PhysAddr(0), PageSize::Size2M, Flags::READ),
            (K, PhysAddr(0x8000), PageSize::Size4K, Flags::RW),
            (K + 0x3000, PhysAddr(0x9000), PageSize::Size4K, Flags::RX),
        ]
    );
}

#[test]
fn falta_de_frame_vira_erro() {
    let mut pt = Fake::new(3);
    assert_eq!(
        pt.map(K, PhysAddr(0), PageSize::Size4K, Flags::RW),
        Err(MapError::OutOfFrames)
    );
    pt.map(K, PhysAddr(0), PageSize::Size2M, Flags::RW).unwrap();
    assert_eq!(
        pt.protect(K, PageSize::Size4K, Flags::READ),
        Err(MapError::OutOfFrames)
    );
    // A página grande continua inteira.
    assert_eq!(pt.translate(K + 0x5000).unwrap().size, PageSize::Size2M);
}

#[test]
fn conta_tabelas_e_devolve_a_metade_baixa() {
    let mut pt = Fake::new(64);
    let u = 0x40_0000u64;
    // PDPT + PD + PT para a primeira página; 2 MiB adiante, só mais um PT.
    assert_eq!(pt.tables_needed(u, u + 0x1000), 3);
    assert_eq!(pt.tables_needed(u, u + MIB2 + 0x1000), 4);
    let user = Flags {
        user: true,
        ..Flags::RW
    };
    pt.map(u, PhysAddr(0x9000), PageSize::Size4K, user).unwrap();
    assert_eq!(pt.memory().tables.len(), 4);
    assert_eq!(pt.tables_needed(u, u + 0x2000), 0);
    assert_eq!(pt.tables_needed(u, u + MIB2 + 0x1000), 1);
    // Uma página do kernel não entra na conta nem é devolvida.
    pt.map(K, PhysAddr(0xa000), PageSize::Size4K, Flags::RW)
        .unwrap();
    pt.free_user_half();
    assert_eq!(pt.memory().freed.len(), 3);
    assert_eq!(pt.translate(u), None);
    assert!(pt.translate(K).is_some());
}

#[test]
fn so_a_metade_do_kernel_vira_global() {
    let mut pt = Fake::new(16);
    let user = Flags {
        user: true,
        ..Flags::RW
    };
    pt.map(0x40_0000, PhysAddr(0x9000), PageSize::Size4K, user)
        .unwrap();
    pt.map(K, PhysAddr(0x8000), PageSize::Size4K, Flags::RX)
        .unwrap();
    pt.map(K + MIB2, PhysAddr(0), PageSize::Size2M, Flags::RW)
        .unwrap();
    assert_eq!(pt.globalize_kernel_half(), 2);
    let global = |f: Flags| Flags { global: true, ..f };
    assert_eq!(pt.translate(K).unwrap().flags, global(Flags::RX));
    assert_eq!(pt.translate(K + MIB2).unwrap().flags, global(Flags::RW));
    assert_eq!(pt.translate(0x40_0000).unwrap().flags, user);
    // A divisão da página grande mantém o bit nas folhas pequenas.
    pt.protect(K + MIB2, PageSize::Size4K, global(Flags::READ))
        .unwrap();
    let m = pt.translate(K + MIB2 + 0x1000).unwrap();
    assert_eq!((m.size, m.flags), (PageSize::Size4K, global(Flags::RW)));
    assert_eq!(pt.globalize_kernel_half(), 513);
}
