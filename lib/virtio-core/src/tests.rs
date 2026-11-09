//! Testes com um dispositivo simulado.

use crate::{DmaBuf, Error, Mmio, Queue, Seg, Transport, cap, status};
use crate::{F_ACCESS_PLATFORM, F_VERSION_1};
use std::cell::RefCell;
use std::rc::Rc;

struct Dev {
    regs: [u8; 64],
    features: u64,
    reject: bool,
    stuck_reset: bool,
}

#[derive(Clone)]
struct Common(Rc<RefCell<Dev>>);

impl Common {
    fn with(features: u64) -> Self {
        let mut regs = [0; 64];
        regs[24] = 8; // queue_size máximo 8
        Self(Rc::new(RefCell::new(Dev {
            regs,
            features,
            reject: false,
            stuck_reset: false,
        })))
    }
}

impl Mmio for Common {
    fn read8(&self, off: usize) -> u8 {
        self.0.borrow().regs[off]
    }
    fn read16(&self, off: usize) -> u16 {
        let d = self.0.borrow();
        u16::from_le_bytes([d.regs[off], d.regs[off + 1]])
    }
    fn read32(&self, off: usize) -> u32 {
        let d = self.0.borrow();
        if off == 4 {
            let sel = u32::from_le_bytes(d.regs[0..4].try_into().unwrap());
            return (d.features >> (32 * sel)) as u32;
        }
        u32::from_le_bytes(d.regs[off..off + 4].try_into().unwrap())
    }
    fn write8(&self, off: usize, v: u8) {
        let mut d = self.0.borrow_mut();
        let mut v = v;
        if off == 20 {
            if d.stuck_reset && v == 0 {
                return;
            }
            if v & status::FEATURES_OK != 0 && d.reject {
                v &= !status::FEATURES_OK;
            }
        }
        d.regs[off] = v;
    }
    fn write16(&self, off: usize, v: u16) {
        self.0.borrow_mut().regs[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn write32(&self, off: usize, v: u32) {
        self.0.borrow_mut().regs[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}

#[derive(Clone)]
struct Mem(Rc<RefCell<Vec<u8>>>);

impl Mem {
    fn new(n: usize) -> Self {
        Self(Rc::new(RefCell::new(vec![0xAA; n])))
    }
}

impl DmaBuf for Mem {
    fn len(&self) -> usize {
        self.0.borrow().len()
    }
    fn device_addr(&self) -> u64 {
        0x10_0000
    }
    fn read16(&self, o: usize) -> u16 {
        u16::from_le_bytes(self.0.borrow()[o..o + 2].try_into().unwrap())
    }
    fn read32(&self, o: usize) -> u32 {
        u32::from_le_bytes(self.0.borrow()[o..o + 4].try_into().unwrap())
    }
    fn write16(&self, o: usize, v: u16) {
        self.0.borrow_mut()[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn write32(&self, o: usize, v: u32) {
        self.0.borrow_mut()[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn write64(&self, o: usize, v: u64) {
        self.0.borrow_mut()[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn barrier(&self) {}
}

/// O "dispositivo" completa a cadeia `head` com `len` bytes.
fn device_use(m: &Mem, q_used_off: usize, n: usize, id: u32, len: u32) {
    let idx = m.read16(q_used_off + 2);
    let slot = usize::from(idx) % n;
    m.write32(q_used_off + 4 + 8 * slot, id);
    m.write32(q_used_off + 8 + 8 * slot, len);
    m.write16(q_used_off + 2, idx.wrapping_add(1));
}

fn queue4() -> (Queue<Mem, 4>, Mem, usize) {
    let m = Mem::new(Queue::<Mem, 4>::dma_len());
    let q = Queue::<Mem, 4>::new(m.clone()).unwrap();
    let used = (q.addrs().2 - 0x10_0000) as usize;
    (q, m, used)
}

#[test]
fn negocia_version1_e_features() {
    let c = Common::with(F_VERSION_1 | F_ACCESS_PLATFORM | 0b101);
    let mut t = Transport::new(c.clone());
    let f = t.negotiate(0b001, F_ACCESS_PLATFORM).unwrap();
    assert_eq!(f, F_VERSION_1 | F_ACCESS_PLATFORM | 0b001);
    assert_eq!(t.features(), f);
    assert_eq!(
        t.status(),
        status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK
    );
    t.driver_ok();
    assert_ne!(t.status() & status::DRIVER_OK, 0);
}

#[test]
fn recusa_legacy_e_feature_obrigatoria_ausente() {
    let mut t = Transport::new(Common::with(0b1));
    assert_eq!(t.negotiate(0, 0), Err(Error::NoVersion1));
    assert_eq!(t.status(), status::FAILED);
    let mut t = Transport::new(Common::with(F_VERSION_1));
    assert_eq!(
        t.negotiate(0, F_ACCESS_PLATFORM),
        Err(Error::FeaturesRejected)
    );
}

#[test]
fn dispositivo_rejeita_features_ou_nao_reseta() {
    let c = Common::with(F_VERSION_1);
    c.0.borrow_mut().reject = true;
    assert_eq!(
        Transport::new(c).negotiate(0, 0),
        Err(Error::FeaturesRejected)
    );
    let c = Common::with(F_VERSION_1);
    c.0.borrow_mut().regs[20] = 7;
    c.0.borrow_mut().stuck_reset = true;
    assert_eq!(Transport::new(c).negotiate(0, 0), Err(Error::ResetTimeout));
}

#[test]
fn configura_fila() {
    let c = Common::with(F_VERSION_1);
    let t = Transport::new(c.clone());
    let m = Mem::new(Queue::<Mem, 4>::dma_len());
    let (q, _) = t.setup_queue::<_, 4>(0, m, 0).unwrap();
    assert_eq!(c.read16(24), 4);
    assert_eq!(c.read16(28), 1);
    assert_eq!(c.read32(32), 0x10_0000);
    assert_eq!(u64::from(c.read32(40)), q.addrs().1);
    // N maior que o máximo do dispositivo, ou fila inexistente.
    let m = Mem::new(Queue::<Mem, 16>::dma_len());
    assert_eq!(t.setup_queue::<_, 16>(0, m, 0).err(), Some(Error::BadQueue));
    c.0.borrow_mut().regs[24] = 0;
    let m = Mem::new(Queue::<Mem, 4>::dma_len());
    assert_eq!(t.setup_queue::<_, 4>(1, m, 0).err(), Some(Error::BadQueue));
}

#[test]
fn fila_exige_dma_e_tamanho_validos() {
    let m = Mem::new(Queue::<Mem, 4>::dma_len() - 1);
    assert_eq!(Queue::<Mem, 4>::new(m).err(), Some(Error::DmaTooSmall));
    let m = Mem::new(4096);
    assert_eq!(Queue::<Mem, 3>::new(m).err(), Some(Error::BadQueue));
}

#[test]
fn push_pop_gira_o_anel() {
    let (mut q, m, used) = queue4();
    let segs = [
        Seg {
            addr: 0x1000,
            len: 16,
            write: false,
        },
        Seg {
            addr: 0x2000,
            len: 512,
            write: true,
        },
    ];
    for round in 0..10u32 {
        let h = q.push(&segs).unwrap();
        assert_eq!(q.free(), 2);
        assert_eq!(q.pop().unwrap(), None);
        device_use(&m, used, 4, u32::from(h), 100 + round);
        let c = q.pop().unwrap().unwrap();
        assert_eq!((c.head, c.len), (h, 100 + round));
        assert_eq!(q.free(), 4);
    }
}

#[test]
fn fila_cheia_e_cadeia_invalida() {
    let (mut q, _, _) = queue4();
    let s = Seg {
        addr: 0,
        len: 1,
        write: false,
    };
    assert_eq!(q.push(&[]), Err(Error::BadChain));
    assert_eq!(q.push(&[s; 5]), Err(Error::BadChain));
    q.push(&[s; 3]).unwrap();
    assert_eq!(q.push(&[s; 2]), Err(Error::Full));
    q.push(&[s]).unwrap();
    assert_eq!(q.push(&[s]), Err(Error::Full));
}

#[test]
fn dispositivo_hostil_nao_quebra_a_fila() {
    let (mut q, m, used) = queue4();
    let s = Seg {
        addr: 0x1000,
        len: 64,
        write: true,
    };
    let h = q.push(&[s]).unwrap();
    // Id fora da fila, id que não está em voo.
    device_use(&m, used, 4, 99, 1);
    assert_eq!(q.pop(), Err(Error::DeviceMisbehaved));
    device_use(&m, used, 4, 3, 1);
    assert_eq!(q.pop(), Err(Error::DeviceMisbehaved));
    // len maior que o buffer é limitado; id repetido é recusado.
    device_use(&m, used, 4, u32::from(h), u32::MAX);
    assert_eq!(q.pop().unwrap().unwrap().len, 64);
    device_use(&m, used, 4, u32::from(h), 1);
    assert_eq!(q.pop(), Err(Error::DeviceMisbehaved));
    assert_eq!(q.free(), 4);
    q.push(&[s]).unwrap();
}

fn cfg_with(caps: &[(u8, u8, u32, u32, Option<u32>)]) -> [u8; 256] {
    let mut c = [0u8; 256];
    c[0x34] = 0x40;
    for (i, &(kind, bar, off, len, mult)) in caps.iter().enumerate() {
        let p = 0x40 + 0x20 * i;
        c[p] = 0x09;
        c[p + 1] = if i + 1 < caps.len() {
            (p + 0x20) as u8
        } else {
            0
        };
        c[p + 2] = if mult.is_some() { 20 } else { 16 };
        c[p + 3] = kind;
        c[p + 4] = bar;
        c[p + 8..p + 12].copy_from_slice(&off.to_le_bytes());
        c[p + 12..p + 16].copy_from_slice(&len.to_le_bytes());
        c[p + 16..p + 20].copy_from_slice(&mult.unwrap_or(0).to_le_bytes());
    }
    c
}

#[test]
fn acha_capabilities() {
    let c = cfg_with(&[
        (cap::COMMON, 4, 0, 56, None),
        (cap::NOTIFY, 4, 0x1000, 0x1000, Some(4)),
        (cap::ISR, 4, 0x2000, 4, None),
        (cap::DEVICE, 4, 0x3000, 64, None),
    ]);
    let k = cap::find(&c).unwrap();
    assert_eq!(k.common.bar, 4);
    assert_eq!((k.notify.offset, k.notify_multiplier), (0x1000, 4));
    assert_eq!(k.isr.offset, 0x2000);
    assert_eq!(k.device.unwrap().length, 64);
}

#[test]
fn capabilities_malformadas() {
    // Falta a ISR; BAR inválido; lista em laço.
    let c = cfg_with(&[
        (cap::COMMON, 4, 0, 56, None),
        (cap::NOTIFY, 4, 0, 4, Some(4)),
    ]);
    assert_eq!(cap::find(&c), Err(Error::BadCap));
    let c = cfg_with(&[(cap::COMMON, 7, 0, 56, None)]);
    assert_eq!(cap::find(&c), Err(Error::BadCap));
    let mut c = cfg_with(&[(cap::COMMON, 4, 0, 56, None)]);
    c[0x41] = 0x40;
    assert_eq!(cap::find(&c), Err(Error::BadCap));
    assert_eq!(cap::find(&c[..0x20]), Err(Error::BadCap));
}

/// Fuzz no host (T-421): bytes pseudoaleatórios não derrubam o transporte.
#[test]
fn fuzz_pseudoaleatorio_sem_panico() {
    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..20_000 {
        let n = (rnd() % 300) as usize;
        let data: std::vec::Vec<u8> = (0..n).map(|_| rnd() as u8).collect();
        crate::fuzz::caps(&data);
        crate::fuzz::queue(&data);
    }
}
