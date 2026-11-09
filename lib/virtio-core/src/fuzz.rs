//! Harness de fuzzing do transporte (T-421): o mesmo código roda no alvo
//! `fuzz/virtio` (libFuzzer) e num teste do host com bytes pseudoaleatórios.
//!
//! O dispositivo não é confiável (ADR 0046): qualquer sequência de bytes
//! escrita por ele na memória compartilhada, ou no espaço de configuração,
//! deve acabar em `Ok` ou em [`Error`](crate::Error), nunca em pânico.

extern crate std;

use core::cell::RefCell;
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use crate::{DmaBuf, Queue, Seg, cap};

/// Memória de DMA que o "dispositivo" (o fuzzer) também escreve.
#[derive(Clone)]
struct Mem(Rc<RefCell<Vec<u8>>>);

impl DmaBuf for Mem {
    fn len(&self) -> usize {
        self.0.borrow().len()
    }
    fn device_addr(&self) -> u64 {
        0x10_0000
    }
    fn read16(&self, o: usize) -> u16 {
        u16::from_le_bytes([self.0.borrow()[o], self.0.borrow()[o + 1]])
    }
    fn read32(&self, o: usize) -> u32 {
        let m = self.0.borrow();
        u32::from_le_bytes([m[o], m[o + 1], m[o + 2], m[o + 3]])
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

/// Percorre a lista de capabilities de `data` como espaço de configuração
/// (preenchido até 256 bytes, como o PCI entrega).
pub fn caps(data: &[u8]) {
    let mut cfg = [0u8; 256];
    let n = data.len().min(256);
    cfg[..n].copy_from_slice(&data[..n]);
    let _ = cap::find(&cfg);
    // Também a leitura curta, que o PCI nunca entregaria.
    let _ = cap::find(data);
}

/// Usa `data` como um roteiro: `push` de cadeias, `pop` e escritas do
/// dispositivo em qualquer lugar da memória compartilhada.
pub fn queue(data: &[u8]) {
    const N: usize = 8;
    let mem = Mem(Rc::new(RefCell::new(vec![0; Queue::<Mem, N>::dma_len()])));
    let Ok(mut q) = Queue::<Mem, N>::new(mem.clone()) else {
        return;
    };
    let mut i = 0;
    let next = |i: &mut usize| {
        let b = data.get(*i).copied().unwrap_or(0);
        *i += 1;
        b
    };
    while i < data.len() {
        match next(&mut i) % 3 {
            0 => {
                let n = usize::from(next(&mut i) % 10);
                let mut segs = Vec::new();
                for _ in 0..n {
                    let b = next(&mut i);
                    segs.push(Seg {
                        addr: u64::from(b) << 12,
                        len: u32::from(next(&mut i)) << 8,
                        write: b & 1 != 0,
                    });
                }
                let _ = q.push(&segs);
            }
            1 => {
                let _ = q.pop();
            }
            _ => {
                // O dispositivo escreve 4 bytes de lixo em qualquer lugar.
                let len = mem.len();
                let at = (usize::from(next(&mut i)) << 8 | usize::from(next(&mut i))) % len;
                let mut m = mem.0.borrow_mut();
                for k in 0..4 {
                    let b = next(&mut i);
                    if let Some(x) = m.get_mut(at + k) {
                        *x = b;
                    }
                }
            }
        }
    }
    // Esvazia o que sobrou: nenhuma entrada deixa a fila inutilizável.
    for _ in 0..64 {
        if !matches!(q.pop(), Ok(Some(_)) | Err(_)) {
            break;
        }
    }
}
