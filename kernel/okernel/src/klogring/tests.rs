//! Testes de kernel do anel do log (T-357).

use alloc::sync::Arc;

use kabi::vm::PAGE_SIZE;
use okernel::vm::MemoryObject;

use super::{DATA_LEN, KERNEL_TID, OBJECT_BYTES, install, tail, uninstall};
use crate::kcap::root_quota;
use crate::kmem;
use crate::ktest::{Outcome, Test};

/// Testes de kernel do anel do log.
pub const TESTS: &[Test] = &[Test {
    name: "klog.anel_do_kernel",
    run: anel,
}];

fn read(object: &MemoryObject, off: u64, out: &mut [u8]) -> Result<(), &'static str> {
    for (i, b) in out.iter_mut().enumerate() {
        let at = off + i as u64;
        let frame = object.frame(at / PAGE_SIZE).ok_or("quadro")?;
        // SAFETY: quadro vivo do objeto, lido pelo mapa direto.
        *b = unsafe { *((kmem::direct(frame) + at % PAGE_SIZE) as *const u8) };
    }
    Ok(())
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Uma linha do `klog` aparece no anel como registro de log da ADR 0036
/// com `tid` 0xFFFF; depois de mais de 64 KiB o anel dá a volta com
/// enchimento e o `tail` passa de `data_len`.
fn anel() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let platform = okernel::platform::get().ok_or("sem plataforma")?;
    let object = Arc::new(MemoryObject::new(&quota, OBJECT_BYTES, platform).map_err(|_| "objeto")?);
    let before = install(Arc::clone(&object))?;
    let result = check(&object);
    let _ = uninstall();
    if let Some(old) = before {
        install(old)?;
    }
    result
}

fn check(object: &MemoryObject) -> Outcome {
    let mut head = [0u8; 72];
    read(object, 0, &mut head)?;
    ensure!(&head[0..4] == b"ORNG");
    ensure!(u64::from(u32_at(&head, 8)) == DATA_LEN);
    info!("klogring: linha {}", 42);
    let t = tail();
    let mut rec = [0u8; 64];
    read(object, PAGE_SIZE, &mut rec)?;
    let msg = b"klogring: linha 42";
    ensure!(u32_at(&rec, 0) as usize == 16 + msg.len());
    // kind 1; nível info = 3 na ADR 0036.
    ensure!(rec[4] == 1 && rec[16] == 3);
    ensure!(u16::from_le_bytes([rec[18], rec[19]]) == KERNEL_TID);
    ensure!(&rec[24..24 + msg.len()] == msg);
    ensure!(t == (24 + msg.len() as u64).next_multiple_of(8));
    read(object, 64, &mut head[..8])?;
    ensure!(u64::from_le_bytes(head[..8].try_into().map_err(|_| "tail")?) == t);
    while tail() <= DATA_LEN + 4096 {
        info!(
            "klogring: enchendo o anel até dar a volta, posição {}",
            tail()
        );
    }
    ensure!(tail().is_multiple_of(8));
    Ok(())
}
