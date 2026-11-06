//! Anel do log do kernel para o `logd` (T-357; ADR 0036, item 6).
//!
//! Um `MemoryObject` de 17 páginas: a página 0 é o cabeçalho do
//! `ostd::ring` (`magic`, `version`, `kind`, `data_len` e `tail` no byte
//! 64) e as 16 seguintes são 64 KiB de dados. Cada linha do `klog` vira um
//! registro de log da ADR 0036 (item 2), com `tid = 0xFFFF`, no formato de
//! registro do `ostd::ring` (`len` da carga útil, `kind` 1, `flags`, carga útil,
//! arredondado a 8 bytes, sem atravessar o fim do vetor).
//!
//! A política é **sobrescrever o mais antigo**: o kernel não lê `head` e
//! nunca espera. O `logd` só lê, guarda a posição dele e detecta a
//! sobrescrita relendo o `tail` (`ologd::kernel::Cursor`).
//!
//! [`push`] roda sob a trava do `klog` (a última folha, ADR 0031) e não
//! toma outra trava nem aloca: escreve pelo mapa direto nos quadros
//! registrados por [`install`], que também troca o anel sob a mesma trava.
//!
//! # Unsafe
//!
//! As escritas pelo mapa direto nos quadros do objeto do anel, que o
//! kernel mantém vivo enquanto estão registrados.

#![allow(
    clippy::cast_possible_truncation,
    reason = "tamanhos limitados a 64 KiB e x86-64"
)]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use kabi::vm::PAGE_SIZE;
use okernel::log::Level;
use okernel::vm::MemoryObject;

use crate::kmem;

mod tests;
pub use tests::TESTS;

/// Páginas de dados.
pub const DATA_PAGES: usize = 16;
/// Bytes de dados (`data_len`).
pub const DATA_LEN: u64 = DATA_PAGES as u64 * PAGE_SIZE;
/// Bytes do objeto: cabeçalho e dados.
pub const OBJECT_BYTES: u64 = PAGE_SIZE + DATA_LEN;
/// `tid` das linhas do kernel.
pub const KERNEL_TID: u16 = 0xFFFF;
/// Maior mensagem (ADR 0036, item 2).
pub const MAX_MSG: usize = 512;

const MAGIC: u32 = u32::from_le_bytes(*b"ORNG");
const VERSION: u16 = 1;
const KIND_LOG: u16 = 1;
const KIND_PAD: u16 = 0;
const OFF_TAIL: u64 = 64;
const RECORD_HEAD: u64 = 8;
const LOG_HEAD: u64 = 16;

/// Endereços no mapa direto das 17 páginas (0 = sem anel).
static PAGES: [AtomicU64; DATA_PAGES + 1] = [const { AtomicU64::new(0) }; DATA_PAGES + 1];
/// Próxima posição absoluta de escrita (espelho do `tail`).
static TAIL: AtomicU64 = AtomicU64::new(0);

/// O objeto do anel instalado (`Arc::into_raw`), só para mantê-lo vivo.
static KEEP: AtomicPtr<MemoryObject> = AtomicPtr::new(core::ptr::null_mut());

fn keep(object: Option<Arc<MemoryObject>>) -> Option<Arc<MemoryObject>> {
    let new = object.map_or(core::ptr::null_mut(), |o| Arc::into_raw(o).cast_mut());
    let old = KEEP.swap(new, Ordering::AcqRel);
    // SAFETY: todo ponteiro não nulo em `KEEP` veio de `Arc::into_raw` e
    // sai dele uma vez só, por este `swap`.
    (!old.is_null()).then(|| unsafe { Arc::from_raw(old) })
}

/// Escreve `bytes` na posição `off` do objeto (atravessando páginas).
fn write_at(mut off: u64, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        let page = usize::try_from(off / PAGE_SIZE).unwrap_or(usize::MAX);
        let Some(base) = PAGES.get(page).map(|p| p.load(Ordering::Relaxed)) else {
            return;
        };
        if base == 0 {
            return;
        }
        let in_page = off % PAGE_SIZE;
        let n = bytes
            .len()
            .min(usize::try_from(PAGE_SIZE - in_page).unwrap_or(0));
        // SAFETY: `base` é o mapa direto de um quadro do objeto em `KEEP`,
        // vivo enquanto registrado; `in_page + n` não passa da página; só
        // o kernel escreve (o `logd` tem `READ`), sob a trava do `klog`.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), (base + in_page) as *mut u8, n);
        }
        off += n as u64;
        bytes = &bytes[n..];
    }
}

/// Publica o `tail` no cabeçalho com `Release`.
fn publish_tail(tail: u64) {
    let base = PAGES[0].load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    // SAFETY: o byte 64 da página 0 está alinhado a 8 e pertence ao objeto
    // vivo em `KEEP`; o leitor o lê como atômico.
    let field = unsafe { &*((base + OFF_TAIL) as *const AtomicU64) };
    field.store(tail, Ordering::Release);
}

/// Registra o anel `object` (de [`OBJECT_BYTES`], com quadros) como
/// destino do log do kernel e escreve o cabeçalho. Devolve o anel
/// anterior, se havia.
///
/// # Errors
///
/// Objeto de tamanho errado ou sem quadros.
pub fn install(object: Arc<MemoryObject>) -> Result<Option<Arc<MemoryObject>>, &'static str> {
    if object.pages() != DATA_PAGES as u64 + 1 {
        return Err("tamanho do anel");
    }
    let mut addrs = [0u64; DATA_PAGES + 1];
    for (i, a) in addrs.iter_mut().enumerate() {
        *a = kmem::direct(object.frame(i as u64).ok_or("quadro do anel")?);
    }
    crate::klog::locked(|| {
        for (slot, a) in PAGES.iter().zip(addrs) {
            slot.store(a, Ordering::Relaxed);
        }
        TAIL.store(0, Ordering::Relaxed);
        let mut head = [0u8; 16];
        head[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        head[4..6].copy_from_slice(&VERSION.to_le_bytes());
        head[6..8].copy_from_slice(&KIND_LOG.to_le_bytes());
        head[8..12].copy_from_slice(&(DATA_LEN as u32).to_le_bytes());
        write_at(0, &head);
        publish_tail(0);
    });
    Ok(keep(Some(object)))
}

/// Tira o anel (para testes). Com a trava do `klog`.
pub fn uninstall() -> Option<Arc<MemoryObject>> {
    crate::klog::locked(|| {
        for p in &PAGES {
            p.store(0, Ordering::Relaxed);
        }
    });
    keep(None)
}

/// Posição absoluta do `tail` (para testes).
pub fn tail() -> u64 {
    TAIL.load(Ordering::Relaxed)
}

/// Acrescenta uma linha. Só sob a trava do `klog`.
pub fn push(ts_ns: u64, level: Level, msg: &[u8]) {
    if PAGES[0].load(Ordering::Relaxed) == 0 {
        return;
    }
    let msg = &msg[..msg.len().min(MAX_MSG)];
    let payload = LOG_HEAD + msg.len() as u64;
    let len = RECORD_HEAD + payload;
    let size = len.next_multiple_of(8);
    let mut tail = TAIL.load(Ordering::Relaxed);
    let room = DATA_LEN - tail % DATA_LEN;
    if room < size {
        // Enchimento até o fim do vetor: o registro não atravessa.
        let mut pad = [0u8; 8];
        pad[0..4].copy_from_slice(&((room - RECORD_HEAD) as u32).to_le_bytes());
        pad[4..6].copy_from_slice(&KIND_PAD.to_le_bytes());
        write_at(PAGE_SIZE + tail % DATA_LEN, &pad);
        tail += room;
    }
    let at = PAGE_SIZE + tail % DATA_LEN;
    let mut head = [0u8; (RECORD_HEAD + LOG_HEAD) as usize];
    head[0..4].copy_from_slice(&(payload as u32).to_le_bytes());
    head[4..6].copy_from_slice(&KIND_LOG.to_le_bytes());
    head[8..16].copy_from_slice(&ts_ns.to_le_bytes());
    head[16] = level as u8;
    head[18..20].copy_from_slice(&KERNEL_TID.to_le_bytes());
    head[20..22].copy_from_slice(&(msg.len() as u16).to_le_bytes());
    write_at(at, &head);
    write_at(at + head.len() as u64, msg);
    tail += size;
    TAIL.store(tail, Ordering::Relaxed);
    publish_tail(tail);
}
