//! Acesso à memória que o próprio processo mapeou, pelos tipos que guardam
//! o mapeamento ([`Mapping`]). O compilador não vê o mapeamento; as
//! condições ficam no tipo (ver [`Mapping`]).

use kabi::ipc::IpcBuffer;

use crate::vm::Mapping;

/// Os bytes de `m`.
pub fn bytes(m: &Mapping) -> &[u8] {
    let ptr = core::ptr::with_exposed_provenance::<u8>(m.addr());
    // SAFETY: `m` mapeou `[addr, addr + size)` (legível) no `new` e só
    // desmapeia no `Drop`, depois de todo empréstimo; o empréstimo
    // compartilhado de `m` impede um mutável ao mesmo tempo.
    unsafe { core::slice::from_raw_parts(ptr, m.size()) }
}

/// Os bytes de `m`, para escrita. Quem chama confere que `m` é gravável.
pub fn bytes_mut(m: &mut Mapping) -> &mut [u8] {
    debug_assert!(m.writable());
    let ptr = core::ptr::with_exposed_provenance_mut::<u8>(m.addr());
    // SAFETY: como em `bytes`, com a faixa gravável (quem chama confere) e
    // o empréstimo exclusivo de `m`.
    unsafe { core::slice::from_raw_parts_mut(ptr, m.size()) }
}

/// O buffer de IPC no início de `m`, uma página gravável alinhada.
pub fn ipc_buffer(m: &mut Mapping) -> &mut IpcBuffer {
    assert!(m.writable() && m.size() >= size_of::<IpcBuffer>() && m.addr().is_multiple_of(4096));
    let ptr = core::ptr::with_exposed_provenance_mut::<IpcBuffer>(m.addr());
    // SAFETY: como em `bytes_mut`; a página é alinhada como `IpcBuffer`
    // pede, cabe nele e qualquer conteúdo é válido (só inteiros).
    unsafe { &mut *ptr }
}
