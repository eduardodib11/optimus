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

/// Leitura volátil de 32 bits em `off` de `m` (registradores de MMIO;
/// T-402). Quem chama confere `off` alinhado a 4 e dentro de `m`.
pub fn read32(m: &Mapping, off: usize) -> u32 {
    assert!(off.is_multiple_of(4) && off + 4 <= m.size());
    let ptr = core::ptr::with_exposed_provenance::<u32>(m.addr() + off);
    // SAFETY: como em `bytes`; o endereço é alinhado e cabe na faixa
    // (conferido acima). Volátil: cada leitura chega ao dispositivo.
    unsafe { ptr.read_volatile() }
}

/// Escrita volátil de 32 bits em `off` de `m`, gravável (como [`read32`]).
pub fn write32(m: &mut Mapping, off: usize, value: u32) {
    assert!(m.writable() && off.is_multiple_of(4) && off + 4 <= m.size());
    let ptr = core::ptr::with_exposed_provenance_mut::<u32>(m.addr() + off);
    // SAFETY: como em `bytes_mut`, com o alinhamento e a faixa conferidos
    // acima e o empréstimo exclusivo de `m`.
    unsafe { ptr.write_volatile(value) }
}

/// O buffer de IPC no início de `m`, uma página gravável alinhada.
pub fn ipc_buffer(m: &mut Mapping) -> &mut IpcBuffer {
    assert!(m.writable() && m.size() >= size_of::<IpcBuffer>() && m.addr().is_multiple_of(4096));
    let ptr = core::ptr::with_exposed_provenance_mut::<IpcBuffer>(m.addr());
    // SAFETY: como em `bytes_mut`; a página é alinhada como `IpcBuffer`
    // pede, cabe nele e qualquer conteúdo é válido (só inteiros).
    unsafe { &mut *ptr }
}
