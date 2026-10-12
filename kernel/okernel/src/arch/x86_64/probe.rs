//! Acessos à memória que sobrevivem a faltas (`probe.S`) e o gancho que os
//! retoma no tratador de exceções (T-107).

use core::sync::atomic::Ordering;

use super::idt::TrapFrame;
use super::percpu;

unsafe extern "C" {
    fn probe_write_byte(addr: *mut u8, value: u8) -> u64;
    fn probe_read_byte(addr: *const u8, out: *mut u8) -> u64;
    fn probe_exec(target: *const u8) -> u64;
    static probe_extable: [[u64; 2]; 3];
    fn copy_user(dst: *mut u8, src: *const u8, len: u64) -> u64;
    static probe_fault: u8;
}

/// Uma falta capturada por uma sonda.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// Vetor da exceção (14 = #PF, 13 = #GP).
    pub vector: u64,
    /// Código de erro empilhado pela CPU.
    pub error: u64,
    /// Endereço que faltou (CR2 no #PF).
    pub addr: u64,
}

/// #PF: a página estava presente (violação de proteção).
pub const PF_PRESENT: u64 = 1;
/// #PF: o acesso era escrita.
pub const PF_WRITE: u64 = 1 << 1;
/// #PF: busca de instrução.
pub const PF_FETCH: u64 = 1 << 4;

/// A última falta de sonda desta CPU (o registro mora na `PerCpu`).
fn last_fault() -> Fault {
    let [vector, error, addr] =
        percpu::with(|p| [0, 1, 2].map(|i| p.probe_last()[i].load(Ordering::Relaxed)));
    Fault {
        vector,
        error,
        addr,
    }
}

/// Grava `value` em `addr`, ou devolve a falta.
///
/// # Safety
///
/// Se `addr` estiver mapeado e gravável, a escrita acontece de verdade: quem
/// chama garante que ela não quebra nada (por exemplo, regravando o valor
/// que já está lá).
pub unsafe fn write_byte(addr: u64, value: u8) -> Result<(), Fault> {
    // SAFETY: contrato do chamador; uma falta volta pelo `probe_fault`.
    match unsafe { probe_write_byte(addr as *mut u8, value) } {
        0 => Ok(()),
        _ => Err(last_fault()),
    }
}

/// Lê o byte em `addr`, ou devolve a falta.
pub fn read_byte(addr: u64) -> Result<u8, Fault> {
    let mut out = 0;
    // SAFETY: ler não muda a memória (o kernel não mapeia MMIO com efeito de
    // leitura em endereços que os testes sondam), e uma falta volta pelo
    // `probe_fault`.
    match unsafe { probe_read_byte(addr as *const u8, &raw mut out) } {
        0 => Ok(out),
        _ => Err(last_fault()),
    }
}

/// Chama `addr`, que precisa conter `ret` (0xc3), ou devolve a falta de busca.
///
/// # Safety
///
/// Se `addr` for executável, o código lá roda: precisa ser só um `ret`.
pub unsafe fn exec(addr: u64) -> Result<(), Fault> {
    percpu::with(|p| p.probe_exec_armed().store(true, Ordering::SeqCst));
    // SAFETY: contrato do chamador; a falta volta pelo `probe_fault`.
    let result = unsafe { probe_exec(addr as *const u8) };
    percpu::with(|p| p.probe_exec_armed().store(false, Ordering::SeqCst));
    match result {
        0 => Ok(()),
        _ => Err(last_fault()),
    }
}

/// Faixa `[addr, addr + len)` toda na metade de usuário.
fn user_range(addr: u64, len: u64) -> bool {
    addr.checked_add(len)
        .is_some_and(|end| addr >= kabi::vm::USER_START && end <= kabi::vm::USER_END)
}

/// Copia `dst.len()` bytes da memória de usuário em `src` (do espaço
/// ativo); `false` se a faixa sair da metade de usuário ou faltar.
pub fn copy_from_user(dst: &mut [u8], src: u64) -> bool {
    if !user_range(src, dst.len() as u64) {
        return false;
    }
    // SAFETY: `dst` é memória do kernel gravável do tamanho pedido; `src`
    // está na metade de usuário (não alcança o kernel), e uma falta lá
    // volta pela tabela de exceções.
    unsafe { copy_user(dst.as_mut_ptr(), src as *const u8, dst.len() as u64) == 0 }
}

/// Copia `src` para a memória de usuário em `dst` (do espaço ativo);
/// `false` se a faixa sair da metade de usuário ou faltar.
pub fn copy_to_user(dst: u64, src: &[u8]) -> bool {
    if !user_range(dst, src.len() as u64) {
        return false;
    }
    // SAFETY: idem a `copy_from_user`: só escreve na metade de usuário.
    unsafe { copy_user(dst as *mut u8, src.as_ptr(), src.len() as u64) == 0 }
}

/// Gancho do tratador de exceções: se a falta veio de uma sonda, registra e
/// desvia o retorno para `probe_fault`. Devolve se tratou.
pub(super) fn fixup(frame: &mut TrapFrame, cr2: u64) -> bool {
    // SAFETY: tabela só de leitura, relocada pelo optboot.
    let table = unsafe { &probe_extable };
    let exec_fault = frame.vector == 14
        && frame.error & PF_FETCH != 0
        && frame.rip == cr2
        && percpu::with(|p| p.probe_exec_armed().swap(false, Ordering::SeqCst));
    let resume = if exec_fault {
        (&raw const probe_fault).addr() as u64
    } else if let Some(&[_, fix]) = table.iter().find(|&&[insn, _]| insn == frame.rip) {
        fix
    } else {
        return false;
    };
    let addr = if frame.vector == 14 { cr2 } else { 0 };
    percpu::with(|p| {
        for (slot, value) in p.probe_last().iter().zip([frame.vector, frame.error, addr]) {
            slot.store(value, Ordering::Relaxed);
        }
    });
    if exec_fault {
        // Descarta o retorno empilhado pelo `call` do `probe_exec`.
        frame.rsp += 8;
    }
    frame.rip = resume;
    true
}
