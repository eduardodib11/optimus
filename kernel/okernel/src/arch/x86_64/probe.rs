//! Acessos à memória que sobrevivem a faltas (`probe.S`) e o gancho que os
//! retoma no tratador de exceções (T-107).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::idt::TrapFrame;

unsafe extern "C" {
    fn probe_write_byte(addr: *mut u8, value: u8) -> u64;
    fn probe_read_byte(addr: *const u8, out: *mut u8) -> u64;
    fn probe_exec(target: *const u8) -> u64;
    static probe_extable: [[u64; 2]; 2];
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

static EXEC_ARMED: AtomicBool = AtomicBool::new(false);
static LAST: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

fn last_fault() -> Fault {
    let [vector, error, addr] = [0, 1, 2].map(|i| LAST[i].load(Ordering::Relaxed));
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
    EXEC_ARMED.store(true, Ordering::SeqCst);
    // SAFETY: contrato do chamador; a falta volta pelo `probe_fault`.
    let result = unsafe { probe_exec(addr as *const u8) };
    EXEC_ARMED.store(false, Ordering::SeqCst);
    match result {
        0 => Ok(()),
        _ => Err(last_fault()),
    }
}

/// Gancho do tratador de exceções: se a falta veio de uma sonda, registra e
/// desvia o retorno para `probe_fault`. Devolve se tratou.
pub(super) fn fixup(frame: &mut TrapFrame, cr2: u64) -> bool {
    // SAFETY: tabela só de leitura, relocada pelo optboot.
    let table = unsafe { &probe_extable };
    let exec_fault = frame.vector == 14
        && frame.error & PF_FETCH != 0
        && frame.rip == cr2
        && EXEC_ARMED.swap(false, Ordering::SeqCst);
    let resume = if exec_fault {
        (&raw const probe_fault).addr() as u64
    } else if let Some(&[_, fix]) = table.iter().find(|&&[insn, _]| insn == frame.rip) {
        fix
    } else {
        return false;
    };
    let addr = if frame.vector == 14 { cr2 } else { 0 };
    for (slot, value) in LAST.iter().zip([frame.vector, frame.error, addr]) {
        slot.store(value, Ordering::Relaxed);
    }
    if exec_fault {
        // Descarta o retorno empilhado pelo `call` do `probe_exec`.
        frame.rsp += 8;
    }
    frame.rip = resume;
    true
}
