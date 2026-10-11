//! Instruções x86-64 que o `optboot` usa: entropia por hardware e TSC.

use core::arch::asm;
use core::arch::x86_64::{__cpuid, __cpuid_count};

/// Tentativas antes de desistir do RDRAND/RDSEED (a Intel recomenda 10).
const RETRIES: u32 = 10;

/// A CPU tem RDSEED (CPUID.07H:EBX\[18\]).
fn has_rdseed() -> bool {
    __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0
}

/// A CPU tem RDRAND (CPUID.01H:ECX\[30\]).
fn has_rdrand() -> bool {
    __cpuid(1).ecx & (1 << 30) != 0
}

/// Uma palavra de RDSEED, se a instrução existir e entregar.
fn rdseed() -> Option<u64> {
    for _ in 0..RETRIES {
        let (value, ok): (u64, u8);
        // SAFETY: só chamada depois de `has_rdseed`; RDSEED escreve um
        // registrador e o CF, sem acessar memória.
        unsafe {
            asm!("rdseed {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok,
                 options(nomem, nostack));
        }
        if ok == 1 {
            return Some(value);
        }
    }
    None
}

/// Uma palavra de RDRAND, se a instrução existir e entregar.
fn rdrand() -> Option<u64> {
    for _ in 0..RETRIES {
        let (value, ok): (u64, u8);
        // SAFETY: só chamada depois de `has_rdrand`; RDRAND escreve um
        // registrador e o CF, sem acessar memória.
        unsafe {
            asm!("rdrand {v}", "setc {ok}", v = out(reg) value, ok = out(reg_byte) ok,
                 options(nomem, nostack));
        }
        if ok == 1 {
            return Some(value);
        }
    }
    None
}

/// Fonte de entropia por hardware usada.
#[derive(Clone, Copy, Debug)]
pub enum HwRng {
    /// RDSEED: saída direta do condicionador de entropia.
    Rdseed,
    /// RDRAND: saída do DRBG da CPU.
    Rdrand,
}

/// Preenche `buf` com RDSEED ou, na falta dele, RDRAND.
pub fn hw_random(buf: &mut [u8]) -> Option<HwRng> {
    let (source, next): (HwRng, fn() -> Option<u64>) = if has_rdseed() && rdseed().is_some() {
        (HwRng::Rdseed, rdseed)
    } else if has_rdrand() {
        (HwRng::Rdrand, rdrand)
    } else {
        return None;
    };
    for chunk in buf.chunks_mut(8) {
        let word = next()?.to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    Some(source)
}

/// Contador de ciclos do processador.
pub fn rdtsc() -> u64 {
    // SAFETY: RDTSC só lê o contador de tempo, sem efeito colateral; o
    // optboot roda no anel 0, onde CR4.TSD não bloqueia a instrução.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Desliga interrupções mascaráveis.
pub fn disable_interrupts() {
    // SAFETY: CLI só limpa RFLAGS.IF; o optboot não depende de interrupções
    // depois de ExitBootServices.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// Liga EFER.NXE e CR0.WP, carrega `pml4` no CR3, troca a pilha para
/// `stack_top` e salta para `entry` com `arg` em `rdi` (System V). Não volta.
///
/// # Safety
///
/// `pml4` precisa mapear em identidade o código e a pilha atuais do optboot
/// (que continuam em uso até o salto), mapear `entry` como executável e
/// `stack_top` como gravável; interrupções precisam estar desligadas e os
/// serviços de boot encerrados.
pub unsafe fn enter_kernel(pml4: u64, stack_top: u64, entry: u64, arg: u64) -> ! {
    // SAFETY: contrato acima. NXE vem antes do CR3 porque as tabelas novas
    // usam o bit NX, que sem NXE é reservado e causaria falta de página.
    // O `push 0` deixa a pilha como depois de um `call` (rsp ≡ 8 mod 16) e
    // termina o encadeamento de quadros para depuradores.
    unsafe {
        asm!(
            "mov ecx, 0xc0000080",
            "rdmsr",
            "or eax, 1 << 11",
            "wrmsr",
            "mov rax, cr0",
            "or rax, 1 << 16",
            "mov cr0, rax",
            "mov cr3, r8",
            "mov rsp, r9",
            "xor ebp, ebp",
            "push 0",
            "jmp r10",
            in("r8") pml4,
            in("r9") stack_top,
            in("r10") entry,
            in("rdi") arg,
            options(noreturn),
        )
    }
}
