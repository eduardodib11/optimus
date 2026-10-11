//! Instruções privilegiadas da CPU: CPUID, registradores de controle, MSRs e
//! TLB.

use core::arch::asm;

/// Resultado de CPUID: EAX, EBX e ECX.
pub struct CpuidResult {
    /// EAX.
    pub eax: u32,
    /// EBX.
    pub ebx: u32,
    /// ECX.
    pub ecx: u32,
}

/// Executa CPUID na folha `leaf`, subfolha `sub`.
pub fn cpuid(leaf: u32, sub: u32) -> CpuidResult {
    // CPUID existe em toda CPU x86-64 e só lê informação; folhas além do
    // máximo devolvem dados da última folha básica, sem falta.
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    CpuidResult {
        eax: r.eax,
        ebx: r.ebx,
        ecx: r.ecx,
    }
}

/// Maior folha básica (`basic`) ou estendida de CPUID que a CPU oferece.
pub fn max_leaf(extended: bool) -> u32 {
    cpuid(if extended { 0x8000_0000 } else { 0 }, 0).eax
}

macro_rules! read_control_register {
    ($read:ident, $reg:literal, $doc:literal) => {
        #[doc = concat!("Lê ", $doc, ".")]
        pub fn $read() -> u64 {
            let value;
            // SAFETY: ler um registrador de controle no anel 0 não tem efeito.
            unsafe { asm!(concat!("mov {}, ", $reg), out(reg) value, options(nomem, nostack)) };
            value
        }
    };
}

read_control_register!(read_cr0, "cr0", "CR0");
read_control_register!(read_cr3, "cr3", "CR3");
read_control_register!(read_cr4, "cr4", "CR4");

/// Grava o CR3 (troca de espaço de endereçamento e descarte da TLB).
///
/// # Safety
///
/// `value` precisa apontar um PML4 válido que mapeie o kernel em execução.
pub unsafe fn write_cr3(value: u64) {
    // SAFETY: contrato do chamador.
    unsafe { asm!("mov cr3, {}", in(reg) value, options(nostack)) };
}

/// Grava o CR4.
///
/// # Safety
///
/// Só pode ligar recursos que a CPU tem e que não quebrem o kernel.
pub unsafe fn write_cr4(value: u64) {
    // SAFETY: contrato do chamador.
    unsafe { asm!("mov cr4, {}", in(reg) value, options(nostack)) };
}

/// CR0.WP: o anel 0 respeita páginas só de leitura.
pub const CR0_WP: u64 = 1 << 16;
/// CR4.UMIP: SGDT, SIDT, SLDT, SMSW e STR proibidas no anel 3.
pub const CR4_UMIP: u64 = 1 << 11;
/// CR4.SMEP: o anel 0 não executa páginas de usuário.
pub const CR4_SMEP: u64 = 1 << 20;
/// CR4.SMAP: o anel 0 não acessa páginas de usuário (fora de STAC).
pub const CR4_SMAP: u64 = 1 << 21;

/// MSR `IA32_EFER`.
pub const MSR_EFER: u32 = 0xc000_0080;
/// EFER.NXE: bit NX das tabelas de página ativo.
pub const EFER_NXE: u64 = 1 << 11;

/// Lê o MSR `msr`.
///
/// # Safety
///
/// O MSR precisa existir nesta CPU (senão, #GP).
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: contrato do chamador; RDMSR só lê.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high, options(nomem, nostack));
    }
    (u64::from(high) << 32) | u64::from(low)
}

/// Invalida a entrada da TLB de `virt` nesta CPU.
pub fn invlpg(virt: u64) {
    // SAFETY: INVLPG só descarta uma tradução em cache; a próxima consulta
    // relê as tabelas.
    unsafe { asm!("invlpg [{}]", in(reg) virt, options(nostack)) };
}

/// Descarta as traduções não globais da TLB recarregando o CR3.
pub fn flush_tlb() {
    // SAFETY: regravar o mesmo CR3 mantém o espaço de endereçamento.
    unsafe { write_cr3(read_cr3()) };
}
