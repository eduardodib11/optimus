//! Instruções privilegiadas da CPU: CPUID, registradores de controle, MSRs,
//! TLB, TSC e interrupções.

use core::arch::asm;
use core::sync::atomic::AtomicBool;

/// SMAP ligado no CR4: o asm de entrada e de cópia de usuário só usa
/// STAC/CLAC com ele (sem SMAP essas instruções dão #UD).
#[unsafe(no_mangle)]
pub static SMAP_ENABLED: AtomicBool = AtomicBool::new(false);

/// Resultado de CPUID.
pub struct CpuidResult {
    /// EAX.
    pub eax: u32,
    /// EBX.
    pub ebx: u32,
    /// ECX.
    pub ecx: u32,
    /// EDX.
    pub edx: u32,
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
        edx: r.edx,
    }
}

/// Assinatura do hipervisor (CPUID `0x4000_0000`), se houver um.
pub fn hypervisor() -> Option<[u8; 12]> {
    if cpuid(1, 0).ecx & (1 << 31) == 0 {
        return None;
    }
    let r = cpuid(0x4000_0000, 0);
    let mut sig = [0; 12];
    for (chunk, word) in sig.chunks_mut(4).zip([r.ebx, r.ecx, r.edx]) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Some(sig)
}

/// Roda sob o TCG do QEMU (CPU emulada, sem KVM). Lá o TSC segue o relógio
/// do host, e uma preempção do processo do QEMU aparece em qualquer medida
/// de tempo: os testes de latência só exigem estatísticas robustas (p99,
/// mediana) e apenas registram o pior caso.
pub fn under_tcg() -> bool {
    hypervisor().is_some_and(|sig| &sig == b"TCGTCGTCGTCG")
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

/// Grava o CR0.
///
/// # Safety
///
/// O valor não pode desligar proteções nem a paginação de que o kernel
/// depende.
pub unsafe fn write_cr0(value: u64) {
    // SAFETY: contrato do chamador.
    unsafe { asm!("mov cr0, {}", in(reg) value, options(nostack)) };
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

/// Grava `value` no MSR `msr`.
///
/// # Safety
///
/// O MSR precisa existir e o valor não pode quebrar o kernel.
pub unsafe fn wrmsr(msr: u32, value: u64) {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "WRMSR divide o valor em EDX:EAX"
    )]
    let (low, high) = (value as u32, (value >> 32) as u32);
    // SAFETY: contrato do chamador.
    unsafe { asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high, options(nostack)) };
}

/// Lê o contador de tempo (TSC).
pub fn rdtsc() -> u64 {
    // SAFETY: RDTSC só lê o contador; o kernel não liga CR4.TSD.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Desliga as interrupções.
pub fn disable_interrupts() {
    // SAFETY: CLI só adia interrupções desta CPU.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// As interrupções desta CPU estão ligadas (RFLAGS.IF)?
pub fn interrupts_enabled() -> bool {
    let rflags: u64;
    // SAFETY: PUSHFQ/POP só leem RFLAGS para um registrador.
    unsafe { asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags)) };
    rflags & (1 << 9) != 0
}

/// Liga as interrupções e espera a próxima; volta com elas desligadas.
pub fn wait_for_interrupt() {
    // SAFETY: STI só vale depois da instrução seguinte, então nenhuma
    // interrupção escapa entre STI e HLT; os tratadores instalados voltam.
    unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
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
