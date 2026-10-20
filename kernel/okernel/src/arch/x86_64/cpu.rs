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

/// Id do APIC local desta CPU pela CPUID (folha 0xB, com o id de 32 bits
/// do x2APIC, ou o id inicial de 8 bits da folha 1), sem tocar no APIC.
pub fn apic_id() -> u32 {
    if max_leaf(false) >= 0xb {
        let r = cpuid(0xb, 0);
        if r.ebx != 0 {
            return r.edx;
        }
    }
    cpuid(1, 0).ebx >> 24
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

/// MSR `IA32_FS_BASE`: a base do segmento FS, o TLS do usuário (ADR 0039,
/// item 3). O kernel não usa FS.
pub const MSR_FS_BASE: u32 = 0xc000_0100;

/// Põe `va` (o TLS da thread que vai rodar) em `IA32_FS_BASE`, só se a CPU
/// tiver outro valor (ADR 0039, item 3).
///
/// Compara com o valor que está na CPU, lido com RDMSR, e não com o da
/// thread que saiu: o usuário muda o `FS_BASE` sem o kernel saber ao
/// carregar um seletor em FS (`mov fs, ax` zera a base em CPUs Intel e
/// copia a do descritor, também zero, em todas), e esse valor vazaria para
/// a próxima thread se a troca confiasse no campo da anterior.
///
/// Um `va` fora da metade de usuário (o `thread_configure` já os recusa)
/// vira zero, porque o `WRMSR` com endereço não canônico daria #GP aqui.
pub fn load_user_fs_base(va: u64) {
    let va = if va < kabi::vm::USER_END { va } else { 0 };
    // SAFETY: `IA32_FS_BASE` existe em toda CPU x86-64; o valor é
    // canônico (metade baixa) e o kernel não usa FS, então só o usuário o
    // vê.
    unsafe {
        if rdmsr(MSR_FS_BASE) != va {
            wrmsr(MSR_FS_BASE, va);
        }
    }
}

/// Lê o contador de tempo (TSC).
pub fn rdtsc() -> u64 {
    // SAFETY: RDTSC só lê o contador; o kernel não liga CR4.TSD.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Lê o TSC depois de todas as leituras de memória anteriores (`lfence;
/// rdtsc`): uma leitura que vem depois de ver o valor publicado por outra
/// CPU não executa antes dele (ADR 0030, item 5).
pub fn rdtsc_ordered() -> u64 {
    // SAFETY: LFENCE só ordena; RDTSC só lê o contador (CR4.TSD desligado).
    unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    }
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
    crate::ksync::assert_none_held("ocioso");
    // Pedido que chegou por sondagem antes de dormir (ADR 0031, item 5); o
    // que chegar depois acorda o `hlt` pelo IPI.
    crate::ksmp::ipi::poll();
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

/// CR4.PGE: páginas globais (sobrevivem à troca de CR3).
const CR4_PGE: u64 = 1 << 7;

/// Descarta a TLB inteira, globais incluídas (desligar e religar CR4.PGE
/// esvazia tudo; sem PGE, basta recarregar o CR3).
pub fn flush_tlb_all() {
    let cr4 = read_cr4();
    if cr4 & CR4_PGE == 0 {
        flush_tlb();
        return;
    }
    // SAFETY: só PGE muda, e volta ao valor de antes; nada mais do modo da
    // CPU é tocado.
    unsafe {
        write_cr4(cr4 & !CR4_PGE);
        write_cr4(cr4);
    }
}

/// Liga CR4.PGE, se a CPU tem páginas globais (CPUID.1:EDX.PGE), e
/// descarta a TLB inteira; devolve se ficou ligado. Os APs herdam o bit do
/// CR4 do BSP.
pub fn enable_global_pages() -> bool {
    if cpuid(1, 0).edx & (1 << 13) == 0 {
        flush_tlb_all();
        return false;
    }
    let cr4 = read_cr4();
    // SAFETY: só PGE muda; desligá-lo e ligá-lo descarta a TLB inteira,
    // globais incluídas, e a CPU anuncia o recurso.
    unsafe {
        write_cr4(cr4 & !CR4_PGE);
        write_cr4(cr4 | CR4_PGE);
    }
    true
}
