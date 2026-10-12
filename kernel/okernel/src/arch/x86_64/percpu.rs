//! Área por CPU apontada por `GS_BASE` no kernel (ADR 0030, item 2; T-317).
//!
//! Cada CPU tem a sua [`PerCpu`]: os três primeiros campos têm os
//! deslocamentos que o assembly usa (`gs:[0]`, `gs:[8]`, `gs:[16]`), os ids
//! lógico e de APIC vêm em `gs:[24]`, e depois o estado que antes era
//! global: GDT e TSS, rsp salvo do ocioso, timer armado e disparos dele,
//! pilha de travas e o registro das sondas de memória. Continuam globais só
//! a configuração comum a todas as CPUs (modo do APIC, calibragem do TSC,
//! XSAVE), o dono do pânico e o escalonador (T-323). Cada CPU tem também a
//! caixa de pedidos de IPI (T-322), a thread atual, o quadro gravado
//! quando um pânico a congela e os caches de frames e de objetos do heap
//! (T-328). O BSP usa a
//! instância estática (as exceções podem chegar antes do alocador); os APs
//! recebem a sua na partida (T-318).
//!
//! Regra de uso: nada lido da `PerCpu` pode atravessar uma troca de
//! contexto, porque a thread pode voltar em outra CPU (ADR 0032). O acesso
//! é por [`with`], de vida curta; em debug, `schedule` confere que nenhum
//! empréstimo está aberto ([`assert_no_borrows`]).

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use okernel::ipi::Mailbox;
use okernel::mm::cache::{FrameCache, ObjectCache, object_cache};
use okernel::sync::HeldLocks;

use super::cpu::{rdmsr, wrmsr};
use super::gdt::{self, Gdt, IST_STACK_SIZE, Tss};

const MSR_GS_BASE: u32 = 0xc000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// Estado de uma CPU, alinhado a 4 KiB.
#[repr(C, align(4096))]
pub struct PerCpu {
    /// Endereço da própria `PerCpu` (`gs:[0]`).
    this: AtomicU64,
    /// Topo da pilha de kernel da thread atual (`gs:[8]`).
    kernel_rsp: AtomicU64,
    /// Rascunho do rsp do usuário na entrada (`gs:[16]`).
    user_rsp: AtomicU64,
    /// Id lógico (`gs:[24]`).
    cpu_id: AtomicU32,
    /// Id de APIC (`gs:[28]`).
    apic_id: AtomicU32,
    /// rsp salvo do ocioso desta CPU.
    idle_rsp: AtomicU64,
    /// Instante pedido ao timer desta CPU e ainda não disparado (zero:
    /// nenhum).
    timer_armed: AtomicU64,
    /// Disparos do timer desta CPU e o TSC do último.
    timer_stats: [AtomicU64; 2],
    /// Empréstimos abertos por [`with`] (debug).
    borrows: AtomicU32,
    /// A CPU terminou a inicialização.
    online: AtomicBool,
    /// Uma sonda de execução está armada (`probe::exec`).
    probe_exec_armed: AtomicBool,
    /// Vetor, erro e endereço da última falta de sonda.
    probe_last: [AtomicU64; 3],
    /// Travas na mão (ADR 0031, item 4).
    held: HeldLocks,
    /// Pedidos de outras CPUs (ADR 0031, item 5).
    mailbox: Mailbox,
    /// Endereço da `Thread` que roda (zero: o ocioso), para o dump do
    /// pânico.
    thread: AtomicU64,
    /// Quadro gravado pelo NMI do pânico: rip, rsp, rflags, cr3, cs e
    /// thread (ADR 0031, item 8).
    panic_dump: [AtomicU64; 6],
    gdt: UnsafeCell<Gdt>,
    tss: UnsafeCell<Tss>,
    /// Cache de frames de 4 KiB (T-328): só esta CPU o toca, por
    /// [`with_frame_cache`].
    frames: UnsafeCell<FrameCache>,
    /// Frames no cache, para as contas de outras CPUs.
    frames_cached: AtomicU32,
    /// O cache está emprestado (pega reentrada).
    frames_busy: AtomicBool,
    /// Cache de objetos do heap (T-328), por [`with_object_cache`].
    objects: UnsafeCell<ObjectCache>,
    /// Objetos no cache, somadas as classes.
    objects_cached: AtomicU32,
    /// O cache de objetos está emprestado.
    objects_busy: AtomicBool,
}

// Os deslocamentos que `syscall.S` usa.
const _: () = assert!(offset_of!(PerCpu, this) == 0);
const _: () = assert!(offset_of!(PerCpu, kernel_rsp) == 8);
const _: () = assert!(offset_of!(PerCpu, user_rsp) == 16);
const _: () = assert!(offset_of!(PerCpu, cpu_id) == 24);
const _: () = assert!(offset_of!(PerCpu, apic_id) == 28);

// SAFETY: os campos compartilháveis são atômicos; GDT e TSS (as células)
// só são tocadas pela própria CPU, com interrupções desligadas (`load` e
// `set_kernel_stack`), e a CPU as lê pelo hardware; os caches de frames e
// de objetos, só pela própria CPU em `with_frame_cache` e
// `with_object_cache`.
unsafe impl Sync for PerCpu {}

impl PerCpu {
    /// Frames no cache desta área (lido de qualquer CPU; pode estar
    /// mudando).
    pub fn frames_cached(&self) -> usize {
        self.frames_cached.load(Ordering::Relaxed) as usize
    }

    /// Objetos do heap no cache desta área (lido de qualquer CPU; pode
    /// estar mudando).
    pub fn objects_cached(&self) -> usize {
        self.objects_cached.load(Ordering::Relaxed) as usize
    }

    /// Área vazia da CPU de id lógico `cpu_id`.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            this: AtomicU64::new(0),
            kernel_rsp: AtomicU64::new(0),
            user_rsp: AtomicU64::new(0),
            cpu_id: AtomicU32::new(cpu_id),
            apic_id: AtomicU32::new(0),
            idle_rsp: AtomicU64::new(0),
            timer_armed: AtomicU64::new(0),
            timer_stats: [const { AtomicU64::new(0) }; 2],
            borrows: AtomicU32::new(0),
            online: AtomicBool::new(false),
            probe_exec_armed: AtomicBool::new(false),
            probe_last: [const { AtomicU64::new(0) }; 3],
            held: HeldLocks::new(),
            mailbox: Mailbox::new(),
            thread: AtomicU64::new(0),
            panic_dump: [const { AtomicU64::new(0) }; 6],
            gdt: UnsafeCell::new(gdt::GDT_TEMPLATE),
            tss: UnsafeCell::new(Tss::new()),
            frames: UnsafeCell::new(FrameCache::new()),
            frames_cached: AtomicU32::new(0),
            frames_busy: AtomicBool::new(false),
            objects: UnsafeCell::new(object_cache()),
            objects_cached: AtomicU32::new(0),
            objects_busy: AtomicBool::new(false),
        }
    }

    /// Id lógico.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id.load(Ordering::Relaxed)
    }

    /// Id de APIC.
    pub fn apic_id(&self) -> u32 {
        self.apic_id.load(Ordering::Relaxed)
    }

    /// Grava o id de APIC (o do BSP só é lido depois de ligar o APIC).
    pub fn set_apic_id(&self, id: u32) {
        self.apic_id.store(id, Ordering::Relaxed);
    }

    /// A CPU terminou a inicialização.
    pub fn online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    /// Marca a CPU como ligada.
    pub fn set_online(&self) {
        self.online.store(true, Ordering::Release);
    }

    /// Onde a troca de contexto guarda o rsp do ocioso desta CPU.
    pub fn idle_rsp(&self) -> &AtomicU64 {
        &self.idle_rsp
    }

    /// Instante armado no timer desta CPU (zero: nenhum).
    pub fn timer_armed(&self) -> &AtomicU64 {
        &self.timer_armed
    }

    /// Disparos do timer desta CPU e o TSC do último.
    pub fn timer_stats(&self) -> &[AtomicU64; 2] {
        &self.timer_stats
    }

    /// Sonda de execução armada nesta CPU.
    pub fn probe_exec_armed(&self) -> &AtomicBool {
        &self.probe_exec_armed
    }

    /// Registro da última falta de sonda nesta CPU.
    pub fn probe_last(&self) -> &[AtomicU64; 3] {
        &self.probe_last
    }

    /// Caixa de pedidos de IPI desta CPU.
    pub fn mailbox(&self) -> &Mailbox {
        &self.mailbox
    }

    /// Endereço da `Thread` que roda nesta CPU (zero: o ocioso).
    pub fn thread(&self) -> &AtomicU64 {
        &self.thread
    }

    /// Quadro gravado quando o pânico congelou esta CPU.
    pub fn panic_dump(&self) -> &[AtomicU64; 6] {
        &self.panic_dump
    }

    /// Endereço da GDT desta CPU.
    pub fn gdt_addr(&self) -> u64 {
        self.gdt.get().addr() as u64
    }

    /// Endereço da TSS desta CPU.
    pub fn tss_addr(&self) -> u64 {
        self.tss.get().addr() as u64
    }

    /// Instala esta área na CPU que roda: GDT, TSS com as pilhas IST
    /// (`ist_tops`, cada uma alinhada a [`IST_STACK_SIZE`] e com o endereço
    /// desta área já gravado no topo) e `GS_BASE`.
    ///
    /// # Safety
    ///
    /// Uma vez, na CPU dona, com interrupções desligadas; a área vive para
    /// sempre e não está instalada em outra CPU.
    pub unsafe fn install(&'static self, apic_id: u32, ist_tops: [u64; 3]) {
        let me = core::ptr::from_ref(self).addr() as u64;
        self.this.store(me, Ordering::Relaxed);
        self.apic_id.store(apic_id, Ordering::Relaxed);
        // SAFETY: contrato acima; GDT e TSS são desta CPU e ninguém mais as
        // toca; `GS_BASE` vem depois de `gdt::load`, que zera GS.
        unsafe {
            gdt::load(self.gdt.get(), self.tss.get(), ist_tops);
            wrmsr(MSR_GS_BASE, me);
            wrmsr(MSR_KERNEL_GS_BASE, 0);
        }
    }

    /// Pilha de kernel para entradas vindas do anel 3 (`gs:[8]` e RSP0).
    ///
    /// # Safety
    ///
    /// Na CPU dona, com interrupções desligadas; `top` é o topo da pilha de
    /// kernel mapeada da thread que vai rodar.
    pub unsafe fn set_kernel_stack(&self, top: u64) {
        self.kernel_rsp.store(top, Ordering::Relaxed);
        // SAFETY: contrato acima.
        unsafe { gdt::set_kernel_stack(self.tss.get(), top) };
    }
}

/// Área do BSP (CPU 0).
static BSP: PerCpu = PerCpu::new(0);

/// Pilhas IST do BSP, alinhadas ao próprio tamanho para que o topo ache a
/// dona (ADR 0030, item 2).
#[repr(C, align(16384))]
struct IstStack([u8; IST_STACK_SIZE]);

const _: () = assert!(IST_STACK_SIZE == 16384);

static mut BSP_IST: [IstStack; 3] = [const { IstStack([0; IST_STACK_SIZE]) }; 3];

/// Grava o endereço de `owner` no topo da pilha IST que termina em `top` e
/// devolve o rsp inicial dela (16 bytes abaixo, alinhado a 16).
///
/// # Safety
///
/// `top` é o fim exclusivo de uma pilha mapeada, gravável e só desta CPU.
pub unsafe fn prepare_ist(top: u64, owner: &'static PerCpu) -> u64 {
    // SAFETY: contrato acima.
    unsafe { ((top - 8) as *mut u64).write(core::ptr::from_ref(owner).addr() as u64) };
    top - 16
}

/// A `PerCpu` dona da pilha IST em que `rsp` está (NMI e `#MC` não confiam
/// em GS).
///
/// # Safety
///
/// `rsp` está numa pilha IST preparada por [`prepare_ist`].
pub unsafe fn from_ist_rsp(rsp: u64) -> &'static PerCpu {
    let top = (rsp | (IST_STACK_SIZE as u64 - 1)) + 1;
    // SAFETY: contrato acima: o topo guarda o endereço de uma `PerCpu`
    // estática ou que vive para sempre.
    unsafe { &*(((top - 8) as *const u64).read() as *const PerCpu) }
}

/// Área do BSP.
pub fn bsp() -> &'static PerCpu {
    &BSP
}

/// Instala a área do BSP.
///
/// # Safety
///
/// Uma vez, no boot do BSP, com interrupções desligadas.
pub unsafe fn init_bsp() {
    // SAFETY: contrato acima; as pilhas IST do BSP só são usadas por ele, e
    // nada mais as toca antes de a IDT existir.
    unsafe {
        let stacks = &raw mut BSP_IST;
        let tops = [0, 1, 2].map(|i| {
            let top = (&raw mut (*stacks)[i]).addr() as u64 + IST_STACK_SIZE as u64;
            prepare_ist(top, &BSP)
        });
        BSP.install(0, tops);
    }
    BSP.set_online();
}

/// A área desta CPU (por `gs:[0]`). Ver a regra de uso no topo do módulo.
fn this() -> &'static PerCpu {
    let me: u64;
    // SAFETY: depois de `init_bsp` (ou da partida do AP), `gs:[0]` é o
    // endereço da `PerCpu` desta CPU, que vive para sempre.
    unsafe {
        asm!("mov {}, gs:[0]", out(reg) me, options(nostack, readonly, preserves_flags));
        &*(me as *const PerCpu)
    }
}

/// Roda `f` com a área desta CPU. `f` não pode trocar de contexto.
pub fn with<R>(f: impl FnOnce(&PerCpu) -> R) -> R {
    let p = this();
    if cfg!(debug_assertions) {
        p.borrows.fetch_add(1, Ordering::Relaxed);
    }
    let r = f(p);
    if cfg!(debug_assertions) {
        p.borrows.fetch_sub(1, Ordering::Relaxed);
    }
    r
}

/// Roda `f` com o cache de frames desta CPU (T-328; ADR 0031, item 3: sem
/// trava). `f` não pode trocar de contexto nem alocar ou liberar frames
/// (o cache não é reentrante); pode tomar a trava do buddy.
///
/// # Panics
///
/// Se o cache desta CPU já está emprestado (reentrada).
pub fn with_frame_cache<R>(f: impl FnOnce(&mut FrameCache) -> R) -> R {
    let p = this();
    // SAFETY: a célula é desta CPU e só se chega a ela por aqui.
    unsafe {
        borrow(&p.frames, &p.frames_busy, |cache| {
            let r = f(cache);
            p.frames_cached.store(count(cache.len()), Ordering::Relaxed);
            r
        })
    }
}

/// Roda `f` com o cache de objetos do heap desta CPU (T-328). `f` não pode
/// trocar de contexto nem alocar ou liberar no heap; pode tomar a trava do
/// heap (e, por ela, alocar frames).
///
/// # Panics
///
/// Se o cache desta CPU já está emprestado (reentrada).
pub fn with_object_cache<R>(f: impl FnOnce(&mut ObjectCache) -> R) -> R {
    let p = this();
    // SAFETY: a célula é desta CPU e só se chega a ela por aqui.
    unsafe {
        borrow(&p.objects, &p.objects_busy, |cache| {
            let r = f(cache);
            let n = cache.iter().map(okernel::mm::cache::Magazine::len).sum();
            p.objects_cached.store(count(n), Ordering::Relaxed);
            r
        })
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Empresta `cell` a `f`, com `busy` pegando a reentrada.
///
/// # Safety
///
/// `cell` é um campo da `PerCpu` desta CPU que só se toca por esta função
/// com o mesmo `busy`.
unsafe fn borrow<T, R>(cell: &UnsafeCell<T>, busy: &AtomicBool, f: impl FnOnce(&mut T) -> R) -> R {
    // Só esta CPU toca `busy`, com IF=0: ler e gravar basta, sem a troca
    // atômica (que custa caro no caminho de toda alocação).
    assert!(!busy.load(Ordering::Relaxed), "cache por CPU reentrado");
    busy.store(true, Ordering::Relaxed);
    // SAFETY: contrato acima; só esta CPU chega à célula, e com IF=0 (todo
    // o kernel, ADR 0009) nenhuma interrupção roda no meio; `busy` acaba de
    // garantir que não há outro empréstimo aberto.
    let r = f(unsafe { &mut *cell.get() });
    busy.store(false, Ordering::Relaxed);
    r
}

/// A pilha de travas desta CPU, para os ganchos de `okernel::sync` (uma
/// trava nunca atravessa uma troca de contexto, então a CPU não muda
/// enquanto a pilha é usada).
pub fn held_locks() -> &'static HeldLocks {
    &this().held
}

/// A caixa de pedidos de IPI desta CPU (vive para sempre; só esta CPU a
/// atende).
pub fn mailbox() -> &'static Mailbox {
    &this().mailbox
}

/// Id lógico desta CPU, ou zero se o GS do kernel ainda não foi instalado
/// (pânico no começo do boot).
pub fn cpu_id_or_zero() -> u32 {
    // SAFETY: `IA32_GS_BASE` existe em toda CPU x86-64; ler não muda nada.
    if unsafe { rdmsr(MSR_GS_BASE) } == 0 {
        0
    } else {
        cpu_id()
    }
}

/// Id lógico desta CPU (`gs:[24]`). Vale para o instante da leitura: a
/// thread pode mudar de CPU na próxima troca de contexto.
pub fn cpu_id() -> u32 {
    let id: u32;
    // SAFETY: idem a `this`; ler `gs:[24]` só lê o id desta CPU.
    unsafe {
        asm!("mov {:e}, gs:[24]", out(reg) id, options(nostack, readonly, preserves_flags));
    }
    id
}

/// Em debug, acusa pânico se há empréstimo de [`with`] ou de um cache por
/// CPU aberto (antes de trocar de contexto).
pub fn assert_no_borrows() {
    if cfg!(debug_assertions) {
        let p = this();
        let n = p.borrows.load(Ordering::Relaxed);
        assert!(
            n == 0,
            "{n} empréstimo(s) da PerCpu abertos na troca de contexto"
        );
        assert!(
            !p.frames_busy.load(Ordering::Relaxed) && !p.objects_busy.load(Ordering::Relaxed),
            "cache por CPU emprestado na troca de contexto"
        );
    }
}
