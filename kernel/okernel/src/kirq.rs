//! Linhas de IRQ como objetos `Interrupt` (T-209; SDD v1.0, seção 6.8).
//!
//! O kernel cria um `Interrupt` por vetor ([`create`]) e guarda uma
//! referência fraca dele na tabela de vetores; a capability vai para quem
//! recebe as capabilities iniciais. Um disparo do vetor ([`fire`], chamado
//! pela IDT) sinaliza o bit de notificação ligado por `obj_bind_notify` e
//! acorda quem espera; a linha fica mascarada até `irq_ack`.

use alloc::sync::{Arc, Weak};

use kabi::Error;
use okernel::cap::MemoryQuota;
use okernel::notify::Interrupt;
use okernel::sync::{LockClass, SpinLock};

use crate::arch::x86_64::apic::{KERNEL_VECTORS, SPURIOUS_VECTOR, TIMER_VECTOR};
use crate::kthread;

/// Primeiro vetor entregue a objetos `Interrupt` (abaixo ficam exceções,
/// o timer e reservas do kernel).
pub const FIRST_VECTOR: u8 = 0x30;

static LINES: SpinLock<[Option<Weak<Interrupt>>; 256]> =
    SpinLock::with_class(LockClass::Object, [const { None }; 256]);

/// O `Interrupt` de cada IRQ ISA (ADR 0049, item 5): uma só tem um vivo.
static ISA: SpinLock<[Option<Weak<Interrupt>>; 16]> =
    SpinLock::with_class(LockClass::Object, [const { None }; 16]);

/// Cria o `Interrupt` do vetor `vector`, cobrado de `quota`.
///
/// # Errors
///
/// [`Error::InvalidArgument`] para vetores do kernel (exceções, timer,
/// espúrio e `0xF0..=0xFE`, dos IPIs); [`Error::Busy`] se
/// o vetor já tem objeto vivo; [`Error::QuotaExceeded`] sem cota.
pub fn create(quota: &Arc<MemoryQuota>, vector: u8) -> Result<Arc<Interrupt>, Error> {
    if vector < FIRST_VECTOR
        || vector == TIMER_VECTOR
        || vector == SPURIOUS_VECTOR
        || KERNEL_VECTORS.contains(&vector)
    {
        return Err(Error::InvalidArgument);
    }
    let mut lines = LINES.lock();
    let slot = &mut lines[usize::from(vector)];
    if slot.as_ref().is_some_and(|w| w.strong_count() > 0) {
        return Err(Error::Busy);
    }
    let irq = Arc::new(Interrupt::new(quota, vector)?);
    *slot = Some(Arc::downgrade(&irq));
    Ok(irq)
}

/// Último vetor entregue a MSI e MSI-X (acima ficam os IPIs do kernel).
const LAST_VECTOR: u8 = 0xef;

/// `Interrupt` de MSI ou MSI-X (T-404): o primeiro vetor livre, entregue
/// ao BSP em modo fixo, por borda. Devolve o objeto e o endereço e o dado
/// que o dispositivo escreve: com remapeamento de interrupções, a entrada
/// da IRT do vetor, presa a `source` (ADR 0044, item 6).
///
/// # Errors
///
/// [`Error::Busy`] sem vetor livre; [`Error::QuotaExceeded`] sem cota.
pub fn create_msi(
    quota: &Arc<MemoryQuota>,
    source: Option<u16>,
) -> Result<(Arc<Interrupt>, u64, u64), Error> {
    let (irq, dest) = allocate(quota)?;
    let vector = irq.vector();
    let msi = crate::kiommu::remap_msi(vector, dest, source).map_or(
        (0xfee0_0000 | u64::from(dest) << 12, u64::from(vector)),
        |address| (address, 0),
    );
    Ok((irq, msi.0, msi.1))
}

/// Um `Interrupt` no primeiro vetor livre, e o APIC de destino (o BSP).
fn allocate(quota: &Arc<MemoryQuota>) -> Result<(Arc<Interrupt>, u8), Error> {
    let dest = crate::ksmp::apic_id(0).unwrap_or(0);
    // O endereço de compatibilidade só leva 8 bits de destino (e a IRT do
    // VT-d em modo xAPIC e a entrada do IOAPIC também).
    let dest = u8::try_from(dest).map_err(|_| Error::NotSupported)?;
    for vector in FIRST_VECTOR..=LAST_VECTOR {
        if vector == TIMER_VECTOR {
            continue;
        }
        match create(quota, vector) {
            Ok(irq) => {
                // Uma IRQ legada de um objeto morto não fica no vetor.
                let _ = crate::kioapic::release_vector(vector);
                return Ok((irq, dest));
            }
            Err(Error::Busy) => {}
            Err(e) => return Err(e),
        }
    }
    Err(Error::Busy)
}

/// `Interrupt` da IRQ ISA `irq` (ADR 0049, item 5): um vetor livre, com a
/// entrada do IOAPIC da linha apontada para ele, no BSP.
///
/// # Errors
///
/// [`Error::Busy`] se a IRQ já tem objeto vivo ou sem vetor livre;
/// [`Error::QuotaExceeded`] sem cota; os de [`crate::kioapic::route`].
pub fn create_isa(quota: &Arc<MemoryQuota>, irq: u8) -> Result<Arc<Interrupt>, Error> {
    let (object, dest) = allocate(quota)?;
    {
        let mut isa = ISA.lock();
        let slot = isa
            .get_mut(usize::from(irq))
            .ok_or(Error::InvalidArgument)?;
        if slot.as_ref().is_some_and(|w| w.strong_count() > 0) {
            return Err(Error::Busy);
        }
        *slot = Some(Arc::downgrade(&object));
    }
    crate::kioapic::route(irq, object.vector(), dest)?;
    Ok(object)
}

/// Disparo de `vector` vindo da IDT: devolve se o vetor é de um objeto
/// `Interrupt` vivo (quem chama faz o EOI e o ponto de preempção).
pub fn fire(vector: u64) -> bool {
    let irq = {
        let lines = LINES.lock();
        usize::try_from(vector)
            .ok()
            .and_then(|v| lines.get(v)?.as_ref()?.upgrade())
    };
    let Some(irq) = irq else {
        // Sem dono: se for uma IRQ legada cujo `Interrupt` morreu (um
        // disparo que já estava a caminho), ela é mascarada e o disparo
        // acaba aqui, sem contar como vetor inesperado.
        return u8::try_from(vector).is_ok_and(crate::kioapic::release_vector);
    };
    if let Some((ntfy, bits)) = irq.fire()
        && let Some((thread, word)) = ntfy.signal(bits)
    {
        kthread::wake(thread, word);
    }
    true
}
