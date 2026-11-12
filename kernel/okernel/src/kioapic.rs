//! IRQ legada pelo IOAPIC (ADR 0049, itens 5 a 7): a entrada de
//! redirecionamento da GSI de uma IRQ ISA aponta para o vetor de um
//! `Interrupt`, entregue ao BSP em modo fixo.
//!
//! Só linhas por borda: a máscara é a de software do `Interrupt`, como na
//! MSI. Com remapeamento de interrupções a entrada vai no formato
//! remapeável, com a entrada da IRT presa ao `source-id` do IOAPIC.

use core::ptr;

use kabi::Error;
use okernel::acpi::madt::{IoApic, IsaRoute, MAX_IOAPICS, Topology};
use okernel::sync::{LockClass, SpinLock};

use crate::kmem;

/// Registradores: índice e janela (MMIO) e, pelo índice, versão e a
/// primeira metade da entrada 0.
const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;
const REG_VERSION: u32 = 0x01;
const REG_TABLE: u32 = 0x10;
/// Entrada mascarada.
const MASKED: u32 = 1 << 16;
/// Polaridade baixa.
const ACTIVE_LOW: u32 = 1 << 13;
/// Metade alta no formato remapeável: bit 48 e o índice a partir do 49.
const REMAPPABLE: u32 = 1 << 16;

struct State {
    ioapics: [IoApic; MAX_IOAPICS],
    count: usize,
    isa: [IsaRoute; 16],
    /// Vetor para o qual cada IRQ ISA está roteada (0: mascarada).
    routed: [u8; 16],
}

static STATE: SpinLock<Option<State>> = SpinLock::with_class(LockClass::Object, None);

/// Guarda os IOAPICs e os overrides da MADT (no boot, pelo `ksmp`).
pub fn init(t: &Topology) {
    let mut ioapics = [IoApic::default(); MAX_IOAPICS];
    ioapics[..t.ioapics().len()].copy_from_slice(t.ioapics());
    *STATE.lock() = Some(State {
        ioapics,
        count: t.ioapics().len(),
        isa: *t.isa(),
        routed: [0; 16],
    });
}

/// Um IOAPIC mapeado.
struct Regs(u64);

impl Regs {
    fn map(apic: &IoApic) -> Result<Self, Error> {
        kmem::mmio(u64::from(apic.addr))
            .map(|v| Self(v + (u64::from(apic.addr) & 0xfff)))
            .map_err(|_| Error::NotSupported)
    }

    fn read(&self, reg: u32) -> u32 {
        // SAFETY: a página do IOAPIC (endereço da MADT) foi mapeada sem
        // cache por `kmem::mmio`; índice e janela são de 32 bits, alinhados,
        // e só se acessam com a trava de `STATE`.
        unsafe {
            ptr::write_volatile((self.0 + IOREGSEL) as *mut u32, reg);
            ptr::read_volatile((self.0 + IOWIN) as *const u32)
        }
    }

    fn write(&self, reg: u32, value: u32) {
        // SAFETY: como em `read`.
        unsafe {
            ptr::write_volatile((self.0 + IOREGSEL) as *mut u32, reg);
            ptr::write_volatile((self.0 + IOWIN) as *mut u32, value);
        }
    }

    /// Entradas de redirecionamento.
    fn entries(&self) -> u32 {
        ((self.read(REG_VERSION) >> 16) & 0xff) + 1
    }
}

impl State {
    /// O IOAPIC da GSI e a entrada dela.
    fn find(&self, gsi: u32) -> Result<(IoApic, Regs, u32), Error> {
        for apic in &self.ioapics[..self.count] {
            let Some(pin) = gsi.checked_sub(apic.gsi_base) else {
                continue;
            };
            let regs = Regs::map(apic)?;
            if pin < regs.entries() {
                return Ok((*apic, regs, pin));
            }
        }
        Err(Error::NotSupported)
    }

    fn mask(&mut self, irq: usize) {
        if let Ok((_, regs, pin)) = self.find(self.isa[irq].gsi) {
            regs.write(REG_TABLE + 2 * pin, MASKED);
        }
        self.routed[irq] = 0;
    }
}

/// Aponta a IRQ ISA `irq` para `vector`, no APIC `dest`.
///
/// # Errors
///
/// [`Error::NotSupported`] sem IOAPIC para a GSI, para linha por nível ou,
/// com remapeamento de interrupções, sem o `source-id` do IOAPIC na DMAR.
pub fn route(irq: u8, vector: u8, dest: u8) -> Result<(), Error> {
    let mut state = STATE.lock();
    let state = state.as_mut().ok_or(Error::NotSupported)?;
    let line = *state
        .isa
        .get(usize::from(irq))
        .ok_or(Error::InvalidArgument)?;
    if line.level {
        return Err(Error::NotSupported);
    }
    let (apic, regs, pin) = state.find(line.gsi)?;
    let polarity = if line.active_low { ACTIVE_LOW } else { 0 };
    let high = if crate::kiommu::remap_msi_on() {
        // O formato de compatibilidade está bloqueado: a entrada leva o
        // índice da IRT (o vetor), que só o IOAPIC pode usar.
        let source = crate::kiommu::ioapic_source(apic.id).ok_or(Error::NotSupported)?;
        crate::kiommu::remap_msi(vector, dest, Some(source)).ok_or(Error::NotSupported)?;
        REMAPPABLE | u32::from(vector) << 17
    } else {
        u32::from(dest) << 24
    };
    regs.write(REG_TABLE + 2 * pin, MASKED);
    regs.write(REG_TABLE + 2 * pin + 1, high);
    regs.write(REG_TABLE + 2 * pin, u32::from(vector) | polarity);
    state.routed[usize::from(irq)] = vector;
    Ok(())
}

/// Mascara a IRQ ISA que estiver roteada para `vector` (o `Interrupt` dela
/// morreu e o vetor vai ser reusado, ou disparou sem dono). Devolve se
/// havia uma.
pub fn release_vector(vector: u8) -> bool {
    let mut state = STATE.lock();
    let Some(state) = state.as_mut() else {
        return false;
    };
    let irq = state.routed.iter().position(|&v| v == vector && v != 0);
    if let Some(irq) = irq {
        state.mask(irq);
    }
    irq.is_some()
}
