//! Aceites do T-403 e do T-404 no QEMU (`cargo xtask test iommu`:
//! `-device intel-iommu` ou `amd-iommu` e `-device edu`): o DMA do `edu`
//! passa pela IOMMU
//! só enquanto ele está ligado ao domínio (desligado, a escrita vira falta
//! e a RAM fica intacta), e a MSI dele chega a um `Interrupt` e acorda a
//! notificação ligada.

#![allow(
    clippy::cast_possible_truncation,
    reason = "campos de registradores PCI e do edu têm largura fixa"
)]

use alloc::sync::Arc;
use core::ptr;

use okernel::cap::MemoryQuota;
use okernel::dma::DmaDomain;
use okernel::notify::Notification;
use okernel::vm::MemoryObject;

use crate::arch::x86_64::{inl, outl};
use crate::kcap::root_quota;
use crate::kmem;
use crate::ktest::{Outcome, Test};
use crate::ktime;

/// Testes do VT-d.
pub const TESTS: &[Test] = &[
    Test {
        name: "dev.iommu_isola_o_edu",
        run: iommu_isola_o_edu,
    },
    Test {
        name: "dev.msi_do_edu_acorda_a_notificacao",
        run: msi_do_edu,
    },
];

/// Lê o registrador de configuração `off` de `bdf` pelas portas 0xCF8/0xCFC.
fn config(bdf: u16, off: u8) -> u32 {
    // SAFETY: 0xCF8/0xCFC são o mecanismo 1 de configuração do PCI, sem
    // efeito além de ler o registrador pedido.
    unsafe {
        outl(
            0xcf8,
            0x8000_0000 | u32::from(bdf) << 8 | u32::from(off & 0xfc),
        );
        inl(0xcfc)
    }
}

fn set_config(bdf: u16, off: u8, value: u32) {
    // SAFETY: como em `config`; quem chama escreve só o comando do `edu`.
    unsafe {
        outl(
            0xcf8,
            0x8000_0000 | u32::from(bdf) << 8 | u32::from(off & 0xfc),
        );
        outl(0xcfc, value);
    }
}

/// Os registradores do `edu` (BAR 0, já mapeado sem cache).
struct Edu(u64);

impl Edu {
    fn write(&self, off: u64, value: u64) {
        // SAFETY: `off` é um registrador de DMA do `edu` (0x80 a 0x98), na
        // primeira página do BAR 0, mapeada por `kmem::mmio`.
        unsafe { ptr::write_volatile((self.0 + off) as *mut u64, value) };
    }

    fn write32(&self, off: u64, value: u32) {
        // SAFETY: `off` é um registrador de 32 bits do `edu` (abaixo de
        // 0x80), na primeira página do BAR 0, mapeada por `kmem::mmio`.
        unsafe { ptr::write_volatile((self.0 + off) as *mut u32, value) };
    }

    fn read(&self, off: u64) -> u64 {
        // SAFETY: como em `write`.
        unsafe { ptr::read_volatile((self.0 + off) as *const u64) }
    }

    /// DMA de 64 bytes: `to_ram` copia do buffer do `edu` (0x40000) para
    /// `iova`; senão, de `iova` para o buffer. Espera até 2 s.
    fn dma(&self, iova: u64, to_ram: bool) -> bool {
        let (src, dst) = if to_ram {
            (0x40000, iova)
        } else {
            (iova, 0x40000)
        };
        self.write(0x80, src);
        self.write(0x88, dst);
        self.write(0x90, 64);
        self.write(0x98, 1 | if to_ram { 2 } else { 0 });
        let end = ktime::now_ns() + 2_000_000_000;
        while ktime::now_ns() < end {
            if self.read(0x98) & 1 == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

fn find_edu() -> Option<u16> {
    (0..32u16)
        .map(|d| d << 3)
        .find(|&bdf| config(bdf, 0) == 0x11e8_1234)
}

fn page(mo: &MemoryObject, i: u64) -> Option<*mut u8> {
    Some(kmem::direct(mo.frame(i)?) as *mut u8)
}

/// Alguma falta registrada é de `bdf` em `iova`, escrita ou leitura.
fn fault_of(bdf: u16, iova: u64, write: bool) -> bool {
    let mut seen = false;
    super::faults(&mut |f| seen |= f.bdf == bdf && f.iova == iova && f.write == write);
    seen
}

fn iommu_isola_o_edu() -> Outcome {
    let (Some(bdf), Some(_)) = (find_edu(), okernel::dma::iommu()) else {
        info!("ktest: sem edu ou sem IOMMU; o aceite roda em `cargo xtask test iommu`");
        return Ok(());
    };
    let bar = u64::from(config(bdf, 0x10) & !0xf);
    ensure!(bar != 0);
    // Memória e bus master ligados.
    set_config(bdf, 0x04, config(bdf, 0x04) | 0x6);
    let edu = Edu(kmem::mmio(bar).map_err(|_| "BAR do edu")?);
    let platform = okernel::platform::get().ok_or("sem plataforma")?;
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used = quota.used();
    let mo = Arc::new(MemoryObject::new(&quota, 2 * 4096, platform).map_err(|_| "objeto")?);
    let (src, dst) = (page(&mo, 0).ok_or("frame")?, page(&mo, 1).ok_or("frame")?);
    // SAFETY: os dois frames são do objeto, vivo até o fim do teste, e só
    // o `edu` os toca, entre as chamadas de DMA.
    unsafe {
        for i in 0..64u8 {
            src.add(usize::from(i)).write_volatile(0xa0 ^ i);
        }
        ptr::write_bytes(dst, 0, 64);
    }
    let domain = Arc::new(DmaDomain::new(&quota).map_err(|_| "domínio")?);
    ensure!(domain.map(&mo, 0x10_0000, 0, 2 * 4096, true) == Ok(0x10_0000));
    // Desligado: a escrita não chega à RAM, e a leitura vira falta. O
    // `intel-iommu` do QEMU tem um só registrador de falta: lê-se uma por
    // vez. O `amd-iommu` do QEMU bloqueia mas grava o evento fora do
    // formato da AMD (e nada para PTE zerada): lá as faltas não se conferem.
    let records = super::kind() == Some("VT-d");
    ensure!(edu.dma(0x10_1000, true));
    // SAFETY: como acima.
    ensure!((0..64).all(|i| unsafe { dst.add(i).read_volatile() } == 0));
    ensure!(!records || fault_of(bdf, 0x10_1000, true));
    ensure!(edu.dma(0x10_0000, false));
    ensure!(!records || fault_of(bdf, 0x10_0000, false));
    domain.attach(bdf).map_err(|_| "attach")?;
    ensure!(edu.dma(0x10_0000, false) && edu.dma(0x10_1000, true));
    // SAFETY: como acima.
    let copied = (0..64u8).all(|i| unsafe { dst.add(usize::from(i)).read_volatile() } == 0xa0 ^ i);
    ensure!(copied);
    // Desligado de novo: a escrita vira falta e a RAM não muda.
    domain.detach(bdf).map_err(|_| "detach")?;
    // SAFETY: como acima.
    unsafe { ptr::write_bytes(dst, 0, 64) };
    ensure!(edu.dma(0x10_1000, true));
    // SAFETY: como acima.
    ensure!((0..64).all(|i| unsafe { dst.add(i).read_volatile() } == 0));
    ensure!(!records || fault_of(bdf, 0x10_1000, true));
    super::faults(&mut |_| {});
    drop((domain, mo));
    ensure!(quota.used() == used);
    Ok(())
}

/// O `edu` com memória e bus master ligados e o BAR 0 mapeado.
fn edu() -> Result<Option<(u16, Edu)>, &'static str> {
    let Some(bdf) = find_edu() else {
        return Ok(None);
    };
    let bar = u64::from(config(bdf, 0x10) & !0xf);
    ensure!(bar != 0);
    set_config(bdf, 0x04, config(bdf, 0x04) | 0x6);
    Ok(Some((bdf, Edu(kmem::mmio(bar).map_err(|_| "BAR do edu")?))))
}

/// Deslocamento da capability `id` de `bdf`.
fn capability(bdf: u16, id: u8) -> Option<u8> {
    let mut at = (config(bdf, 0x34) & 0xfc) as u8;
    for _ in 0..48 {
        if at == 0 {
            return None;
        }
        let head = config(bdf, at);
        if head as u8 == id {
            return Some(at);
        }
        at = (head >> 8) as u8 & 0xfc;
    }
    None
}

/// Espera até 1 s pelo bit 0 de `ntfy`.
fn signalled(ntfy: &Notification) -> bool {
    let end = ktime::now_ns() + 1_000_000_000;
    while ktime::now_ns() < end {
        if ntfy.pending() & 1 != 0 {
            return true;
        }
        // O kernel roda com interrupções desligadas: abre-as até a MSI ou
        // o timer de 1 ms.
        ktime::set_timer_at(ktime::now_ns() + 1_000_000);
        crate::arch::x86_64::cpu::wait_for_interrupt();
    }
    false
}

/// T-404: `Interrupt` de MSI da cota de dispositivo; a MSI do `edu` (que
/// o próprio `edu` dispara ao escrever em 0x60) sinaliza o bit ligado, a
/// linha fica mascarada até o `ack` e o disparo guardado sai nele.
fn msi_do_edu() -> Outcome {
    let Some((bdf, edu)) = edu()? else {
        info!("ktest: sem edu; o aceite roda em `cargo xtask test iommu`");
        return Ok(());
    };
    let root = root_quota().ok_or("sem cota raiz")?;
    let used = root.used();
    {
        let device = MemoryQuota::device(&root, 64 << 10).map_err(|_| "cota")?;
        let (irq, address, data) = crate::kirq::create_msi(&device).map_err(|_| "vetor")?;
        ensure!(address >> 20 == 0xfee && data == u64::from(irq.vector()));
        let ntfy = Arc::new(Notification::new(&root).map_err(|_| "notificação")?);
        irq.bind(Arc::clone(&ntfy), 0).map_err(|_| "bind")?;
        // MSI de 64 bits: endereço em +4 e +8, dado em +12, liga no bit 16.
        let msi = capability(bdf, 5).ok_or("edu sem MSI")?;
        set_config(bdf, msi + 4, address as u32);
        set_config(bdf, msi + 8, (address >> 32) as u32);
        set_config(bdf, msi + 12, data as u32);
        set_config(bdf, msi, config(bdf, msi) | 1 << 16);
        edu.write32(0x60, 1);
        ensure!(signalled(&ntfy));
        edu.write32(0x64, 1);
        // Mascarada até o `ack`: o segundo disparo fica guardado.
        ensure!(ntfy.poll() == 1);
        edu.write32(0x60, 1);
        ensure!(!signalled(&ntfy));
        let (again, bits) = irq.ack().ok_or("disparo guardado perdido")?;
        ensure!(Arc::ptr_eq(&again, &ntfy) && bits == 1);
        edu.write32(0x64, 1);
        set_config(bdf, msi, config(bdf, msi) & !(1 << 16));
    }
    ensure!(root.used() == used);
    Ok(())
}
