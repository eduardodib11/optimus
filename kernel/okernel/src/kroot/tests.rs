//! Testes de kernel do bootfs e do `root` (T-211).

use super::{ROOT_NAME, bootfs, load, run_until_exit};
use crate::kcap::root_quota;
use crate::ktest::{Outcome, Test};
use crate::kthread::tests::settled;
use crate::kthread::{take_debug_log, yield_now};

/// Testes de kernel do bootfs.
pub const TESTS: &[Test] = &[
    Test {
        name: "bootfs.entregue_e_verificado",
        run: entregue,
    },
    Test {
        name: "bootfs.root_inicia_a_partir_do_bootfs",
        run: root_inicia,
    },
    Test {
        name: "pcie.mmio_so_fora_da_ram",
        run: mmio_fora_da_ram,
    },
];

/// T-402: a janela ECAM do MCFG vira objeto de MMIO da cota de
/// dispositivo; RAM, a página do APIC e a janela de MSI são recusadas, e
/// uma cota comum não cria objeto de MMIO.
fn mmio_fora_da_ram() -> Outcome {
    use kabi::Error;
    use kabi::boot::MemKind;
    use okernel::cap::MemoryQuota;
    use okernel::vm::MemoryObject;
    let platform = okernel::platform::get().ok_or("sem plataforma")?;
    let root = root_quota().ok_or("sem cota raiz")?;
    let used0 = root.used();
    {
        let dev = MemoryQuota::device(&root, 64 << 10).map_err(|_| "cota")?;
        let rsdp = crate::bootinfo::get()
            .and_then(kabi::boot::BootInfo::acpi_rsdp)
            .ok_or("sem RSDP")?;
        let ecam = okernel::acpi::mcfg(&mut crate::ktime::DirectRead, rsdp)
            .map_err(|_| "sem MCFG no q35")?;
        let bytes = (u64::from(ecam.end_bus) + 1) << 20;
        let mo = MemoryObject::new_device(&dev, ecam.base, bytes, platform)
            .map_err(|_| "ECAM recusada")?;
        ensure!(mo.is_device() && mo.frame(0).map(|f| f.0) == Some(ecam.base));
        ensure!(
            MemoryObject::new_device(&root, ecam.base, 4096, platform).err()
                == Some(Error::AccessDenied)
        );
        let map = crate::bootinfo::get()
            .and_then(crate::bootinfo::memory_map)
            .ok_or("sem mapa")?;
        let ram = map
            .iter()
            .find(|r| r.kind() == MemKind::Usable && r.len >= 4096)
            .ok_or("sem RAM")?;
        let apic = crate::arch::x86_64::apic::xapic_phys();
        for base in [ram.base & !0xfff, apic & !0xfff, 0xFEE0_0000] {
            ensure!(
                MemoryObject::new_device(&dev, base, 4096, platform).err()
                    == Some(Error::InvalidArgument)
            );
        }
        info!(
            "ktest: · ECAM em {:#x} com {} barramentos",
            ecam.base,
            u32::from(ecam.end_bus) + 1
        );
    }
    ensure!(root.used() == used0);
    Ok(())
}

fn entregue() -> Outcome {
    let image = bootfs().ok_or("sem bootfs na BootInfo")?;
    let fs = obfs::Image::parse(image).map_err(|_| "bootfs inválido")?;
    ensure!(fs.verify().is_ok());
    let root = fs.find(ROOT_NAME).ok_or("sem root")?;
    ensure!(oelf::Elf::parse_user(root.data).is_ok());
    ensure!(oelf::Elf::parse(root.data).is_err());
    info!(
        "ktest: · bootfs de {} KiB com {} entradas; root com {} bytes",
        image.len() >> 10,
        fs.len(),
        root.data.len()
    );
    Ok(())
}

/// Aceite do T-211: o `root` do bootfs roda no anel 3 e se anuncia; e o
/// do T-212 em pequena escala: ele inicia o `hello` e conversa com ele.
fn root_inicia() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let image = bootfs().ok_or("sem bootfs")?;
        let _ = take_debug_log();
        let p = load(image)?;
        ensure!(run_until_exit(&p.thread, 15_000_000_000));
        let (log, len) = take_debug_log();
        let text = core::str::from_utf8(&log[..len]).unwrap_or("?");
        info!("ktest: · o root imprimiu \"{text}\"");
        ensure!(text.starts_with(
            "root: iniciadoroot: IPC sem par: TimedOut e WouldBlockhello: iniciado pelo root"
        ));
        // T-212: o root carregou o hello do bootfs e conversou com ele.
        ensure!(text.contains("idas e voltas sem erro"));
        // O hello termina depois da última resposta do root.
        for _ in 0..100 {
            yield_now();
        }
        // Quebra o ciclo thread ↔ CapSpace e devolve tudo à cota.
        let [_, _, thread, _] = p.handles;
        drop(p.cspace.lock().delete(thread));
    }
    // O anel do log do kernel (T-357) vive além do root: tirá-lo devolve a
    // cota dele.
    drop(crate::klogring::uninstall());
    ensure!(settled(&quota, used0));
    Ok(())
}
